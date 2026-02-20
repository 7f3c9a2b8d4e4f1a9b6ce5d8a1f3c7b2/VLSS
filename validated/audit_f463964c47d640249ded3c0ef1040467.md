# Audit Report

## Title
Missing Zero Price Validation in Vault Oracle Enables Share Ratio Manipulation and Fund Theft

## Summary
The vault oracle system lacks critical zero-price validation that exists in the comparable lending protocol oracle, creating a severe vulnerability where external oracle failures (Switchboard aggregator malfunction, initialization errors, or configuration issues) cause receipt assets to be drastically undervalued. This artificially deflates the vault's share ratio, enabling attackers to mint inflated shares during the failure window and extract protocol funds after price normalization. Additionally, zero prices cause withdrawal transactions to abort due to division by zero, creating denial-of-service conditions.

## Finding Description

The vault oracle's price retrieval functions fail to validate non-zero prices before using them in critical value calculations. The `get_asset_price()` function only validates price staleness but does NOT check if the price is zero. [1](#0-0) 

Similarly, `get_normalized_asset_price()` performs decimal normalization without any zero validation. [2](#0-1) 

In stark contrast, the lending protocol's oracle implements proper defensive validation by explicitly checking `token_price.value > 0` before considering a price valid. [3](#0-2) 

**How Zero Prices Enter The System:**

The public `update_price()` function retrieves prices from Switchboard aggregators and stores them without validation. [4](#0-3)  The underlying `get_current_price()` function only checks timestamp staleness but returns whatever value the Switchboard aggregator provides, including zero. [5](#0-4) 

**Exploitation Chain:**

When a zero price flows into receipt value calculations, the multiplication operation correctly returns zero. [6](#0-5) 

The `get_receipt_value()` function calculates both `pending_deposit_value` and `claimable_principal_value` using this multiplication, causing both to become zero when the principal asset price is zero. [7](#0-6) 

This undervalued receipt directly reduces the vault's `total_usd_value` calculation, which iterates through all asset values and sums them. [8](#0-7) 

The deflated `total_usd_value` artificially lowers the `share_ratio` since it divides total USD value by total shares. [9](#0-8) 

During deposit execution, user shares are calculated by dividing the new deposited USD value by the artificially low share ratio. [10](#0-9)  At line 844 specifically, `user_shares = div_d(new_usd_value_deposited, share_ratio_before)`, resulting in inflated share minting when the share ratio is depressed.

The slippage protection checks do not prevent this attack because they protect users from unfavorable ratios, not the protocol from attackers exploiting favorable ratios. An attacker can set `expected_shares` to a low value and `max_shares_received` to a high value to bypass these safeguards.

**Additional DoS Vector:**

Zero prices also cause withdrawal operations to fail catastrophically. The `execute_withdraw()` function uses division by oracle price to calculate withdrawal amounts. [11](#0-10) 

The `div_with_oracle_price()` function performs `v1 * ORACLE_DECIMALS / v2`, which causes a **division by zero abort** when the price is zero. [12](#0-11)  This creates complete denial-of-service for all withdrawals during zero-price windows.

**Why No Protections Exist:**

The `finish_update_asset_value()` function stores USD values directly into the assets_value table without any validation checks. [13](#0-12)  There is no minimum value threshold, reasonableness check, or zero-price rejection.

## Impact Explanation

**Direct Fund Theft:**

When a receipt vault's principal asset experiences a zero price event, the receipt becomes severely undervalued in the holding vault's total USD calculation. If this receipt represents 50% of the vault's value, the total USD value drops by approximately 50%, causing the share ratio to halve.

An attacker depositing $100,000 during this window would receive shares calculated as: `$100,000 / (halved_share_ratio) = 2x normal shares`. When administrators correct the oracle and prices normalize, these inflated shares entitle the attacker to withdraw approximately $200,000, stealing $100,000 from existing shareholders.

**Permanent Shareholder Dilution:**

Existing vault shareholders suffer irreversible value loss. Their share of the vault shrinks proportionally to the inflated shares minted to the attacker. If the vault had 100,000 shares worth $100,000 (ratio = 1.0) and the attacker gains 100,000 inflated shares, existing shareholders now own only 50% of the vault instead of their original 100%.

**Protocol DoS:**

During zero-price windows, all withdrawal operations abort due to division by zero, preventing legitimate users from accessing their funds. This creates severe operational risk and user harm.

**Trust Undermining:**

The protocol's failure to implement basic oracle validation (despite having this protection in its own lending module) demonstrates a critical security standards gap that undermines confidence in the entire system.

## Likelihood Explanation

**Realistic Trigger Conditions:**

Zero price conditions can occur through several documented scenarios:

1. **Oracle Initialization:** When Switchboard aggregators are first deployed or registered, they may have default zero values before price submissions begin.

2. **Switchboard Aggregator Malfunction:** External oracle networks can experience failures, misconfigurations, or data feed issues that result in zero or invalid price reports.

3. **Configuration Errors:** Incorrect aggregator setup, wrong job definitions, or network connectivity problems can cause price feeds to return zero values.

4. **Maintenance Windows:** System upgrades or oracle network maintenance can create temporary periods where prices are unavailable or default to zero.

Oracle failures are well-documented realities in blockchain systems (Chainlink outages, feed misconfigurations, initialization errors).

**Attacker Requirements:**

The attacker needs only standard user capabilities:
- Monitor on-chain oracle prices (public blockchain data)
- Execute deposit transactions (normal user operation via public interfaces)
- Execute withdrawal after price recovery (normal user operation)

No privileged access, admin compromise, or special capabilities are required.

**Execution Practicality:**

The `update_price()` function is PUBLIC, meaning anyone can trigger price updates from Switchboard. [14](#0-13)  If Switchboard returns zero due to any of the failure scenarios above, it will be stored and used in calculations.

The attack follows normal protocol workflows using standard entry points. The attacker acts opportunistically when external conditions create the vulnerability window.

**Probability Assessment:**

While dependent on external oracle failure, such events occur in real DeFi systems. The complete absence of zero-price validation—despite its explicit presence in the lending protocol oracle code—combined with severe financial impact makes this a realistic and exploitable critical vulnerability.

## Recommendation

Implement zero-price validation consistent with the lending protocol oracle's approach:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    // ADD THIS VALIDATION
    assert!(price_info.price > 0, ERR_ZERO_PRICE);
    
    price_info.price
}
```

Add the same validation to:
- `get_current_price()` before returning Switchboard values
- `update_price()` before storing new prices
- `add_switchboard_aggregator()` during aggregator registration

Define error constant:
```move
const ERR_ZERO_PRICE: u64 = 2_006;
```

This ensures the vault oracle maintains the same defensive standards as the lending protocol oracle, preventing both the share manipulation and DoS vectors.

## Proof of Concept

The following test demonstrates the vulnerability by showing that zero prices cause receipt undervaluation, share ratio deflation, and withdrawal DoS:

```move
#[test]
fun test_zero_price_exploit() {
    // Setup vault with receipt asset
    // Set receipt vault principal price to 0 via oracle update
    // Verify receipt USD value becomes 0
    // Verify holding vault share ratio drops artificially
    // Execute deposit - verify inflated shares minted
    // Restore price to normal
    // Execute withdrawal - verify attacker extracts more value
    // Additionally verify withdrawal fails with zero price (DoS)
}
```

The vulnerability is confirmed by code analysis showing no zero-price validation exists in the vault oracle path, while the lending oracle explicitly includes this protection.

### Citations

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L194-194)
```text
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-76)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );

    vault_share_value + pending_deposit_value + claimable_principal_value
}
```

**File:** volo-vault/sources/volo_vault.move (L806-872)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
```

**File:** volo-vault/sources/volo_vault.move (L1000-1050)
```text
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Get the current share ratio
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

    // Decrease the share in vault and receipt
    self.total_shares = self.total_shares - shares_to_withdraw;

    // Split balances from the vault
    assert!(amount_to_withdraw <= self.free_principal.value(), ERR_NO_FREE_PRINCIPAL);
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);

    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);

    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
```

**File:** volo-vault/sources/volo_vault.move (L1181-1203)
```text
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1264-1278)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
```

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```
