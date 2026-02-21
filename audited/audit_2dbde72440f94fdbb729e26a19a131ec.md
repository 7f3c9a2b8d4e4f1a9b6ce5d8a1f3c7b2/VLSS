# Audit Report

## Title
Decimal Mismatch Vulnerability in Oracle Aggregator Switching Leads to Incorrect Asset Valuations

## Summary
The `change_switchboard_aggregator()` function fails to update the `decimals` field in `PriceInfo` when switching oracle aggregators, causing catastrophic price normalization errors when the new aggregator uses a different decimal format. This corrupts all vault accounting, share pricing, and loss tolerance enforcement.

## Finding Description

The vulnerability exists in the oracle aggregator management system. When an admin switches to a new Switchboard aggregator, the `change_switchboard_aggregator()` function updates the aggregator address, price, and timestamp but critically omits updating the `decimals` field. [1](#0-0) 

The `decimals` field is stored in the `PriceInfo` struct and is essential for correct price normalization: [2](#0-1) 

The `get_normalized_asset_price()` function retrieves the stored `decimals` field to normalize prices to 9 decimals: [3](#0-2) 

When the stored decimals don't match the actual aggregator's decimal format, the normalization formula produces massively incorrect results. For example, if an aggregator is switched from 18 decimals to 9 decimals but the stored value remains 18, a price of 2_000_000_000 (2.0 USD in 9 decimals) would be normalized as 2_000_000_000 / 10^9 = 2 (essentially 0.000000002 USD), undervaluing assets by a factor of 1 billion.

**Execution Flow:**

1. Admin calls `change_switchboard_aggregator()` through the management interface: [4](#0-3) 

2. Vault operations fetch normalized prices using the incorrect decimals: [5](#0-4) [6](#0-5) 

3. These incorrect prices feed into USD value calculations: [7](#0-6) 

4. Wrong USD values corrupt share ratio calculations: [8](#0-7) 

5. Share ratios are used in deposits and withdrawals: [9](#0-8) [10](#0-9) 

6. Loss tolerance checks compare incorrect values, failing to detect actual losses: [11](#0-10) 

## Impact Explanation

**Direct Fund Impact:**
- **Incorrect Share Pricing:** Users receive massively incorrect share amounts during deposits or wrong principal amounts during withdrawals based on corrupted USD valuations
- **Quantified Damage:** If decimals differ by n (e.g., switching from 18 to 9 decimals), valuations are off by a factor of 10^n. A vault with 1000 SUI worth $2000 could be valued at $0.002 (undervalued by 10^9) or $2 trillion (overvalued by 10^9), causing share dilution or enabling massive over-withdrawals

**Security Mechanism Bypass:**
- **Loss Tolerance Bypass:** The loss tolerance mechanism enforced at lines 361-363 of operation.move compares `total_usd_value_before` and `total_usd_value_after`. With inflated or deflated valuations, actual losses appear negligible relative to the incorrect base value, bypassing protection limits

**Affected Parties:**
- All vault depositors receive incorrect share amounts or withdrawal amounts
- Protocol loses ability to enforce risk management controls
- Entire vault accounting becomes corrupted until aggregator is fixed

## Likelihood Explanation

**High Likelihood:**

1. **Legitimate Operational Scenario:** Admins routinely switch oracle aggregators for valid reasons (upgrading feeds, improving reliability, switching providers). This is not an attack but normal operations.

2. **Feasible Preconditions:** Different Switchboard aggregators report prices in different decimal formats. The `add_switchboard_aggregator()` function explicitly accepts a `decimals` parameter, proving the protocol anticipates different formats: [12](#0-11) 

3. **No Safeguards:** There are no validation checks to ensure decimal compatibility when switching aggregators. No warnings or events indicate a potential mismatch.

4. **Silent Failure:** The bug doesn't cause immediate transaction failure. Calculations proceed with incorrect values, potentially for extended periods before detection.

5. **Single Transaction:** Only requires one admin transaction with AdminCap.

## Recommendation

Update `change_switchboard_aggregator()` to accept a `decimals` parameter and update the `PriceInfo.decimals` field:

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // Add decimals parameter
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.decimals = decimals;  // Update decimals field
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

Also update the management wrapper function to accept and pass the decimals parameter.

## Proof of Concept

```move
#[test]
fun test_decimal_mismatch_vulnerability() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Add aggregator with 18 decimals, price = 2 * 10^18 (2.0 USD)
        let mut aggregator1 = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator1, 2_000_000_000_000_000_000, 0);
        
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            std::string::utf8(b"TEST"),
            18,  // 18 decimals
            &aggregator1,
        );
        
        // Normalized price should be 2_000_000_000 (2.0 USD in 9 decimals)
        let price1 = vault_oracle::get_normalized_asset_price(
            &oracle_config,
            &clock,
            std::string::utf8(b"TEST"),
        );
        assert!(price1 == 2_000_000_000, 0);
        
        aggregator::destroy_aggregator(aggregator1);
        test_scenario::return_shared(oracle_config);
    };
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        let admin_cap = s.take_from_sender<AdminCap>();
        
        // Switch to aggregator with 9 decimals, price = 2 * 10^9 (2.0 USD)
        let mut aggregator2 = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator2, 2_000_000_000, 0);
        
        vault_manage::change_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            &clock,
            std::string::utf8(b"TEST"),
            &aggregator2,
        );
        
        // BUG: Normalized price is wrong because decimals field wasn't updated
        // It still uses 18 decimals: 2_000_000_000 / 10^9 = 2
        // Should be 2_000_000_000 (no change, already 9 decimals)
        let price2 = vault_oracle::get_normalized_asset_price(
            &oracle_config,
            &clock,
            std::string::utf8(b"TEST"),
        );
        
        // This assertion will FAIL, proving the vulnerability
        // Expected: 2_000_000_000 (correct value)
        // Actual: 2 (wrong by factor of 10^9)
        assert!(price2 == 2_000_000_000, 1); // This fails!
        
        aggregator::destroy_aggregator(aggregator2);
        s.return_to_sender(admin_cap);
        test_scenario::return_shared(oracle_config);
    };
    
    clock::destroy_for_testing(clock);
    s.end();
}
```

**Notes:**
- This vulnerability occurs during legitimate admin operations, not malicious attacks
- The protocol already supports different decimal formats (evident from `add_switchboard_aggregator` accepting decimals parameter)
- The impact scales exponentially with decimal differences (10^n factor)
- All vault operations depending on USD valuations are affected
- Loss tolerance enforcement becomes ineffective with corrupted valuations

### Citations

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
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

**File:** volo-vault/sources/oracle.move (L158-184)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);

    emit(SwitchboardAggregatorAdded {
        asset_type,
        aggregator: aggregator.id().to_address(),
    });
}
```

**File:** volo-vault/sources/oracle.move (L198-220)
```text
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**File:** volo-vault/sources/manage.move (L118-126)
```text
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
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

**File:** volo-vault/sources/volo_vault.move (L990-1077)
```text

// ---------------------  Execute Withdraw  ---------------------//

// Only operator can execute withdraw
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
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
    });

    // Update total usd value after withdraw executed
    // This update should not generate any performance fee
    // (actually the total usd value will decrease, so there is no performance fee)
    self.update_free_principal_value(config, clock);

    // Update the vault receipt info
    let vault_receipt = &mut self.receipts[withdraw_request.receipt_id()];

    let recipient = withdraw_request.recipient();
    if (recipient != address::from_u256(0)) {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            0,
        )
    } else {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            withdraw_balance.value(),
        )
    };

    self.delete_withdraw_request(request_id);

    (withdraw_balance, recipient)
}
```

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L1130-1154)
```text
public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();
    assert!(
        type_name::get<CoinType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<CoinType>().into_string();
    let now = clock.timestamp_ms();

    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

    finish_update_asset_value(self, asset_type, coin_usd_value, now);
}
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

**File:** volo-vault/sources/utils.move (L69-76)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}

// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/operation.move (L353-373)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });
```
