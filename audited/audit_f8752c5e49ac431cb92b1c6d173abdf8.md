# Audit Report

## Title
Zero Oracle Price Enables Share Ratio Manipulation and Fund Theft

## Summary
The vault oracle system lacks zero-price validation when retrieving Switchboard aggregator prices. When a Navi position asset price returns 0 due to oracle malfunction, the position's USD value is calculated as 0, severely understating the vault's total value. This deflates the share ratio, allowing attackers to acquire excess shares during deposits and subsequently withdraw more funds than deposited, directly stealing value from existing shareholders.

## Finding Description

The vulnerability stems from missing zero-price validation across the oracle price retrieval and position valuation pipeline, breaking the protocol's fundamental accounting invariant that share value accurately reflects vault assets.

**1. Switchboard Price Retrieval Without Validation**

The `get_current_price()` function retrieves the raw Switchboard aggregator result value without validating it is non-zero [1](#0-0) . The function only validates timestamp freshness but performs no bounds checking on the price value itself. The Switchboard Decimal type explicitly supports zero values [2](#0-1) .

**2. Asset Price Query Without Validation**

The `get_asset_price()` function returns the cached price directly without validating it is non-zero [3](#0-2) . The error constants confirm no zero-price validation exists [4](#0-3) .

**3. Position Value Calculation With Zero Price**

When `calculate_navi_position_value()` retrieves the asset price and it is 0, the multiplication operations produce zero USD values regardless of actual position balances [5](#0-4) . If price = 0, then both `supply_usd_value` and `borrow_usd_value` become 0, causing the entire Navi position value to be severely understated.

**4. Understated Total Vault Value**

The incorrect position value flows through to the vault's total value calculation, which simply sums all asset values [6](#0-5) .

**5. Share Ratio Deflation and Excess Share Issuance**

During deposit execution, the deflated share ratio is used to calculate user shares. The share ratio calculation uses the understated total USD value [7](#0-6) , and deposit execution applies this deflated ratio [8](#0-7) . The attacker receives `user_shares = new_usd_value_deposited / share_ratio_before`. With an artificially deflated `share_ratio_before`, the attacker receives significantly more shares than legitimate.

**6. Slippage Check Bypass**

The slippage validation uses attacker-controlled `expected_shares` parameter [9](#0-8) . The attacker sets `expected_shares` based on the current (incorrect) deflated ratio, so all checks pass.

**7. Withdrawal at Corrected Ratio**

After the oracle corrects, the attacker withdraws at the corrected ratio [10](#0-9) , extracting more value than deposited.

## Impact Explanation

**Direct Fund Theft**: This vulnerability enables direct theft of funds from existing vault shareholders through share dilution.

**Attack Mechanics**:
1. Oracle failure causes Navi position asset price → 0
2. Vault total value drops from 1M USD to 700K USD (300K Navi position now valued at 0)
3. Share ratio deflates from 1.0 to 0.7 (30% understatement)
4. Attacker deposits 100K USD and receives 142,857 shares (vs. 100K expected)
5. Oracle corrects, vault value → 1.1M USD, new ratio → 0.9625
6. Attacker withdraws: 142,857 shares × 0.9625 = 137.5K USD
7. **Net theft: 37.5K USD from existing shareholders**

The loss scales linearly with the mispriced position size and attacker's deposit amount. Existing shareholders' 1M shares are now worth only 962.5K USD, representing a permanent 3.75% value loss. This breaks the protocol's core invariant that share value accurately reflects proportional ownership of vault assets.

## Likelihood Explanation

**Precondition: Oracle Failure Returning Zero Price**

While Switchboard oracles are generally reliable, zero prices can occur due to:
- Asset delisting from exchanges
- Extreme market volatility causing data feed gaps
- Oracle infrastructure malfunction
- Price aggregation failures with insufficient valid responses

The critical issue is that **the protocol lacks defensive validation** against this invalid state.

**Execution Path**:
1. Attacker monitors oracle prices off-chain
2. Upon detecting zero price, creates deposit request via `request_deposit` [11](#0-10) 
3. Operator processes request through standard `execute_deposit` flow
4. All protocol checks pass (vault status, slippage bounds, etc.)
5. After oracle correction, attacker requests withdrawal
6. Standard withdrawal extracts excess value

**Economic Viability**:
- Profit: (mispriced_value / vault_value) × deposit_amount × (1 - fees)
- Example: 30% understatement on 100K deposit = 37.5% gross profit = 37.3K USD net after 0.2% fees
- Attack costs: Gas fees (negligible) + deposit/withdrawal fees (10-30 bps)
- Time window: Hours to days depending on oracle monitoring and correction speed

**No Privilege Requirements**: Any user can create deposit requests. The attack appears as legitimate activity during the oracle malfunction period.

## Recommendation

Add zero-price validation in the oracle price retrieval functions:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    let price = current_result.result().value() as u256;
    assert!(price > 0, ERR_ZERO_PRICE); // Add this validation
    price
}

public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    assert!(price_info.price > 0, ERR_ZERO_PRICE); // Add this validation
    price_info.price
}
```

Add the corresponding error constant:
```move
const ERR_ZERO_PRICE: u64 = 2_006;
```

## Proof of Concept

The vulnerability can be demonstrated with a test that:
1. Sets up a vault with a Navi position valued at 300K USD (30% of total)
2. Sets the Navi asset oracle price to 0 (simulating oracle failure)
3. Attacker deposits 100K USD and receives ~142,857 shares (should be 100K)
4. Restores the oracle price to correct value
5. Attacker withdraws and receives ~137.5K USD
6. Demonstrates 37.5K USD net theft from existing shareholders

The test would verify that the attacker's share calculation uses the deflated ratio and that the final withdrawal extracts excess value, confirming the fund theft mechanism.

## Notes

This vulnerability is particularly severe because:
1. It requires no privileged access - any user can exploit it
2. The attack is economically viable with high profit margins
3. The loss is permanent and directly impacts existing shareholders
4. The protocol has no defensive validation against oracle failures
5. Multiple oracle systems (Switchboard, Pyth, Supra) could potentially experience zero-price events

The fix should be implemented at the oracle layer to provide defense-in-depth against invalid price data from any source.

### Citations

**File:** volo-vault/sources/oracle.move (L16-21)
```text
// ---------------------  Errors  ---------------------//
const ERR_AGGREGATOR_NOT_FOUND: u64 = 2_001;
const ERR_PRICE_NOT_UPDATED: u64 = 2_002;
const ERR_AGGREGATOR_ALREADY_EXISTS: u64 = 2_003;
const ERR_AGGREGATOR_ASSET_MISMATCH: u64 = 2_004;
const ERR_INVALID_VERSION: u64 = 2_005;
```

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-69)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L707-757)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Generate current request id
    let current_deposit_id = self.request_buffer.deposit_id_count;
    self.request_buffer.deposit_id_count = current_deposit_id + 1;

    // Deposit amount
    let amount = coin.value();

    // Generate the new deposit request and add it to the vault storage
    let new_request = deposit_request::new(
        current_deposit_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        amount,
        expected_shares,
        clock.timestamp_ms(),
    );
    self.request_buffer.deposit_requests.add(current_deposit_id, new_request);

    emit(DepositRequested {
        request_id: current_deposit_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        amount: amount,
        expected_shares: expected_shares,
    });

    // Temporary buffer the coins from user
    // Operator will retrieve this coin and execute the deposit
    self.request_buffer.deposit_coin_buffer.add(current_deposit_id, coin);

    vault_receipt.update_after_request_deposit(amount);

    current_deposit_id
}
```

**File:** volo-vault/sources/volo_vault.move (L820-844)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L848-850)
```text
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1013)
```text
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
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
