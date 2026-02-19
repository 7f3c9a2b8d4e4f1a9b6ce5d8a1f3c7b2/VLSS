# Audit Report

## Title
Missing Aggregator Characteristic Validation in change_switchboard_aggregator Enables Vault Misvaluation

## Summary
The `change_switchboard_aggregator` function fails to validate or update the critical `decimals` field when changing oracle aggregators, allowing admin configuration errors to cause catastrophic vault misvaluation and direct fund loss through incorrect share calculations.

## Finding Description
The vulnerability exists in the aggregator change logic where the decimals field, critical for price normalization, is never updated or validated.

When adding an aggregator initially, the `decimals` parameter is required and stored in the PriceInfo struct [1](#0-0) . This decimals field is then used by `get_normalized_asset_price` to normalize all prices to 9 decimals for consistent USD valuation [2](#0-1) .

However, the `change_switchboard_aggregator` function only updates the aggregator address, price, and timestamp - it does NOT update the decimals field [3](#0-2) . The function signature doesn't even accept a decimals parameter. This means if an admin accidentally provides an aggregator with different decimal precision, the old decimals value will be used with the new aggregator's prices, causing incorrect normalization.

The normalized prices directly impact vault share calculations. The share ratio is calculated as `total_usd_value / total_shares` [4](#0-3) , which depends on correct asset pricing. During deposits, user shares are calculated as `new_usd_value_deposited / share_ratio_before` [5](#0-4) . During withdrawals, the amount is calculated from shares using the share ratio [6](#0-5) .

The admin can call this function through the public entry point [7](#0-6) .

## Impact Explanation
**Catastrophic Fund Loss Through Share Miscalculation**

If the decimals mismatch between old and new aggregators, price normalization becomes incorrect by orders of magnitude:

1. **Decimal Mismatch Scenario**: Old aggregator has decimals=18, new aggregator effectively uses decimals=9, but stored decimals remains 18
   - New price: 2e18 (representing $2 with 9 decimal precision)
   - Normalization divides by 10^(18-9) = 10^9
   - Result: 2e18 / 1e9 = 2e9 (correct)
   - BUT if the new aggregator actually returns prices in different scale, this breaks

2. **Wrong Asset Scenario**: Admin provides BTC aggregator instead of SUI aggregator
   - BTC price: ~$100,000
   - SUI price: ~$2
   - All SUI holdings valued as if they were BTC
   - Vault appears 50,000x more valuable

3. **Direct Fund Impact**:
   - If vault is overvalued: Users depositing receive fewer shares than deserved, losing claim to proportional vault value
   - If vault is undervalued: Users withdrawing can drain excessive amounts, stealing from remaining depositors
   - Share ratio corruption affects ALL subsequent deposits and withdrawals until corrected

This breaks the fundamental invariant that each share represents accurate proportional ownership of vault value.

## Likelihood Explanation
**High Likelihood - Routine Operational Error**

This is a realistic operational scenario:

1. **Frequent Operation**: Aggregator changes are routine maintenance (oracle provider updates, failover, configuration changes)

2. **Easy Mistakes**: 
   - Copy-paste wrong aggregator address from off-chain tracking
   - Confusion when multiple assets use different aggregators
   - Typo in deployment script
   - Oracle provider changes aggregator format without notice

3. **No Safeguards**: The function provides zero validation:
   - No check that new aggregator returns prices in same scale
   - No check that new aggregator is for same asset type
   - No way to update decimals even if admin realizes mistake
   - No warning or confirmation mechanism

4. **Admin Assumption**: While admins are trusted to act honestly, they are not trusted to be infallible. Configuration validation is standard security practice to prevent honest mistakes from causing catastrophic failures.

## Recommendation

Add validation and decimals parameter to the `change_switchboard_aggregator` function:

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // ADD THIS PARAMETER
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
    price_info.decimals = decimals;  // UPDATE DECIMALS
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

Update the public wrapper in manage.move to accept and pass the decimals parameter.

Alternatively, implement validation that the new aggregator characteristics match the old one (same decimals, same asset), though this may be harder to enforce on-chain.

## Proof of Concept

```move
#[test]
fun test_aggregator_decimal_mismatch_causes_misvaluation() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());

    // Setup vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Add aggregator with decimals=18
        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator, 2_000_000_000_000_000_000, 0); // $2 with 18 decimals
        
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            18,  // Original decimals
            &aggregator,
        );
        
        // Get normalized price (should be 2e9 = $2)
        let price_before = vault_oracle::get_normalized_asset_price(
            &oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        assert!(price_before == 2_000_000_000, 0); // Correct: $2
        
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };

    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        let admin_cap = s.take_from_sender<AdminCap>();
        
        // Admin accidentally changes to aggregator with different decimal scale
        // New aggregator returns price with 9 decimals, but stored decimals stays 18
        let mut new_aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut new_aggregator, 2_000_000_000, 0); // $2 with 9 decimals (new format)
        
        vault_manage::change_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            &new_aggregator,
        );
        
        // Decimals still 18, but price is now 2e9 instead of 2e18
        // Normalization: 2e9 / 10^9 = 2 (wrong! should be 2e9)
        let price_after = vault_oracle::get_normalized_asset_price(
            &oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        
        // Price is now 1 billion times too small!
        assert!(price_after == 2, 0); // CATASTROPHIC: $0.000000002 instead of $2
        
        s.return_to_sender(admin_cap);
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(new_aggregator);
    };

    clock::destroy_for_testing(clock);
    s.end();
}
```

## Notes

This vulnerability represents a critical gap in configuration validation. While admin roles are trusted to act honestly, they should not be trusted to be infallible. The protocol must validate that configuration changes maintain system invariants - in this case, that price normalization remains accurate. The decimals field is as critical to pricing accuracy as the aggregator address itself, yet it receives no validation or update mechanism during aggregator changes.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L811-872)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1000-1060)
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
    });

    // Update total usd value after withdraw executed
    // This update should not generate any performance fee
    // (actually the total usd value will decrease, so there is no performance fee)
    self.update_free_principal_value(config, clock);

    // Update the vault receipt info
    let vault_receipt = &mut self.receipts[withdraw_request.receipt_id()];

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
