# Audit Report

## Title
Stale Oracle Prices Enable Incorrect Share Minting During Deposit Execution

## Summary
The vault's deposit execution flow uses oracle prices that can be up to 1 minute stale to calculate share amounts, creating a systemic vulnerability where deposits result in incorrect share allocation during price volatility. This occurs due to conflicting staleness requirements between the vault module (0ms) and oracle module (60,000ms), combined with a timestamp update mechanism that creates a false appearance of price freshness.

## Finding Description

The vulnerability exists in the interaction between the vault's value update system and the oracle's price staleness checks.

**The Dual Staleness Standards:**

The vault module enforces same-transaction freshness for asset values: [1](#0-0) 

This is enforced when calculating total USD value: [2](#0-1) 

However, the oracle module allows 1-minute stale prices: [3](#0-2) 

This is checked when retrieving oracle prices: [4](#0-3) 

**The Execution Flow:**

During deposit execution, the operator calls: [5](#0-4) 

The vault's `execute_deposit()` calculates shares using USD values: [6](#0-5) 

At line 839, `update_free_principal_value()` is called, which fetches the oracle price: [7](#0-6) 

**The Bypass Mechanism:**

When `update_free_principal_value()` calls `finish_update_asset_value()`, it updates the asset's timestamp to the current time while using a potentially stale price: [8](#0-7) 

This creates a false appearance of freshness - the vault's staleness check at line 1266 passes because the timestamp was just updated to `now`, even though the underlying price data can be up to 1 minute old.

**Why Slippage Protections Fail:**

The deposit execution includes slippage checks, but these are calculated off-chain and don't enforce oracle freshness: [9](#0-8) 

If both the user and operator calculate their expected values using current market prices, but the oracle price is stale, both checks can pass while the internal calculation uses incorrect pricing.

## Impact Explanation

**Direct Fund Impact:**

The shares minted are calculated as `new_usd_value_deposited / share_ratio_before`. When the oracle price is stale:

- **Stale LOW price (market went up):** The depositor's assets are valued lower than their true worth → fewer shares minted → depositor loses value, existing shareholders gain unfairly
- **Stale HIGH price (market went down):** The depositor's assets are valued higher than their true worth → more shares minted → existing shareholders diluted, depositor gains unfairly

**Quantified Risk:**

For a volatile asset with 5-10% price movement in 1 minute during high volatility periods:
- A $100,000 deposit with 10% stale price discrepancy = $10,000 worth of incorrect share allocation
- Affects every deposit executed during volatile periods with stale oracle prices
- Cumulative impact across multiple deposits can be substantial

**Affected Parties:**
- Depositors submitting requests
- All existing vault shareholders
- Protocol's fair value guarantees

## Likelihood Explanation

**High Likelihood - Occurs During Normal Operations:**

This is NOT an attack but a systemic operational risk that occurs naturally when:

1. **Oracle prices age naturally:** Prices in `OracleConfig` remain cached for up to 1 minute between updates
2. **Market volatility:** Crypto assets frequently experience significant price movements within 1-minute windows
3. **Operator executes deposits:** Following standard procedures, operators execute pending deposits asynchronously from oracle updates
4. **No on-chain enforcement:** Operators cannot distinguish between fresh and near-stale oracle prices on-chain

**Feasibility:**
- Requires no special privileges beyond standard operator role
- No malicious intent needed
- Market volatility is common
- 1-minute windows are sufficient for material price divergence in volatile crypto markets

**Detection Constraints:**
- Silent failure mode - incorrect shares minted without errors
- Off-chain slippage parameters may not account for oracle staleness
- No automatic circuit breakers for price staleness at execution time

## Recommendation

**Solution 1: Enforce Oracle Freshness in Vault (Preferred)**

Modify the vault's `MAX_UPDATE_INTERVAL` to align with the oracle's update requirements, or add an explicit check that oracle prices themselves must be updated in the same transaction:

```move
// In vault::execute_deposit, before line 839:
// Ensure oracle price was updated in current transaction
let oracle_last_updated = config.get_price_last_updated(asset_type);
assert!(clock.timestamp_ms() - oracle_last_updated <= MAX_UPDATE_INTERVAL, ERR_STALE_ORACLE_PRICE);
```

**Solution 2: Require Fresh Oracle Update Before Deposit Execution**

Require operators to update oracle prices in the same transaction as deposit execution:

```move
public fun execute_deposit_with_price_update<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    // ... other params
) {
    // Force oracle price update in same transaction
    vault_oracle::update_price(config, aggregator, clock, asset_type);
    
    // Then execute deposit
    execute_deposit(/* ... */);
}
```

**Solution 3: Reduce Oracle Staleness Window**

Reduce the oracle's `MAX_UPDATE_INTERVAL` from 60,000ms to a shorter duration (e.g., 5,000ms or 5 seconds) to minimize the window for price divergence.

## Proof of Concept

```move
#[test]
public fun test_stale_oracle_causes_incorrect_shares() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // Set oracle price at T0: 1 SUI = $2
    s.next_tx(OWNER);
    {
        let mut config = s.take_shared<OracleConfig>();
        vault_oracle::set_current_price(&mut config, &clock, 
            type_name::get<SUI_TEST_COIN>().into_string(), 
            2_000_000_000); // $2 with 9 decimals
        test_scenario::return_shared(config);
    };
    
    // User requests deposit of 1 SUI, expecting ~2 shares (at $2 price)
    s.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, receipt, remaining) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin,
            1_000_000_000, 2_000_000_000, // expect 2 shares
            option::none(), &clock, s.ctx()
        );
        
        transfer::public_transfer(remaining, ALICE);
        transfer::public_transfer(receipt, ALICE);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Market price moves to $3 but oracle NOT updated (still at $2)
    // Time passes but less than 1 minute
    clock.increment_for_testing(30_000); // 30 seconds
    
    // Operator executes deposit with STALE oracle price ($2 instead of $3)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        operation::execute_deposit(
            &operation, &cap, &mut vault, &mut reward_manager,
            &clock, &config, 0, 2_000_000_000
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(reward_manager);
    };
    
    // Verify: User received 2 shares but should have received ~1.33 shares
    // (1 SUI * $3 = $3 worth, but calculated as $2 worth at stale price)
    s.next_tx(ALICE);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let receipt = s.take_from_sender<Receipt>();
        let vault_receipt_info = vault.vault_receipt_info(receipt.receipt_id());
        
        // User got 2 shares using $2 stale price
        // Should have gotten ~1.33 shares at true $3 price
        // This represents 50% overpayment of shares = dilution of existing holders
        assert!(vault_receipt_info.shares() == 2_000_000_000);
        
        s.return_to_sender(receipt);
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability represents a **design-level issue** where two conflicting staleness requirements create a systemic risk rather than a one-time exploit. The vault architecture assumes same-transaction freshness for all asset valuations but relies on an oracle system that permits 1-minute staleness. The timestamp update mechanism in `finish_update_asset_value()` bridges these incompatible requirements by creating a false appearance of freshness, allowing stale prices to pass strict staleness checks. This affects the core value proposition of the vault - accurate share pricing - and occurs naturally during normal operations without requiring any malicious behavior.

### Citations

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
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

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
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

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

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
}
```

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
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

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
```
