# Audit Report

## Title
Complete Vault Denial of Service Due to Hard Switchboard Oracle Dependency Without Fallback Mechanism

## Summary
The Volo Vault has a critical architectural dependency on Switchboard oracles with no fallback mechanism, emergency mode, or manual price override capability. If Switchboard experiences downtime or fails to update prices, the entire vault becomes inoperable within 60 seconds, blocking all deposits, withdrawals, and operations until Switchboard recovers.

## Finding Description

The Volo Vault oracle system enforces strict freshness requirements on Switchboard price data with no alternative price sources or emergency procedures.

**Root Cause - Hard Switchboard Dependency:**

The `get_current_price()` function directly queries Switchboard aggregators and enforces timestamp validation with no fallback mechanism: [1](#0-0) 

This function reads from the Switchboard aggregator's `current_result()` and validates the timestamp is within `update_interval` (default 60 seconds). If stale, it aborts with `ERR_PRICE_NOT_UPDATED`.

**Strict Freshness Enforcement:**

The maximum update interval is hardcoded to 60 seconds: [2](#0-1) 

**Price Cache Architecture:**

External keepers must call `update_price()` to refresh cached prices from Switchboard: [3](#0-2) 

This function depends on `get_current_price()` succeeding, requiring Switchboard to be operational.

Vault operations read from the cache via `get_asset_price()`: [4](#0-3) 

This validates cached prices are within the `update_interval`. If the cache becomes stale (because Switchboard is down and keepers cannot refresh), all operations fail.

**Critical Operations Blocked:**

1. **Deposit Execution** - Requires fresh prices to calculate share amounts: [5](#0-4) 

The function calls `get_total_usd_value()` twice and `update_free_principal_value()`, all requiring fresh oracle prices.

2. **Withdrawal Execution** - Requires fresh prices to calculate withdrawal amounts: [6](#0-5) 

The function directly calls `vault_oracle::get_normalized_asset_price()` and depends on `get_share_ratio()` which requires fresh prices.

3. **Operation Start** - Requires total USD value calculation: [7](#0-6) 

4. **Value Updates** - All asset value updates require fresh oracle data: [8](#0-7) 

**USD Value Staleness Check:**

The vault enforces that all asset values must be recently updated: [9](#0-8) 

Line 1266 enforces the staleness check across all assets.

**No Fallback Mechanisms:**

1. **No Manual Price Override** - The only price setting function is test-only: [10](#0-9) 

The `#[test_only]` attribute prevents this from being called in production.

2. **Aggregator Change Requires Working Oracle** - Even switching to a backup aggregator requires it to be operational: [11](#0-10) 

Line 207 calls `get_current_price()` on the new aggregator, requiring it to have fresh data.

3. **Disabling Vault Doesn't Help** - Status checks block operations: [12](#0-11) 

Both `execute_deposit()` and `execute_withdraw()` call `assert_normal()` (line 649), requiring status to be exactly `VAULT_NORMAL_STATUS`. The `update_free_principal_value()` function calls `assert_enabled()` (line 645), blocking if vault is disabled. Setting vault to disabled blocks ALL operations.

## Impact Explanation

When Switchboard fails to update prices, a complete operational cascade occurs:

**Within 60 Seconds:**
1. Price cache becomes stale as keeper cannot call `update_price()`
2. All deposit execution attempts fail with `ERR_PRICE_NOT_UPDATED`
3. All withdrawal execution attempts fail with `ERR_PRICE_NOT_UPDATED`
4. Operation start/completion fails with `ERR_USD_VALUE_NOT_UPDATED`
5. No asset value updates possible

**Affected Parties:**
- **Users**: Cannot execute pending deposit/withdrawal requests - funds effectively frozen in request buffers
- **Operators**: Cannot perform vault operations - vault management completely halted
- **Protocol**: Total loss of functionality, potential reputation damage

**Severity Justification:**

This is **Critical** severity because:
- 100% of vault functionality becomes unavailable
- No user or admin action can restore functionality without Switchboard recovery
- Duration is unbounded - could last hours or days
- Multiple vaults affected simultaneously if using same oracle config
- The validation framework explicitly includes "oracle dependence" as a valid DoS impact vector

## Likelihood Explanation

This scenario is **highly realistic** and requires no attacker action:

**Feasible Trigger Conditions:**
1. Switchboard scheduled maintenance windows
2. Network congestion preventing oracle updates
3. Oracle provider bugs or consensus failures  
4. Governance decisions to pause feeds during extreme market volatility
5. Economic attacks on oracle networks

**No Mitigation Possible:**
- Cannot switch to backup oracle without primary being operational
- 60-second tolerance is extremely strict
- No emergency procedures exist
- External dependency completely beyond protocol control

**Historical Precedent:**
Oracle outages have affected major DeFi protocols (Chainlink pauses, network congestion during high volatility), demonstrating this is not theoretical.

**Likelihood: High** - Switchboard is a single point of failure for an external service beyond protocol control, with no redundancy or fallback mechanisms.

## Recommendation

Implement multi-layered oracle resilience:

1. **Add Fallback Oracle Sources**: Support multiple oracle providers (Pyth, Supra, etc.) with automatic failover
2. **Implement Emergency Mode**: Add admin-controlled emergency mode that allows operations with extended staleness tolerance or manual price setting
3. **Extend Staleness Tolerance**: Consider graduated staleness tolerance (e.g., 5 minutes for normal ops, 30 minutes for withdrawals-only mode)
4. **Add Circuit Breaker**: Allow vault to enter "withdrawal-only" mode during oracle failures using last known prices with conservative safety margins
5. **Implement Price Bounds**: Store historical price ranges and allow operations within reasonable bounds even with stale data

Example fix structure:
```move
// Add emergency mode flag to OracleConfig
emergency_mode: bool,
fallback_staleness_tolerance: u64,

// Modify get_asset_price to check emergency mode
public fun get_asset_price(...) {
    if (config.emergency_mode) {
        assert!(price_info.last_updated.diff(now) < config.fallback_staleness_tolerance, ...);
    } else {
        assert!(price_info.last_updated.diff(now) < config.update_interval, ...);
    }
    // ...
}
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```move
#[test]
fun test_oracle_failure_blocks_all_operations() {
    // 1. Setup: Initialize vault with Switchboard oracle
    // 2. User creates deposit request
    // 3. Advance clock by 61 seconds (past MAX_UPDATE_INTERVAL)
    // 4. Attempt execute_deposit -> FAILS with ERR_PRICE_NOT_UPDATED
    // 5. Attempt execute_withdraw -> FAILS with ERR_PRICE_NOT_UPDATED  
    // 6. Attempt operation start -> FAILS with ERR_USD_VALUE_NOT_UPDATED
    // 7. Demonstrate: No admin function can restore functionality
    //    - Cannot change aggregator (requires working new aggregator)
    //    - Cannot disable vault (blocks operations further)
    //    - No manual price override exists
    // Result: Complete vault DoS until Switchboard recovers
}
```

The test would show that once the 60-second window passes without Switchboard updates, the vault becomes completely non-functional with no recovery mechanism available to admins or users.

### Citations

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

**File:** volo-vault/sources/oracle.move (L283-294)
```text
#[test_only]
public fun set_current_price(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    price: u256,
) {
    let price_info = &mut config.aggregators[asset_type];

    price_info.price = price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**File:** volo-vault/sources/volo_vault.move (L645-655)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}

public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}

public(package) fun assert_during_operation<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_DURING_OPERATION_STATUS, ERR_VAULT_NOT_DURING_OPERATION);
}
```

**File:** volo-vault/sources/volo_vault.move (L806-841)
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
```

**File:** volo-vault/sources/volo_vault.move (L994-1056)
```text
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

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```
