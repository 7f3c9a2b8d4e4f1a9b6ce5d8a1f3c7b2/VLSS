# Audit Report

## Title
Complete Vault Denial of Service Due to Hard Switchboard Oracle Dependency Without Fallback Mechanism

## Summary
The Volo Vault relies entirely on Switchboard oracle updates with a 60-second freshness requirement and no fallback mechanism. If Switchboard stops updating, the entire vault becomes inoperable within 60 seconds, blocking all deposits, withdrawals, and operations until Switchboard recovers.

## Finding Description

The vulnerability stems from a hard dependency on Switchboard oracle updates with no alternative price source or emergency procedures.

**Root Cause - Oracle Freshness Enforcement:**

The `get_current_price()` function queries Switchboard aggregators and enforces strict freshness validation, aborting if the aggregator timestamp exceeds `update_interval` (60 seconds). [1](#0-0) 

**Price Update Architecture:**

The system uses a two-tier architecture where keepers call `update_price()` to refresh cached prices from Switchboard, which depends on `get_current_price()` succeeding. [2](#0-1) 

The `get_asset_price()` function validates cached prices are within `update_interval` (60 seconds). Once Switchboard stops updating, the cache cannot be refreshed, and after 60 seconds all price queries fail. [3](#0-2) 

**Critical Operations Blocked:**

1. **Deposit Execution**: The `execute_deposit()` function requires the vault to be in normal status and calls `update_free_principal_value()` which requires `get_normalized_asset_price()`. [4](#0-3) [5](#0-4) 

2. **Withdrawal Execution**: The `execute_withdraw()` function requires normal status and directly calls `get_normalized_asset_price()` and `get_share_ratio()`. [6](#0-5) 

3. **Total Value Validation**: The `get_total_usd_value()` function enforces that all asset values must be updated within `MAX_UPDATE_INTERVAL`, which is set to 0 in `volo_vault.move`, requiring same-transaction updates. [7](#0-6) [8](#0-7) 

4. **Operation Completion**: All operations must call `get_total_usd_value()` for validation before completion. [9](#0-8) [10](#0-9) 

**No Fallback Mechanisms:**

1. **Manual Price Override Unavailable**: The only manual price-setting function `set_current_price()` is marked `#[test_only]`, making it unavailable in production. [11](#0-10) 

2. **Oracle Switch Requires Operational Oracle**: The `change_switchboard_aggregator()` admin function still requires the new aggregator to be operational because it calls `get_current_price()` on initialization. [12](#0-11) 

3. **Disabled Status Blocks Everything**: While the vault can be disabled, setting it blocks ALL operations including user withdrawals. Both `execute_deposit()` and `execute_withdraw()` require `assert_normal()` status, and even `claim_claimable_principal()` requires normal status. [13](#0-12) [14](#0-13) [15](#0-14) 

## Impact Explanation

**Complete Operational Denial of Service:**

When Switchboard fails to update, the following cascade occurs:
1. **T+0**: Switchboard stops updating
2. **T+0 to T+60s**: Existing cached prices remain valid, operations continue
3. **T+60s**: Cached prices become stale, keepers cannot call `update_price()` (Switchboard still stale)
4. **T+60s+**: ALL price queries fail with `ERR_PRICE_NOT_UPDATED`
5. **Result**: All deposits, withdrawals, and operations blocked indefinitely

**Severity: CRITICAL**

This is critical because:
- **100% vault functionality loss**: No deposits, withdrawals, or operations possible
- **User funds locked**: Users cannot execute pending requests or withdraw
- **No mitigation path**: Neither users nor admins can restore functionality without Switchboard recovery
- **Unbounded duration**: Could last hours or days depending on Switchboard issue
- **Multi-vault impact**: All vaults using the same OracleConfig affected simultaneously
- **Protocol reputation damage**: Complete service outage destroys user confidence

## Likelihood Explanation

**Likelihood: HIGH**

This scenario is highly likely because:
1. **No Attacker Required**: This is an operational/availability issue, not a malicious attack
2. **Single Point of Failure**: Switchboard is the sole oracle source with no redundancy
3. **Strict Freshness Requirement**: 60-second tolerance is very tight for oracle networks
4. **External Dependency**: Switchboard is beyond protocol control and subject to its own failures
5. **Historical Precedent**: Oracle outages have affected major DeFi protocols

**Realistic Trigger Scenarios:**
- Scheduled Switchboard maintenance windows
- Network congestion preventing oracle updates during high volatility
- Switchboard oracle bugs or consensus failures
- Oracle queue congestion or fee spikes preventing timely updates
- Governance pausing feeds during extreme market conditions

## Recommendation

Implement a multi-layered fallback mechanism:

1. **Add Emergency Price Feed**: Create a production-available emergency price setter with multi-sig or time-delay governance that can set prices when oracles fail.

2. **Multiple Oracle Sources**: Integrate additional oracle providers (Pyth, Supra) with fallback logic that switches to alternative sources if Switchboard fails.

3. **Grace Period Extension**: Allow admin to temporarily extend `update_interval` during oracle outages to keep cached prices valid longer.

4. **Emergency Withdrawal Mode**: Create a special vault status that allows withdrawals (but not deposits) using last-known-good prices with conservative haircuts to protect remaining users.

5. **Circuit Breaker**: Implement a two-stage disable: first block new deposits while allowing withdrawals, only fully disable as last resort.

## Proof of Concept

```move
#[test]
fun test_oracle_outage_dos() {
    // Setup vault with Switchboard oracle
    let mut scenario = test_scenario::begin(@admin);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Initialize vault and oracle config
    // ... setup code ...
    
    // Advance time by 61 seconds (exceeds 60-second freshness)
    clock::increment_for_testing(&mut clock, 61_000);
    
    // Attempt to execute deposit - should fail with ERR_PRICE_NOT_UPDATED
    // because get_asset_price() checks: price_info.last_updated.diff(now) < update_interval
    let result = operation::execute_deposit(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &oracle_config,
        request_id,
        max_shares,
    );
    // This will abort with ERR_PRICE_NOT_UPDATED (2_002)
    
    // Attempt to execute withdraw - should also fail
    let result = operation::execute_withdraw(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &oracle_config,
        withdraw_request_id,
        max_amount,
        scenario.ctx(),
    );
    // This will also abort with ERR_PRICE_NOT_UPDATED
    
    // Complete DoS - no operations possible
}
```

**Notes:**
- This vulnerability requires no attacker - it's triggered by external oracle availability
- The 60-second window combined with 0-second MAX_UPDATE_INTERVAL in vault creates a tight coupling
- Admin cannot mitigate without Switchboard recovery since all emergency paths also require oracle functionality
- The issue affects protocol availability and user access to funds, constituting a critical operational risk

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

**File:** volo-vault/sources/oracle.move (L278-294)
```text
#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}

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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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

**File:** volo-vault/sources/volo_vault.move (L994-1022)
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
```

**File:** volo-vault/sources/volo_vault.move (L1101-1113)
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
```

**File:** volo-vault/sources/volo_vault.move (L1254-1278)
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
```

**File:** volo-vault/sources/volo_vault.move (L1573-1579)
```text
public(package) fun claim_claimable_principal<T>(
    self: &mut Vault<T>,
    receipt_id: address,
    amount: u64,
): Balance<T> {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```
