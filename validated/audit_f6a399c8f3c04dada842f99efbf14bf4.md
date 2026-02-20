# Audit Report

## Title
Oracle Price Division-by-Zero Causes Critical Withdrawal and Asset Valuation DoS

## Summary
The Volo vault system does not validate that oracle prices are non-zero before performing division operations. When oracle prices become zero due to Switchboard aggregator malfunctions or extreme market conditions, critical vault operations including user withdrawals and DEX position valuations abort with arithmetic errors, creating a denial-of-service condition that prevents users from accessing their deposited funds.

## Finding Description

The vulnerability exists across multiple interconnected components:

**Root Cause - Missing Zero-Price Validation:**

The oracle module's `get_asset_price()` function retrieves prices without validating they are non-zero. [1](#0-0) 

Similarly, `get_current_price()` extracts values from Switchboard aggregators without zero validation. [2](#0-1) 

**Division Without Zero Checks:**

The utility function `div_with_oracle_price()` performs division without checking if the divisor (oracle price) is zero. [3](#0-2) 

**Critical Withdrawal Path Exploitation:**

When operators execute user withdrawals, the code calculates the withdrawal amount by dividing the USD value by the oracle price. [4](#0-3) 

This withdrawal execution is called from the operator-accessible entry point. [5](#0-4) 

**DEX Position Valuation Vulnerabilities:**

The Cetus adaptor calculates relative prices by dividing `price_a` by `price_b`, where `price_b` comes from the oracle without zero validation. [6](#0-5) 

The Momentum adaptor has an identical vulnerability in its position value calculation. [7](#0-6) 

While Move's VM prevents incorrect calculations by aborting on division-by-zero, this protection mechanism itself becomes the attack vector - creating a DoS condition where legitimate operations become permanently blocked until oracle data is corrected.

## Impact Explanation

**HIGH Severity - Critical Protocol Denial of Service**

This vulnerability violates the core protocol invariant that users can withdraw their deposited funds. When any asset's oracle price becomes zero:

1. **Withdrawal DoS**: All pending withdrawal executions for that asset fail with arithmetic abort, trapping user funds in the vault
2. **Position Valuation Failure**: DEX positions (Cetus/Momentum) containing the affected asset cannot have their values updated
3. **Cascade Effects**: Failed position valuations prevent total USD value calculations, affecting share ratios and blocking vault operations
4. **User Impact**: Users with valid withdrawal requests cannot access their principal even when the vault has sufficient free principal

The DoS persists until the oracle price is manually corrected, during which time all affected operations remain blocked.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood**

Oracle failures returning zero prices are realistic scenarios that have occurred in production DeFi systems:

1. **Switchboard Aggregator Issues**: External oracle infrastructure can malfunction, returning stale or invalid (zero) data
2. **Circuit Breaker Events**: Extreme market volatility may trigger price feed circuit breakers
3. **Network Failures**: Infrastructure issues affecting oracle update mechanisms
4. **Attack Surface**: The vulnerability is reachable through normal operator actions (executing legitimate user withdrawals), not requiring any malicious behavior

The vulnerability requires only that a single monitored asset's oracle price becomes zero - a condition outside the protocol's direct control but within realistic operational scenarios.

## Recommendation

Implement explicit zero-price validation at multiple defensive layers:

1. **Oracle Module**: Add zero-price validation in `get_asset_price()` and `get_current_price()`:
```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    // Add zero-price validation
    assert!(price_info.price > 0, ERR_INVALID_PRICE_ZERO);
    
    price_info.price
}
```

2. **Utility Functions**: Add defensive checks in division functions:
```move
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * ORACLE_DECIMALS / v2
}
```

3. **Adaptor Functions**: Add explicit validation before divisions in Cetus and Momentum adaptors.

4. **Error Constants**: Define appropriate error codes:
```move
const ERR_INVALID_PRICE_ZERO: u64 = 2_XXX;
const ERR_DIVISION_BY_ZERO: u64 = X_XXX;
```

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = DIVIDE_BY_ZERO)] // Move VM arithmetic error
fun test_withdrawal_dos_with_zero_oracle_price() {
    let mut scenario = test_scenario::begin(ADMIN);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Create vault and oracle config
    let mut vault = create_test_vault(scenario.ctx());
    let mut oracle_config = create_test_oracle(scenario.ctx());
    
    // Setup: User creates withdrawal request
    let user_receipt = create_test_receipt(&mut vault, 1000000);
    let request_id = submit_withdraw_request(&mut vault, user_receipt, 900000);
    
    // Simulate oracle malfunction: Set price to zero
    oracle_config.set_current_price(&clock, type_name::get<SUI>().into_string(), 0);
    
    // Execute withdrawal - This will abort with division by zero
    // Proving DoS: legitimate withdrawal cannot complete
    let operator_cap = create_operator_cap();
    operation::execute_withdraw(
        &operator,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &oracle_config,
        request_id,
        1000000,
        scenario.ctx()
    );
    // Transaction aborts here - user cannot withdraw despite having valid request
    
    abort_test_scenario(scenario);
}
```

**Notes**

The vulnerability is particularly concerning because:
1. It affects user funds directly (cannot withdraw deposited principal)
2. The DoS is triggered by external oracle behavior outside protocol control
3. Recovery requires admin intervention to fix oracle data or upgrade contracts
4. The vulnerability exists in production-critical paths (withdrawals, position valuations)

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

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
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

**File:** volo-vault/sources/operation.move (L449-479)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let withdraw_request = vault.withdraw_request(request_id);
    reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

    let (withdraw_balance, recipient) = vault.execute_withdraw(
        clock,
        config,
        request_id,
        max_amount_received,
    );

    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
    }
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L49-52)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```
