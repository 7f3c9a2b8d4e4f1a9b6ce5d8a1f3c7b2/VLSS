# Audit Report

## Title
Oracle Price Division-by-Zero Causes Critical Withdrawal and Asset Valuation DoS

## Summary
The Volo vault oracle module does not validate that asset prices are non-zero, and multiple critical functions perform divisions using these oracle prices without explicit zero checks. This creates a denial-of-service vulnerability where users cannot execute withdrawals or update DeFi position values when oracle prices become zero due to Switchboard aggregator malfunction, extreme market conditions, or infrastructure failures.

## Finding Description

The vulnerability exists across three core areas of the protocol:

**Root Cause - Missing Oracle Price Validation:**

The oracle price retrieval functions validate only timestamp freshness but do not check for non-zero prices. [1](#0-0)  The `get_current_price()` function similarly only validates staleness. [2](#0-1) 

The Switchboard Decimal type explicitly allows zero values, with a `zero()` constructor. [3](#0-2) 

**Missing Division Guards:**

The utility division functions lack zero-divisor validation. The `div_with_oracle_price()` function performs `v1 * ORACLE_DECIMALS / v2` without checking if v2 is zero. [4](#0-3) 

**Critical Exploit Path 1 - Withdrawal DoS:**

When operators execute user withdrawals, the code calculates withdrawal amounts by dividing the USD value by the oracle price without validation. [5](#0-4)  This function is called from the operator-accessible public entry point. [6](#0-5) 

**Critical Exploit Path 2 - DEX Position Valuation DoS:**

The Cetus adaptor divides by `price_b` to calculate relative oracle prices without zero validation. [7](#0-6)  It also divides by `relative_price_from_oracle` for slippage checks. [8](#0-7) 

The Momentum adaptor contains identical vulnerabilities. [9](#0-8) [10](#0-9) 

**Why Protections Fail:**

While Sui Move's VM aborts on division-by-zero (preventing incorrect calculations), this creates a permanent DoS condition rather than a protection. Legitimate withdrawal operations become completely blocked when any monitored asset's oracle price becomes zero.

## Impact Explanation

**HIGH Severity - Critical Protocol DoS**

This vulnerability has severe impact on protocol core functionality:

1. **User Fund Access Blocked**: Users with valid pending withdrawal requests cannot execute withdrawals when the principal asset's oracle price is zero. All withdrawal transactions abort with arithmetic errors.

2. **Cascading Vault Operation Failures**: DEX position values cannot be updated, which blocks:
   - Share ratio calculations that depend on total USD value
   - Vault operation completions that require position revaluation
   - Total vault accounting that aggregates position values

3. **Breaks Core Protocol Invariant**: The fundamental guarantee that users can withdraw their deposited funds is violated. This affects protocol solvency perception and user trust.

4. **No Recovery Path**: Unlike temporary network issues, if an oracle feed reports zero due to underlying asset delisting or feed deprecation, the DoS becomes permanent until admin intervention to replace the oracle.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood**

Oracle price feeds reporting zero is a realistic scenario that has occurred across DeFi protocols:

1. **Switchboard Aggregator Malfunctions**: The Volo vault relies on external Switchboard on-demand aggregators. These can report zero values during:
   - Feed configuration errors
   - Insufficient oracle responses meeting minimum sample size
   - Data provider outages
   - Network partitions affecting oracle infrastructure

2. **Extreme Market Conditions**: During circuit breaker events, trading halts, or extreme volatility, price feeds may temporarily report zero or become unavailable.

3. **Asset Lifecycle Events**: Token delistings, migrations, or deprecations can cause oracle feeds to stop updating or report zero values.

4. **Reachability**: The vulnerability is triggered through normal operator actions (executing legitimate user withdrawals), not malicious behavior. Operators are assumed to be honest per the threat model.

5. **Historical Precedent**: Multiple DeFi protocols have experienced oracle-related DoS issues, including Compound, Aave, and others when Chainlink feeds had issues.

The vulnerability requires only that one asset's oracle price becomes zero - a condition with realistic probability given the dependency on external infrastructure.

## Recommendation

Implement explicit non-zero validation for oracle prices at multiple defense layers:

**Layer 1 - Oracle Module Validation:**
```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    // Add zero-price validation
    assert!(price_info.price > 0, ERR_INVALID_PRICE);
    
    price_info.price
}
```

**Layer 2 - Utility Division Guards:**
```move
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * ORACLE_DECIMALS / v2
}
```

**Layer 3 - Price Update Validation:**
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
    
    // Add zero-price validation
    assert!(price > 0, ERR_INVALID_PRICE);
    
    price
}
```

Add appropriate error constants:
```move
const ERR_INVALID_PRICE: u64 = 2_006;
const ERR_DIVISION_BY_ZERO: u64 = 2_007;
```

## Proof of Concept

```move
#[test]
#[expected_failure(arithmetic_error, location = vault_utils)]
public fun test_withdrawal_dos_with_zero_oracle_price() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Initialize vault and oracle
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(OWNER);
    {
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        let mut aggregator = mock_aggregator::create_mock_aggregator(scenario.ctx());
        
        // Set oracle price to zero (simulating oracle malfunction)
        mock_aggregator::set_current_result(&mut aggregator, 0, 0);
        
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            9,
            &aggregator,
        );
        
        scenario.return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };
    
    scenario.next_tx(OWNER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let oracle_config = scenario.take_shared<OracleConfig>();
        let operation = scenario.take_shared<Operation>();
        let operator_cap = scenario.take_from_sender<OperatorCap>();
        
        // Attempt to execute withdrawal - will abort on division by zero
        vault.execute_withdraw(
            &clock,
            &oracle_config,
            1, // request_id
            1000000, // max_amount_received
        );
        
        scenario.return_shared(vault);
        scenario.return_shared(oracle_config);
        scenario.return_shared(operation);
        scenario.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

## Notes

This vulnerability is distinct from typical oracle manipulation attacks. It does not require malicious oracle operators or price manipulation. Instead, it exploits the protocol's failure to handle a realistic edge case (zero prices) that can occur through legitimate oracle infrastructure failures.

The impact is particularly severe because:
1. It affects the core user-facing functionality (withdrawals)
2. It can cause permanent DoS if not quickly detected and remediated
3. It creates systemic risk across all vault operations that depend on oracle prices
4. Recovery requires admin intervention to either fix the oracle feed or replace it

The vulnerability demonstrates inadequate defensive programming against external dependency failures, a critical consideration for DeFi protocols that integrate with third-party oracle systems.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L49-53)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L62-66)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-52)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L54-58)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```
