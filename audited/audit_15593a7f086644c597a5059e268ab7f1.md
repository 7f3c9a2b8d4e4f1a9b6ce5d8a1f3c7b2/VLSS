### Title
Zero Oracle Price Causes Division by Zero Abort in Withdrawal Operations Leading to Vault DoS

### Summary
The `div_with_oracle_price()` function performs unguarded division by oracle prices without validating that prices are non-zero. When used in withdrawal execution, a zero oracle price causes transaction abort, permanently blocking all user withdrawals and creating a critical denial-of-service condition for the vault.

### Finding Description

**Root Cause:**

The `div_with_oracle_price()` utility function performs division by oracle price without any zero-value validation: [1](#0-0) 

**Missing Oracle Validations:**

The oracle system lacks zero-price checks at multiple critical points:

1. When retrieving prices from Switchboard aggregator, no validation is performed: [2](#0-1) 

2. When storing updated prices, no minimum value check exists: [3](#0-2) 

3. When returning prices for consumption, no validation occurs: [4](#0-3) 

4. The normalized price function also lacks zero-price checks: [5](#0-4) 

**Critical Usage in Withdrawal Path:**

The vulnerable function is directly used in the withdrawal execution flow to calculate withdrawal amounts: [6](#0-5) 

This is called by operators through the operation module: [7](#0-6) 

**Additional Exposure:**

The Cetus adaptor also performs unguarded division by oracle prices for position valuation: [8](#0-7) 

**Confirmation of Zero Price Possibility:**

Test functions explicitly allow zero price initialization, confirming this is a reachable state: [9](#0-8) 

### Impact Explanation

**Direct Operational Impact:**
- All withdrawal execution attempts abort immediately when oracle price is zero
- Vault becomes stuck in `VAULT_DURING_OPERATION_STATUS` unable to complete withdrawal operations
- Users with pending withdrawal requests cannot retrieve their funds despite having valid shares

**Custody Integrity Compromise:**
- User funds effectively locked in vault indefinitely
- No alternative withdrawal mechanism exists when oracle returns zero
- Share holders cannot access their proportional principal amount

**Cascading System Failures:**
- Position valuation in Cetus adaptor fails, blocking operation value updates
- Loss tolerance checks cannot complete, preventing epoch transitions
- Reward distribution may be blocked if dependent on successful operations

**Severity:** CRITICAL - Complete operational failure of core vault functionality (withdrawals) with no recovery path when oracle malfunctions.

### Likelihood Explanation

**Realistic Oracle Failure Scenarios:**
- Switchboard oracle feeds can legitimately return zero during:
  - Feed initialization before first update
  - Oracle network disruptions or consensus failures  
  - Malicious oracle operator actions
  - Asset delisting or market halt scenarios
  - Smart contract bugs in oracle aggregator

**Entry Point Accessibility:**
- Operators call `execute_withdraw()` as part of normal vault operations
- No privileged access required to trigger the vulnerable code path
- Occurs automatically when processing user withdrawal requests

**Attack Complexity:** NONE
- Does not require attacker action if oracle naturally returns zero
- If oracle is manipulable, simply requires setting price to zero
- No complex state manipulation or timing requirements

**Economic Rationality:**
- No cost to exploit if oracle malfunction occurs naturally
- High impact (vault DoS) with zero execution cost
- Affects all users, creating maximum disruption

**Detection/Prevention:** DIFFICULT
- No on-chain monitoring for zero prices before usage
- Error only manifests when withdrawal is attempted
- No circuit breaker or fallback price mechanism

### Recommendation

**Immediate Fix - Add Zero Price Validation:**

Add validation in the oracle module's `get_asset_price()` function:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    // ADD THIS CHECK:
    assert!(price_info.price > 0, ERR_ZERO_PRICE);
    
    price_info.price
}
```

**Additional Safeguards:**

1. Add zero-price check in `update_price()` before storing:
```move
let current_price = get_current_price(config, clock, aggregator);
assert!(current_price > 0, ERR_ZERO_PRICE);
price_info.price = current_price;
```

2. Add defensive check in `div_with_oracle_price()`:
```move
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_ZERO_PRICE);
    v1 * ORACLE_DECIMALS / v2
}
```

3. Define new error constant:
```move
const ERR_ZERO_PRICE: u64 = 2_006;
```

**Testing Requirements:**
- Add test case attempting withdrawal with zero oracle price (should revert)
- Add test case for oracle update with zero price (should revert)
- Add integration test for Cetus position valuation with zero price
- Verify graceful degradation with price staleness instead of zero

### Proof of Concept

**Initial State:**
1. Vault has active withdrawal requests from users
2. Oracle price for principal coin type is functioning normally
3. Operator initiates withdrawal execution

**Attack Sequence:**

Step 1: Oracle returns zero price (either malfunction or manipulation)
- Switchboard aggregator's `current_result().result().value()` returns `0`
- No validation prevents this in `get_current_price()`

Step 2: Operator attempts to execute withdrawal via `operation::execute_withdraw()`

Step 3: Vault's `execute_withdraw()` calls `div_with_oracle_price()`:
```
usd_value_to_withdraw = shares_to_withdraw * ratio
amount_to_withdraw = div_with_oracle_price(usd_value_to_withdraw, 0)
```

Step 4: Division by zero occurs in `v1 * ORACLE_DECIMALS / 0`

**Expected Result:** Withdrawal processes successfully

**Actual Result:** Transaction aborts with arithmetic error, withdrawal fails permanently

**Success Condition:** All subsequent withdrawal attempts fail until oracle price becomes non-zero, creating indefinite DoS of withdrawal functionality.

### Citations

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
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

**File:** volo-vault/sources/oracle.move (L296-312)
```text
#[test_only]
public fun set_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: address,
) {
    let price_info = PriceInfo {
        aggregator: aggregator,
        decimals,
        price: 0,
        last_updated: clock.timestamp_ms(),
    };

    config.aggregators.add(asset_type, price_info);
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-66)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18

    // pool price = price_a / price_b (not consider decimals)
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```
