### Title
Unrestricted Public Oracle Price Update Function Allows Unauthorized State Modification

### Summary
The `update_price` function in the vault oracle module is declared as `public fun` and modifies the shared `OracleConfig` object without requiring `AdminCap` or `OperatorCap` authorization. This maps directly to the external report's vulnerability class where state-modifying functions should use `public(package)` or capability-based access control instead of being fully public. Any untrusted actor can invoke this function to force oracle price updates at arbitrary times, enabling timing manipulation attacks and potential denial-of-service.

### Finding Description

The vulnerability exists in [1](#0-0) 

The `update_price` function takes a mutable reference to the shared `OracleConfig` object and modifies critical state (price and timestamp) without any capability checks. The OracleConfig is created as a shared object [2](#0-1) , which means any actor can obtain a mutable reference to it and call public functions.

Unlike the external report where `&mut Permission` of owned objects cannot be obtained by others, the Volo `OracleConfig` is a **shared object**, making this vulnerability more severe. While the function validates that the aggregator address matches the registered aggregator and reads prices from Switchboard (preventing arbitrary price injection), it still allows:

1. **Timing manipulation**: Attackers can force price updates at strategic moments before/after their vault operations to exploit price-dependent logic
2. **Denial-of-service**: Spamming price updates to consume gas or interfere with legitimate operations
3. **Violation of access control principle**: Critical state modifications lack authorization

All other vault configuration setters properly use `public(package)` visibility [3](#0-2)  or require capabilities [4](#0-3) , but `update_price` bypasses this pattern.

### Impact Explanation

**Pricing/Oracle Manipulation via Timing Control**: Oracle prices are critical to vault operations including deposit/withdraw valuations, loss tolerance calculations, and asset value updates [5](#0-4) . An attacker can:

- Force price updates immediately before executing vault deposits/withdrawals to get favorable share calculations
- Manipulate the timing of price staleness checks by controlling when updates occur
- Interfere with legitimate price update schedules managed by protocol operators

**Denial-of-Service**: Continuous calls to `update_price` can cause gas griefing and prevent legitimate protocol operations from executing price updates at optimal times.

**Authorization Bypass**: The function bypasses the established capability-based access control pattern used throughout the Volo protocol, violating the principle of least privilege for state-modifying operations.

### Likelihood Explanation

**Entry Point**: The function is directly callable as `public fun` with no capability requirements [6](#0-5) 

**Preconditions**: 
- OracleConfig is a shared object - accessible by anyone
- Attacker only needs a reference to the correct Switchboard Aggregator object
- Clock object is publicly available on Sui
- No capability checks are performed

**Execution Path**:
1. Attacker obtains shared OracleConfig reference
2. Attacker calls `vault_oracle::update_price(&mut oracle_config, aggregator, clock, asset_type)`
3. Function updates price and timestamp in OracleConfig state
4. No authorization check prevents this

This is fully executable by any untrusted actor on mainnet with no special permissions required.

### Recommendation

Restrict the `update_price` function to package-level visibility or add capability-based authorization:

**Option 1 - Package visibility (recommended)**:
Change line 225 in `volo-vault/sources/oracle.move` from:
```rust
public fun update_price(
```
to:
```rust
public(package) fun update_price(
```

Then create a wrapper function in `volo-vault/sources/manage.move` that requires `OperatorCap`:
```rust
public fun update_oracle_price(
    _: &OperatorCap,
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    oracle::update_price(config, aggregator, clock, asset_type);
}
```

**Option 2 - Direct capability check**:
Add an `OperatorCap` parameter to the function signature and validate it within the function, consistent with how other vault operations are protected [7](#0-6) 

### Proof of Concept

1. **Setup**: Deploy Volo vault with OracleConfig as shared object (current mainnet state)
2. **Attack Execution**:
   - Attacker observes pending large deposit transaction in mempool
   - Attacker front-runs by calling `vault_oracle::update_price()` to update price to current Switchboard value
   - This forces price refresh at attacker-chosen timing
   - Attacker's own deposit transaction executes immediately after with the newly updated price
   - Attacker can time this to exploit any latency between Switchboard price movements and vault price updates
3. **Result**: Attacker gains unauthorized control over oracle update timing, bypassing intended operator-controlled price refresh schedule

The vulnerability is confirmed by test usage patterns [8](#0-7)  which show the function being called directly without any capability object, indicating it was designed to be publicly callable but this violates access control best practices for state-modifying functions on shared objects.

### Notes

This vulnerability directly maps to the external report's class: state-modifying functions should use restrictive visibility (`public(package)`) or capability-based access control instead of being fully `public`. The Volo implementation is actually more severe than the external example because OracleConfig is a shared object, making the mutable reference truly accessible to any caller, whereas the external report's Permission was presumably an owned object where access was naturally restricted by Move's ownership model.

### Citations

**File:** volo-vault/sources/oracle.move (L84-94)
```text
fun init(ctx: &mut TxContext) {
    let config = OracleConfig {
        id: object::new(ctx),
        version: VERSION,
        aggregators: table::new(ctx),
        update_interval: MAX_UPDATE_INTERVAL,
        dex_slippage: DEFAULT_DEX_SLIPPAGE,
    };

    transfer::share_object(config);
}
```

**File:** volo-vault/sources/oracle.move (L110-122)
```text
public(package) fun set_update_interval(config: &mut OracleConfig, update_interval: u64) {
    config.check_version();

    config.update_interval = update_interval;
    emit(UpdateIntervalSet { update_interval })
}

public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();

    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
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

**File:** volo-vault/sources/manage.move (L99-116)
```text
public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}

public fun remove_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    asset_type: String,
) {
    oracle_config.remove_switchboard_aggregator(asset_type);
}
```

**File:** volo-vault/sources/operation.move (L381-391)
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
```

**File:** volo-vault/tests/oracle.test.move (L367-372)
```text
        vault_oracle::update_price(
            &mut oracle_config,
            &aggregator,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
```
