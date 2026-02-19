### Title
Supra Oracle Failure Causes Complete DoS - Fallback to Pyth Never Executes on Abort

### Summary
The oracle system's fallback mechanism from Supra to Pyth only handles stale timestamps, not oracle call failures. When Supra is configured as the primary oracle and its `get_price()` call aborts (due to network issues, invalid pair_id, or oracle contract errors), the entire price update transaction aborts before the secondary Pyth oracle is ever attempted, causing a complete denial of service for all price-dependent operations.

### Finding Description

The oracle system implements a dual-provider architecture where administrators can configure a primary and secondary oracle provider (e.g., Supra primary, Pyth secondary). The intended design is to provide automatic fallback when the primary source fails. [1](#0-0) [2](#0-1) 

However, the critical flaw exists in the price update flow. The primary oracle price is fetched **first** and unconditionally: [3](#0-2) 

This call chain leads to the Supra adaptor: [4](#0-3) 

The Supra adaptor makes an unprotected external call to the SupraOracle contract: [5](#0-4) 

**Root Cause**: If `supra::get_price()` aborts for any reason (pair not found, oracle contract error, network issues), the entire transaction aborts immediately. The fallback logic is never reached because it occurs **after** the primary price fetch: [6](#0-5) 

The fallback mechanism only handles the case where the primary returns a **stale timestamp**, not when it **aborts**: [7](#0-6) 

**Why Protections Fail**: Move has no try-catch mechanism. Once `supra::get_price()` aborts, there is no way to recover and attempt the secondary oracle. The entire programmable transaction block (PTB) fails.

### Impact Explanation

**Concrete Harm**:
- All price update operations fail when Supra oracle is unavailable
- Protocol cannot obtain fresh prices from any source, even though Pyth remains functional
- Operations requiring recent oracle prices (within `update_interval` of 60 seconds) will fail with `ERR_PRICE_NOT_UPDATED` [8](#0-7) 

**Protocol-Wide Impact**:
1. **Vault Operations**: Asset valuation fails, blocking deposits, withdrawals, and operations
2. **Lending Protocol**: Health factor calculations fail, preventing liquidations and new borrows
3. **Price Staleness**: Existing stale prices remain, potentially enabling exploitation during market volatility

**Affected Parties**:
- All vault users unable to execute operations
- Lenders unable to manage positions
- Protocol exposed to under-collateralized positions if prices become stale during Supra downtime

**Severity Justification**: HIGH - Complete protocol DoS affecting all price-dependent operations, with no automatic recovery mechanism. The impact extends beyond inconvenience to potential financial losses if stale prices enable exploitation.

### Likelihood Explanation

**Realistic Preconditions**:
- Supra oracle must be configured as the primary provider (design encourages this for cost efficiency)
- Supra oracle experiences any failure: invalid pair_id configuration, contract bug, network issues, oracle feed downtime

**Attack Complexity**: No attacker action needed - this is a natural operational failure that occurs when Supra has issues.

**Feasibility**: VERY HIGH
- External oracle dependencies inherently carry availability risk
- The Supra oracle is a third-party service outside protocol control
- Network conditions, oracle maintenance, or configuration errors can trigger this

**Detection/Operational Constraints**:
- Failure is immediately visible (all price updates fail)
- Manual intervention required: admin must disable Supra provider and set Pyth as primary
- Recovery time depends on admin availability and response time [9](#0-8) [10](#0-9) 

**Probability**: MEDIUM-HIGH - While not continuously occurring, oracle downtime is a realistic operational risk that external dependencies introduce.

### Recommendation

**Implement Graceful Degradation with Error Handling**:

Since Move lacks try-catch, implement provider selection logic that checks provider availability before attempting fetches:

1. **Add provider health check function** that attempts a lightweight query or maintains a provider status flag updated by off-chain monitoring
2. **Modify fetch sequence** to skip disabled/unhealthy providers automatically
3. **Implement circuit breaker pattern**: Auto-disable primary provider after N consecutive failures, promote secondary to primary
4. **Add emergency override**: Allow `OracleAdminCap` to quickly swap primary/secondary without complex reconfiguration

**Specific Code Changes**:

Add to `oracle_pro.move`:
```
// Before line 83, add health check
if (is_provider_unhealthy(primary_oracle_provider)) {
    // Skip primary, attempt secondary directly
    // Emit warning event
}
```

**Invariant Checks to Add**:
- Ensure at least one enabled provider exists before allowing price feed operations
- Validate secondary provider is genuinely different from primary and functional
- Add staleness limits that trigger automatic provider failover

**Test Cases**:
1. Test Supra abort during `get_price()` with Pyth configured as secondary - should use Pyth
2. Test both providers failing - should gracefully return error without transaction abort
3. Test automatic provider demotion after consecutive failures
4. Test admin emergency provider swap under load

### Proof of Concept

**Initial State**:
- Price feed configured with Supra as primary provider, Pyth as secondary
- Both providers enabled
- Fresh prices available from Pyth, but Supra oracle experiences failure

**Transaction Steps**:

1. Call `oracle_pro::update_single_price()` with valid `OracleHolder` and `PriceInfoObject`
2. Function reaches line 83: `get_price_from_adaptor(primary_oracle_provider_config, ...)`
3. Routes to Supra adaptor at line 170-172
4. Calls `supra::get_price(supra_oracle_holder, supra_pair_id)` at adaptor line 8
5. **Supra oracle aborts** (e.g., `pair not found` error)

**Expected Result** (Intended Behavior):
- System detects Supra failure
- Falls back to Pyth secondary provider
- Successfully updates price using Pyth data

**Actual Result**:
- Entire transaction aborts at step 5
- No fallback to Pyth (line 93 never reached)
- No price update occurs
- All dependent operations fail with stale price errors

**Success Condition for Vulnerability**:
The transaction aborts without attempting the secondary provider, demonstrating the fallback mechanism is non-functional for oracle call failures (only works for stale timestamps).

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L384-398)
```text
    public(friend) fun set_primary_oracle_provider(cfg: &mut OracleConfig, feed_id: address, provider: OracleProvider) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        if (price_feed.primary == provider) {
            return
        };
        let before_provider = price_feed.primary;

        assert!(table::contains(&price_feed.oracle_provider_configs, provider), error::provider_config_not_found());
        let provider_config = table::borrow(&price_feed.oracle_provider_configs, provider);
        assert!(oracle_provider::is_oracle_provider_config_enable(provider_config), error::oracle_provider_disabled());
        price_feed.primary = provider;

        emit(SetOracleProvider {config: object::uid_to_address(&cfg.id), feed_id: feed_id, is_primary: true, provider: oracle_provider::to_string(&provider), before_provider: oracle_provider::to_string(&before_provider)});
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L400-416)
```text
    public(friend) fun set_secondary_oracle_provider(cfg: &mut OracleConfig, feed_id: address, provider: OracleProvider) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        if (price_feed.secondary == provider) {
            return
        };
        let before_provider = price_feed.secondary;

        // assert should be like this
        if (!oracle_provider::is_empty(&provider)) {
            assert!(table::contains(&price_feed.oracle_provider_configs, provider), error::provider_config_not_found());
        };

        price_feed.secondary = provider;

        emit(SetOracleProvider {config: object::uid_to_address(&cfg.id), feed_id: feed_id, is_primary: false, provider: oracle_provider::to_string(&provider), before_provider: oracle_provider::to_string(&before_provider)});
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L83-84)
```text
        let (primary_price, primary_updated_time) = get_price_from_adaptor(primary_oracle_provider_config, decimal, supra_oracle_holder, pyth_price_info);
        let is_primary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, primary_updated_time, max_timestamp_diff);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L91-95)
```text
        if (is_secondary_oracle_available) {
            let secondary_source_config = config::get_secondary_source_config(price_feed);
            (secondary_price, secondary_updated_time) = get_price_from_adaptor(secondary_source_config, decimal, supra_oracle_holder, pyth_price_info);
            is_secondary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, secondary_updated_time, max_timestamp_diff);
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L121-131)
```text
        } else if (is_primary_price_fresh) { // if secondary price not fresh and primary price fresh
            if (is_secondary_oracle_available) { // prevent single source mode from keeping emitting event
                emit(OracleUnavailable {type: constants::secondary_type(), config_address, feed_address, provider: provider::to_string(config::get_secondary_oracle_provider(price_feed)), price: secondary_price, updated_time: secondary_updated_time});
            };
        } else if (is_secondary_price_fresh) { // if primary price not fresh and secondary price fresh
            emit(OracleUnavailable {type: constants::primary_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            final_price = secondary_price;
        } else { // no fresh price, terminate price feed
            emit(OracleUnavailable {type: constants::both_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            return
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L167-183)
```text
    public fun get_price_from_adaptor(oracle_provider_config: &OracleProviderConfig, target_decimal: u8, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject): (u256, u64) {
        let (provider, pair_id) = (provider::get_provider_from_oracle_provider_config(oracle_provider_config), config::get_pair_id_from_oracle_provider_config(oracle_provider_config));
        if (provider == provider::supra_provider()) {
            let supra_pair_id = oracle::adaptor_supra::vector_to_pair_id(pair_id);
            let (price, timestamp) = oracle::adaptor_supra::get_price_to_target_decimal(supra_oracle_holder, supra_pair_id, target_decimal);
            return (price, timestamp)
        };

        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
        };

        abort error::invalid_oracle_provider()
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_supra.move (L7-10)
```text
    public fun get_price_native(supra_oracle_holder: &OracleHolder, pair: u32): (u128, u16, u128){
        let (price, decimal, timestamp, _) = supra::get_price(supra_oracle_holder, pair);
        (price, decimal, timestamp)
    }
```

**File:** volo-vault/sources/oracle.move (L134-137)
```text
    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L122-125)
```text
    public fun disable_supra_oracle_provider(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address) {
        config::version_verification(oracle_config);
        config::set_oracle_provider_config_enable(oracle_config, feed_id, oracle_provider::supra_provider(), false)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L127-130)
```text
    public fun set_primary_oracle_provider(_: &OracleAdminCap, cfg: &mut OracleConfig, feed_id: address, provider: OracleProvider) {
        config::version_verification(cfg);
        config::set_primary_oracle_provider(cfg, feed_id, provider)
    }
```
