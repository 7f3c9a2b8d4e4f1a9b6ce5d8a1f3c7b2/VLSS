### Title
Oracle Version Mismatch Blocks Critical Liquidations Leading to Bad Debt Accumulation

### Summary
The oracle's strict version verification mechanism creates an unavoidable window during protocol upgrades where all liquidation operations are blocked. When `oracle_constants::version()` is incremented but the shared `PriceOracle` object is not immediately migrated, any operation requiring price data—including critical liquidations—will abort, preventing unhealthy positions from being liquidated and causing bad debt accumulation.

### Finding Description

The oracle price fetching system enforces strict version matching through a multi-layer check: [1](#0-0) 

This version check is invoked by every oracle price query: [2](#0-1) [3](#0-2) 

The oracle version constant is defined as: [4](#0-3) 

Critical liquidation operations depend on oracle prices to verify unhealthy positions: [5](#0-4) 

The health check requires price data through this call chain: [6](#0-5) [7](#0-6) [8](#0-7) 

While a migration function exists, it requires explicit admin action: [9](#0-8) 

**Root Cause:** The version check is enforced at the lowest level of price queries with no fallback mechanism, creating a binary state where all operations either work or completely fail based on version matching.

**Why Protections Fail:** During protocol upgrades, there is an unavoidable window between when the code is deployed (with incremented `version()` constant) and when the admin calls `oracle_version_migrate()` to update the shared `PriceOracle` object. Even with immediate migration, transaction ordering on the blockchain means this window exists.

### Impact Explanation

**Direct Impact:**
- All liquidation operations abort with error code 6200 (`incorrect_version`) during the version mismatch window
- Underwater positions cannot be liquidated, regardless of how unhealthy they become
- Interest continues accruing on borrows, making positions increasingly underwater
- Protocol accumulates bad debt equal to (debt - collateral value) for all unliquidatable positions

**Affected Parties:**
- Protocol: Suffers insolvency from bad debt accumulation
- Depositors: Their funds back the bad debt, reducing their actual recoverable value
- Liquidators: Cannot perform their critical role in maintaining protocol health

**Severity Justification:**
This is **CRITICAL** because:
1. It completely disables the protocol's primary defense against insolvency (liquidations)
2. In volatile markets, positions can deteriorate rapidly (within minutes), making even short windows dangerous
3. If the migration is delayed or forgotten during off-hours, the damage compounds exponentially
4. The impact scales with protocol TVL—larger protocols face larger potential bad debt

**Quantified Damage:**
If a position with $1M collateral and $900K debt (health factor 1.11) drops to $950K collateral value during a 30-minute version mismatch window, the protocol suffers $50K immediate loss with no recovery mechanism.

### Likelihood Explanation

**Reachable Entry Point:**
Any public liquidation function (e.g., `lending::liquidation_non_entry()`) can be called during the version mismatch window. [10](#0-9) 

**Feasible Preconditions:**
1. Protocol code is upgraded with incremented `oracle_constants::version()`
2. Shared `PriceOracle` object has not yet been migrated
3. At least one position exists that should be liquidated

These conditions occur during every protocol upgrade—a routine operational event, not a rare circumstance.

**Execution Practicality:**
No attacker action required. This occurs through normal protocol operations:
- Step 1: Deploy code upgrade (version constant changes)
- Step 2: [WINDOW OPENS] - All liquidations blocked
- Step 3: Admin submits migration transaction
- Step 4: [WINDOW CLOSES] - Liquidations resume

Even with perfect admin response time, blockchain transaction ordering creates an unavoidable multi-block window.

**Detection/Operational Constraints:**
- No on-chain detection mechanism exists
- Off-chain monitoring could detect the version mismatch, but cannot prevent the window
- If upgrade occurs during off-hours or timezone differences exist in the team, the window could last hours

**Probability:**
**HIGH** - Occurs during every protocol upgrade that increments the oracle version. Given that DeFi protocols typically upgrade multiple times per year, this vulnerability will manifest repeatedly.

### Recommendation

**Immediate Mitigation:**
1. Modify `oracle::get_token_price()` to implement graceful version handling:
   - Accept prices from oracle version N when code expects N+1
   - Only reject if oracle version is more than 1 behind (N-1 or earlier)
   - This allows migration to happen without blocking operations [3](#0-2) 

**Code-Level Fix:**
```move
public fun get_token_price(
    clock: &Clock,
    price_oracle: &PriceOracle,
    oracle_id: u8
): (bool, u256, u8) {
    // Allow oracle version to be equal OR one less than code version
    assert!(
        price_oracle.version >= version::this_version() - 1 &&
        price_oracle.version <= version::this_version(),
        error::incorrect_version()
    );
    // ... rest of function
}
```

**Invariant Check:**
Add assertion in migration function to prevent skipping versions: [9](#0-8) 

```move
public(friend) fun oracle_version_migrate(_: &OracleAdminCap, oracle: &mut PriceOracle) {
    assert!(oracle.version == version::this_version() - 1, error::invalid_migration());
    oracle.version = version::this_version();
}
```

**Test Cases:**
1. Test liquidation during version N oracle with version N+1 code (should succeed)
2. Test liquidation during version N-1 oracle with version N+1 code (should fail)
3. Test migration prevents skipping versions
4. Test all health-checking operations (withdraw, borrow, liquidate) during version transition

**Operational Procedure:**
1. Before upgrading code, prepare migration transaction
2. Submit both transactions in same PTB (Programmable Transaction Block)
3. Monitor liquidations immediately after upgrade
4. Implement circuit breaker if version mismatch detected

### Proof of Concept

**Initial State:**
- `oracle_constants::version()` returns 2
- Shared `PriceOracle` object has `version: 2`
- User Alice has position: $1000 collateral, $850 debt (health factor 1.18)
- Collateral price drops, position now worth $900 (health factor 0.96, liquidatable)

**Exploit Steps:**

1. **Protocol Upgrade Deployed:**
   - New code deployed with `oracle_constants::version()` returning 3
   - Shared `PriceOracle` object still has `version: 2` in state
   - Version mismatch created

2. **Liquidator Bob Attempts Liquidation:**
   ```
   Transaction: liquidation_non_entry<USDC, SUI>(
       clock, oracle, storage, 
       debt_asset=0, debt_pool, debt_balance,
       collateral_asset=1, collateral_pool,
       alice_address, ctx
   )
   ```

3. **Execution Path:**
   - `base_liquidation_call()` → `logic::execute_liquidate()`
   - `execute_liquidate()` → `is_health()` (line 212)
   - `is_health()` → `user_health_factor()` 
   - `user_health_factor()` → `user_collateral_value()` → `calculator::calculate_value()`
   - `calculate_value()` → `oracle::get_token_price()`
   - `get_token_price()` → `version_verification()` 
   - `version_verification()` → `version::pre_check_version(2)`
   - `pre_check_version()`: `assert!(2 == 3, 6200)` → **ABORTS**

4. **Result:**
   - **Expected:** Liquidation succeeds, Bob receives collateral + bonus, protocol health restored
   - **Actual:** Transaction aborts with error 6200, Alice's underwater position remains unliquidated

5. **Consequence:**
   - Alice's position deteriorates further as interest accrues
   - If price drops to $800, protocol now has $50 bad debt
   - Multiple such positions create protocol insolvency

**Success Condition:**
Transaction aborts prove that version mismatch blocks liquidations. Protocol monitoring shows accumulating underwater positions that cannot be liquidated during the version mismatch window.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_version.move (L13-15)
```text
    public fun pre_check_version(v: u64) {
        assert!(v == constants::version(), error::incorrect_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L65-67)
```text
    fun version_verification(oracle: &PriceOracle) {
        version::pre_check_version(oracle.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L74-77)
```text
    public(friend) fun oracle_version_migrate(_: &OracleAdminCap, oracle: &mut PriceOracle) {
        assert!(oracle.version <= version::this_version(), error::not_available_version());
        oracle.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L28-28)
```text
    public fun version(): u64 { 2 }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L193-212)
```text
    public(friend) fun execute_liquidate<CoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        user: address,
        collateral_asset: u8,
        debt_asset: u8,
        amount: u256
    ): (u256, u256, u256) {
        // check if the user has loan on this asset
        assert!(is_loan(storage, debt_asset, user), error::user_have_no_loan());
        // check if the user's liquidated assets are collateralized
        assert!(is_collateral(storage, collateral_asset, user), error::user_have_no_collateral());

        update_state_of_all(clock, storage);

        validation::validate_liquidate<CoinType, CollateralCoinType>(storage, debt_asset, collateral_asset, amount);

        // Check the health factor of the user
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L379-391)
```text
    public fun user_health_factor(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // 
        let health_collateral_value = user_health_collateral_value(clock, oracle, storage, user); // 202500000000000
        let dynamic_liquidation_threshold = dynamic_liquidation_threshold(clock, storage, oracle, user); // 650000000000000000000000000
        let health_loan_value = user_health_loan_value(clock, oracle, storage, user); // 49500000000
        if (health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(health_collateral_value, health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L408-439)
```text
    fun base_liquidation_call<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_balance: Balance<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        executor: address,
        liquidate_user: address
    ): (Balance<DebtCoinType>, Balance<CollateralCoinType>) {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let debt_amount = balance::value(&debt_balance);
        pool::deposit_balance(debt_pool, debt_balance, executor);

        let normal_debt_amount = pool::normal_amount(debt_pool, debt_amount);
        let (
            normal_obtainable_amount,
            normal_excess_amount,
            normal_treasury_amount
        ) = logic::execute_liquidate<DebtCoinType, CollateralCoinType>(
            clock,
            oracle,
            storage,
            liquidate_user,
            collateral_asset,
            debt_asset,
            (normal_debt_amount as u256)
        );
```
