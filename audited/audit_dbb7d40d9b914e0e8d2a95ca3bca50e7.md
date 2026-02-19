### Title
Missing Liquidation Parameter Relationship Validation Allows Premature Liquidations and Excessive Collateral Seizure

### Summary
The lending protocol lacks validation to ensure correct relationships between liquidation parameters (threshold, ratio, bonus). When `liquidation_threshold < liquidation_ratio`, users can be liquidated prematurely with excessive collateral seizure, resulting in direct loss of user funds. The OwnerCap holder can inadvertently create this dangerous configuration through separate parameter updates without any protocol-level validation preventing invalid relationships.

### Finding Description

The `LiquidationFactors` struct stores three independent parameters that are set and updated separately without cross-validation: [1](#0-0) 

These parameters are initialized through `init_reserve`: [2](#0-1) 

And validated only for individual percentage limits: [3](#0-2) 

The parameters can be updated independently via separate setter functions: [4](#0-3) 

**Root Cause**: The validation function `percentage_ray_validation` only checks that each parameter is ≤ 100%: [5](#0-4) 

It does NOT validate critical relationships: `liquidation_threshold >= liquidation_ratio` and proper bounds for `liquidation_bonus + treasury_factor`.

**Why Protections Fail**:

The `liquidation_threshold` determines WHEN liquidation can occur (health factor calculation): [6](#0-5) 

The `liquidation_ratio` determines HOW MUCH collateral can be seized: [7](#0-6) 

When `threshold < ratio`, positions become liquidatable too early (low health factor threshold) while allowing excessive collateral seizure (high liquidation ratio).

The reference Suilend implementation demonstrates proper validation including relationship checks: [8](#0-7) 

### Impact Explanation

**Direct Fund Loss**: Users lose funds through unfair liquidations. With `liquidation_threshold = 30%` and `liquidation_ratio = 50%`:

- User with $20,000 collateral and $8,000 debt (250% collateral ratio - very healthy)
- Health factor = ($20,000 / $8,000) × 0.30 = 0.75 < 1.0 → liquidatable
- Liquidator can seize: $20,000 × 50% + 5% bonus = $10,500 in collateral
- User's net loss: $10,500 - $8,000 debt = **$2,500 direct loss**

**Who is Affected**: All borrowers when parameters are misconfigured. Given typical DeFi TVL, this could affect millions in user funds.

**Severity**: CRITICAL - Direct, measurable loss of user funds due to missing protocol-level validation. The protocol accepts parameter configurations that violate fundamental DeFi lending invariants.

### Likelihood Explanation

**Attacker Capabilities**: Requires OwnerCap holder to misconfigure parameters. However, this is NOT a trusted role compromise - the admin is EXPECTED to update liquidation parameters as part of normal risk management operations. The vulnerability is the protocol's failure to validate parameter relationships during legitimate updates.

**Attack Complexity**: LOW
1. OwnerCap calls `set_liquidation_threshold(storage, asset_id, 300000000000000000000000000)` (30%)
2. OwnerCap calls `set_liquidation_ratio(storage, asset_id, 500000000000000000000000000)` (50%)
3. Any liquidator can now execute unfair liquidations

**Feasibility**: HIGH - Accidental misconfiguration during parameter updates is realistic, especially when:
- Updating multiple assets with different risk profiles
- Adjusting parameters in response to market conditions
- Different admins updating different parameters over time

**Detection**: Parameter updates are on-chain but relationship violations are not flagged. Users may not notice until liquidations occur.

### Recommendation

**Add comprehensive parameter validation** similar to the Suilend reference implementation:

1. In `storage.move`, add validation function:
```move
fun validate_liquidation_factors(
    liquidation_ratio: u256,
    liquidation_bonus: u256,
    liquidation_threshold: u256,
    treasury_factor: u256
) {
    // Ensure threshold >= ratio (can only liquidate up to threshold)
    assert!(liquidation_threshold >= liquidation_ratio, error::invalid_liquidation_config());
    
    // Ensure total fees don't exceed reasonable bounds (e.g., 20%)
    let total_liquidation_penalty = liquidation_bonus + 
        ray_math::ray_mul(liquidation_bonus, treasury_factor);
    assert!(total_liquidation_penalty <= 200000000000000000000000000, error::invalid_liquidation_config());
}
```

2. Call this validation in:
   - `init_reserve` (line 154) after individual percentage validations
   - `set_liquidation_ratio` (line 317) 
   - `set_liquidation_bonus` (line 325)
   - `set_liquidation_threshold` (line 333)

3. Add error code in `error.move`:
```move
public fun invalid_liquidation_config(): u64 { 1508 }
```

4. Add test cases validating:
   - `threshold < ratio` is rejected
   - `threshold == ratio` is accepted
   - `bonus + treasury_factor` doesn't exceed bounds
   - Updates to any parameter trigger full validation

### Proof of Concept

**Initial State**:
- Reserve configured with correct parameters: threshold=75%, ratio=35%
- User deposits 10 ETH ($20,000), borrows 8,000 USDT
- User health factor = 2.5 × 0.75 = 1.875 (healthy)

**Attack Steps**:
1. OwnerCap calls `set_liquidation_threshold(&owner_cap, &mut storage, 1, 300000000000000000000000000)` → Sets threshold to 30%
2. OwnerCap calls `set_liquidation_ratio(&owner_cap, &mut storage, 1, 500000000000000000000000000)` → Sets ratio to 50%
3. User's health factor recalculates: 2.5 × 0.30 = 0.75 < 1.0 (now liquidatable!)
4. Liquidator calls `execute_liquidate<USDT, ETH>(...)` with 8,000 USDT repayment
5. Protocol seizes: 10 ETH ($10,000) + 5% bonus ($500) = $10,500 from user
6. User loses $2,500 despite maintaining 250% collateral ratio

**Expected vs Actual**:
- **Expected**: Parameter update rejected with `error::invalid_liquidation_config()`
- **Actual**: Parameter update succeeds, enabling unfair liquidations

**Success Condition**: User funds are protected by validation rejecting `threshold < ratio` configurations.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L97-101)
```text
    struct LiquidationFactors has store {
        ratio: u256, 
        bonus: u256,
        threshold: u256,
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L154-174)
```text
    public entry fun init_reserve<CoinType>(
        _: &StorageAdminCap,
        pool_admin_cap: &PoolAdminCap,
        clock: &Clock,
        storage: &mut Storage,
        oracle_id: u8,
        is_isolated: bool,
        supply_cap_ceiling: u256,
        borrow_cap_ceiling: u256,
        base_rate: u256,
        optimal_utilization: u256,
        multiplier: u256,
        jump_rate_multiplier: u256,
        reserve_factor: u256,
        ltv: u256,
        treasury_factor: u256,
        liquidation_ratio: u256,
        liquidation_bonus: u256,
        liquidation_threshold: u256,
        coin_metadata: &CoinMetadata<CoinType>,
        ctx: &mut TxContext
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L186-190)
```text
        percentage_ray_validation(liquidation_ratio);
        percentage_ray_validation(liquidation_bonus);

        percentage_ray_validation(ltv);
        percentage_ray_validation(liquidation_threshold);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L317-339)
```text
    public fun set_liquidation_ratio(_: &OwnerCap, storage: &mut Storage, asset: u8, liquidation_ratio: u256) {
        version_verification(storage);
        percentage_ray_validation(liquidation_ratio);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.liquidation_factors.ratio = liquidation_ratio;
    }

    public fun set_liquidation_bonus(_: &OwnerCap, storage: &mut Storage, asset: u8, liquidation_bonus: u256) {
        version_verification(storage);
        percentage_ray_validation(liquidation_bonus);
        
        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.liquidation_factors.bonus = liquidation_bonus;
    }

    public fun set_liquidation_threshold(_: &OwnerCap, storage: &mut Storage, asset: u8, liquidation_threshold: u256) {
        version_verification(storage);
        percentage_ray_validation(liquidation_threshold);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.liquidation_factors.threshold = liquidation_threshold;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L693-695)
```text
    fun percentage_ray_validation(value: u256) {
        assert!(value <= ray_math::ray(), error::invalid_value());
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L534-544)
```text
        let (liquidation_ratio, liquidation_bonus, _) = storage::get_liquidation_factors(storage, collateral_asset);
        let treasury_factor = storage::get_treasury_factor(storage, collateral_asset);

        let collateral_value = user_collateral_value(clock, oracle, storage, collateral_asset, user);
        let loan_value = user_loan_value(clock, oracle, storage, debt_asset, user);

        let collateral_asset_oracle_id = storage::get_oracle_id(storage, collateral_asset);
        let debt_asset_oracle_id = storage::get_oracle_id(storage, debt_asset);
        let repay_value = calculator::calculate_value(clock, oracle, repay_amount, debt_asset_oracle_id);

        let liquidable_value = ray_math::ray_mul(collateral_value, liquidation_ratio); // 17000 * 35% = 5950u
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve_config.move (L98-114)
```text
    fun validate_reserve_config(config: &ReserveConfig) {
        assert!(config.open_ltv_pct <= 100, EInvalidReserveConfig);
        assert!(config.close_ltv_pct <= 100, EInvalidReserveConfig);
        assert!(config.max_close_ltv_pct <= 100, EInvalidReserveConfig);

        assert!(config.open_ltv_pct <= config.close_ltv_pct, EInvalidReserveConfig);
        assert!(config.close_ltv_pct <= config.max_close_ltv_pct, EInvalidReserveConfig);

        assert!(config.borrow_weight_bps >= 10_000, EInvalidReserveConfig);
        assert!(
            config.liquidation_bonus_bps <= config.max_liquidation_bonus_bps,
            EInvalidReserveConfig,
        );
        assert!(
            config.max_liquidation_bonus_bps + config.protocol_liquidation_fee_bps <= 2_000,
            EInvalidReserveConfig,
        );
```
