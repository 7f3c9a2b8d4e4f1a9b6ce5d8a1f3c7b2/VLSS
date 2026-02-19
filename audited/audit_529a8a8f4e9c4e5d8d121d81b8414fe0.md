### Title
Missing Oracle ID Update Function in Lending Protocol Reserve Configuration

### Summary
The lending protocol's `oracle_id` parameter for each reserve is set during initialization but cannot be updated afterward, preventing critical oracle feed migrations. This mirrors the external report's vulnerability where Switchboard aggregator addresses could not be updated post-initialization. If an oracle feed becomes deprecated or compromised, the lending protocol must continue using potentially incorrect price data, affecting liquidations, health factors, and collateral valuations.

### Finding Description
The vulnerability exists in the lending protocol's storage module where each reserve is initialized with an `oracle_id` that maps to a specific oracle price feed. [1](#0-0) 

While the storage module provides setter functions for numerous other reserve parameters including `set_supply_cap`, `set_borrow_cap`, `set_ltv`, `set_treasury_factor`, `set_base_rate`, `set_multiplier`, `set_jump_rate_multiplier`, `set_reserve_factor`, `set_optimal_utilization`, `set_liquidation_ratio`, `set_liquidation_bonus`, and `set_liquidation_threshold`, [2](#0-1) 

There is no corresponding `set_oracle_id` function to update the oracle ID after reserve creation. The only way to set `oracle_id` is during the `init_reserve` function call. [3](#0-2) 

The `oracle_id` is critically used throughout the lending protocol for price fetching in value calculations, [4](#0-3)  collateral value computations, [5](#0-4)  loan value calculations, [6](#0-5)  and liquidation operations. [7](#0-6) 

### Impact Explanation
If an oracle feed requires updating due to system upgrades, feed deprecation, security vulnerabilities, or accuracy issues, administrators cannot modify the `oracle_id` mapping. The lending protocol would be forced to continue using stale, incorrect, or compromised price data for that reserve. This directly impacts:

- **Liquidation accuracy**: Incorrect prices lead to wrongful liquidations or failure to liquidate undercollateralized positions
- **Health factor calculations**: Users' borrowing capacity and liquidation thresholds become unreliable
- **Collateral valuations**: Deposits and withdrawals execute at incorrect conversion rates
- **Protocol solvency**: Persistent price feed issues could cause systemic bad debt accumulation

The only remediation would be creating an entirely new reserve with a different ID, requiring complex migration of all user positions and liquidity.

### Likelihood Explanation
This scenario has high likelihood in production environments:

- Oracle systems undergo regular upgrades and migrations (e.g., Pyth v1 to v2, Switchboard infrastructure changes)
- Price feeds can be deprecated or sunset by oracle providers
- Oracle feeds may require replacement due to accuracy issues or security vulnerabilities
- The lending protocol already has administrative capabilities (`OwnerCap`, `StorageAdminCap`) suggesting operational need for configuration updates
- The presence of numerous other setter functions demonstrates intended administrative flexibility for reserve parameters

The missing update function represents an operational blind spot rather than an intentional immutable design, as evidenced by the updateability of all other critical reserve parameters.

### Recommendation
Implement a `set_oracle_id` function following the established pattern of other reserve parameter setters:

```move
public fun set_oracle_id(
    _: &OwnerCap, 
    storage: &mut Storage, 
    asset: u8, 
    new_oracle_id: u8
) {
    version_verification(storage);
    let reserve = table::borrow_mut(&mut storage.reserves, asset);
    reserve.oracle_id = new_oracle_id;
}
```

Include appropriate validation to ensure the new `oracle_id` exists in the oracle system before updating, and emit an event for auditability.

### Proof of Concept
1. **Initial State**: A reserve is initialized with `oracle_id = 5` pointing to a specific price feed [8](#0-7) 

2. **Oracle System Change**: The oracle provider deprecates feed ID 5 and creates a new feed at ID 10 for the same asset

3. **Attempted Update**: Administrator attempts to update the reserve's oracle_id to 10, but no such function exists [2](#0-1) 

4. **Impact Realization**: All lending operations continue using oracle_id 5, which now returns stale/zero prices or reverts. Users cannot borrow, liquidations fail, and the reserve becomes effectively frozen

5. **Only Resolution**: Create a new reserve with oracle_id 10, requiring migration of all user positions, liquidity, and integration updates across the entire protocol stack

This operational scenario demonstrates a realistic denial-of-service condition through oracle configuration inflexibility, matching the external report's vulnerability class of initialization-only configuration without update mechanisms.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L154-194)
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
    ) {
        version_verification(storage);

        let current_idx = storage.reserves_count;
        assert!(current_idx < constants::max_number_of_reserves(), error::no_more_reserves_allowed());
        reserve_validation<CoinType>(storage);

        percentage_ray_validation(borrow_cap_ceiling);
        percentage_ray_validation(optimal_utilization);
        percentage_ray_validation(reserve_factor);
        percentage_ray_validation(treasury_factor);
        percentage_ray_validation(liquidation_ratio);
        percentage_ray_validation(liquidation_bonus);

        percentage_ray_validation(ltv);
        percentage_ray_validation(liquidation_threshold);
        
        let reserve_data = ReserveData {
            id: storage.reserves_count,
            oracle_id: oracle_id,
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L242-339)
```text
    public entry fun set_pause(_: &OwnerCap, storage: &mut Storage, val: bool) {
        version_verification(storage);

        storage.paused = val;
        emit(Paused {paused: val})
    }

    public fun set_supply_cap(_: &OwnerCap, storage: &mut Storage, asset: u8, supply_cap_ceiling: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.supply_cap_ceiling = supply_cap_ceiling;
    }

    public fun set_borrow_cap(_: &OwnerCap, storage: &mut Storage, asset: u8, borrow_cap_ceiling: u256) {
        version_verification(storage);
        percentage_ray_validation(borrow_cap_ceiling);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_cap_ceiling = borrow_cap_ceiling;
    }

    public fun set_ltv(_: &OwnerCap, storage: &mut Storage, asset: u8, ltv: u256) {
        version_verification(storage);
        percentage_ray_validation(ltv);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.ltv = ltv;
    }

    public fun set_treasury_factor(_: &OwnerCap, storage: &mut Storage, asset: u8, treasury_factor: u256) {
        version_verification(storage);
        percentage_ray_validation(treasury_factor);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.treasury_factor = treasury_factor
    }

    public fun set_base_rate(_: &OwnerCap, storage: &mut Storage, asset: u8, base_rate: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_rate_factors.base_rate = base_rate;
    }

    public fun set_multiplier(_: &OwnerCap, storage: &mut Storage, asset: u8, multiplier: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_rate_factors.multiplier = multiplier;
    }

    public fun set_jump_rate_multiplier(_: &OwnerCap, storage: &mut Storage, asset: u8, jump_rate_multiplier: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_rate_factors.jump_rate_multiplier = jump_rate_multiplier;
    }

    public fun set_reserve_factor(_: &OwnerCap, storage: &mut Storage, asset: u8, reserve_factor: u256) {
        version_verification(storage);
        percentage_ray_validation(reserve_factor);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_rate_factors.reserve_factor = reserve_factor;
    }

    public fun set_optimal_utilization(_: &OwnerCap, storage: &mut Storage, asset: u8, optimal_utilization: u256) {
        version_verification(storage);
        percentage_ray_validation(optimal_utilization);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_rate_factors.optimal_utilization = optimal_utilization;
    }

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-468)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L475-479)
```text
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L453-457)
```text
        let collateral_oracle_id = storage::get_oracle_id(storage, collateral_asset);
        let debt_oracle_id = storage::get_oracle_id(storage, debt_asset);

        let (_, collateral_price, _) = oracle::get_token_price(clock, oracle, collateral_oracle_id);
        let (_, debt_price, _) = oracle::get_token_price(clock, oracle, debt_oracle_id);
```
