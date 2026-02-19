### Title
Missing Admin Functions to Update Critical Reserve Oracle Configuration

### Summary
The lending protocol's `ReserveData` struct contains critical fields `oracle_id` and `is_isolated` that are set during reserve initialization but lack admin-gated setter functions to modify them post-deployment. This mirrors the external report's vulnerability class where the `is_listed` field controlling borrowing functionality cannot be changed after initialization. The inability to update `oracle_id` prevents admins from migrating or fixing oracle price feeds, which directly impacts liquidation calculations and could lead to protocol insolvency or unfair user liquidations.

### Finding Description
The external report describes a vulnerability where a critical boolean field (`is_listed`) controlling borrowing functionality is initialized to `true` but has no admin function to modify it. This same vulnerability class exists in Volo's lending protocol dependency.

In the lending core storage module, the `ReserveData` struct defines two fields without corresponding setter functions: [1](#0-0) 

The `oracle_id` field (line 45) and `is_isolated` field (line 47) are both initialized during reserve creation: [2](#0-1) 

The storage module provides admin-gated setter functions (requiring `OwnerCap`) for all other reserve configuration parameters including supply_cap, borrow_cap, ltv, treasury_factor, and all rate/liquidation factors: [3](#0-2) 

However, no setter functions exist for `oracle_id` or `is_isolated`. This is confirmed by the complete absence of `set_oracle_id` or `set_is_isolated` functions in the module.

The `oracle_id` field is critical because it's actively used in liquidation calculations to fetch prices: [4](#0-3) [5](#0-4) 

The lending protocol is actively integrated with Volo vault through the navi_adaptor: [6](#0-5) [7](#0-6) 

The adaptor relies on the storage module to calculate position values, which depend on correct oracle pricing via `oracle_id`.

### Impact Explanation
**Critical Impact on Protocol Solvency and User Funds:**

1. **Oracle Migration Failure**: When oracle contracts need upgrading, migrating to new price feeds, or fixing malfunctioning oracles, the protocol cannot update the `oracle_id` mapping. This forces continued use of potentially stale, incorrect, or compromised price feeds.

2. **Incorrect Liquidation Calculations**: Since `oracle_id` is used in `calculator::calculate_value()` and `calculator::calculate_amount()` functions during liquidations, wrong oracle mappings lead to:
   - Users liquidated with incorrect collateral/debt valuations
   - Under-collateralized positions protected from liquidation due to inflated prices
   - Protocol accumulating bad debt
   - Unfair liquidation bonuses calculated with wrong prices

3. **Irreversible Configuration**: The only remediation would be to create entirely new reserves and migrate all user positions—a highly disruptive process requiring user coordination and potentially locked funds during migration.

4. **Vault Operation Disruption**: The navi_adaptor calculates position values for vault operations using the storage module. Incorrect oracle_id values propagate to vault accounting, share ratio calculations, and loss tolerance checks.

### Likelihood Explanation
**High Likelihood of Operational Need:**

1. **Common Oracle Maintenance**: DeFi protocols regularly need to update oracle configurations due to:
   - Oracle contract upgrades (Switchboard, Pyth, etc.)
   - Price feed migrations to more reliable sources
   - Oracle provider changes or decommissioning
   - Response to oracle manipulation incidents

2. **Time-Critical Response**: Oracle malfunctions or compromises require immediate remediation. The inability to update `oracle_id` forces the protocol to either:
   - Continue operating with bad price data (risking insolvency)
   - Pause the entire lending pool (severe availability impact)
   - Deploy new reserves (major operational disruption)

3. **Demonstrated Usage Pattern**: The codebase shows the protocol already uses the lending storage module in production through the navi_adaptor integration, making this a real operational concern rather than theoretical.

4. **No Technical Barrier**: Unlike the `paused` field in `Storage` which has a setter function, or the vault `status` field which has `set_enabled()`, the `oracle_id` field lacks any modification path despite being equally critical for protocol operation.

### Recommendation
Add admin-gated setter functions to the lending_core storage module following the existing pattern used for other reserve parameters:

```move
public fun set_oracle_id(_: &OwnerCap, storage: &mut Storage, asset: u8, oracle_id: u8) {
    version_verification(storage);
    let reserve = table::borrow_mut(&mut storage.reserves, asset);
    reserve.oracle_id = oracle_id;
}

public fun set_is_isolated(_: &OwnerCap, storage: &mut Storage, asset: u8, is_isolated: bool) {
    version_verification(storage);
    let reserve = table::borrow_mut(&mut storage.reserves, asset);
    reserve.is_isolated = is_isolated;
}
```

These functions should:
- Require `OwnerCap` for authorization (same as other setters)
- Call `version_verification(storage)` before modification
- Emit events documenting the configuration change
- Consider adding validation to ensure the new oracle_id exists in the oracle module

### Proof of Concept
**Scenario: Oracle Price Feed Requires Update**

1. **Initial State**: Reserve 0 (SUI) is initialized with `oracle_id = 0` pointing to Switchboard feed A
   - Configured in init_reserve call during protocol deployment
   - All liquidations use this oracle_id to fetch SUI price

2. **Oracle Issue Occurs**: Switchboard feed A becomes unreliable or needs migration to feed B (oracle_id = 5)
   - Admin calls oracle module to add new feed with `oracle_id = 5`
   - Admin attempts to update reserve to use new oracle_id

3. **Configuration Failure**: No `set_oracle_id()` function exists
   - Admin checks storage.move lines 242-339 for setter functions
   - Only finds setters for: supply_cap, borrow_cap, ltv, treasury_factor, base_rate, multiplier, jump_rate_multiplier, reserve_factor, optimal_utilization, liquidation_ratio, liquidation_bonus, liquidation_threshold
   - `oracle_id` cannot be modified

4. **Impact Materialization**:
   - Liquidations continue using `storage::get_oracle_id(storage, 0)` which returns stale oracle_id = 0
   - `calculator::calculate_value()` in liquidation logic (line 542) uses wrong price feed
   - Users liquidated with incorrect SUI prices from feed A instead of correct feed B
   - Vault's `navi_adaptor::calculate_navi_position_value()` calculates wrong USD values
   - Protocol either accumulates bad debt (if feed A shows inflated prices) or unfairly liquidates users (if feed A shows deflated prices)

5. **Forced Remediation**: Admin must:
   - Deploy entirely new reserve with correct oracle_id
   - Coordinate migration of all user positions
   - Risk user fund lockup during migration period
   - Face potential governance/coordination failures

This demonstrates the concrete operational impact of missing the setter function, directly mirroring the external report's concern about inability to modify critical configuration fields post-initialization.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L43-67)
```text
    struct ReserveData has store {
        id: u8, // reserve index
        oracle_id: u8, // The id from navi oracle, update from admin
        coin_type: String, // The coin type, like 0x02::sui::SUI
        is_isolated: bool, // THe isolated of the reserve, update from admin
        supply_cap_ceiling: u256, // Total supply limit of reserve, update from admin
        borrow_cap_ceiling: u256, // Total borrow percentage of reserve, update from admin
        current_supply_rate: u256, // Current supply rates, update from protocol
        current_borrow_rate: u256, // Current borrow rates, update from protocol
        current_supply_index: u256, // The supply exchange rate, update from protocol
        current_borrow_index: u256, // The borrow exchange rate, update from protocol
        supply_balance: TokenBalance, // The total amount deposit inside the pool
        borrow_balance: TokenBalance, // The total amount borrow inside the pool
        last_update_timestamp: u64, // Last update time for reserve, update from protocol
        // Loan-to-value, used to define the maximum amount of assets that can be borrowed against a given collateral
        ltv: u256,
        treasury_factor: u256, // The fee ratio, update from admin
        treasury_balance: u256, // The fee balance, update from protocol
        borrow_rate_factors: BorrowRateFactors, // Basic Configuration, rate and multiplier etc.
        liquidation_factors: LiquidationFactors, // Liquidation configuration
        // Reserved fields, no use for now
        reserve_field_a: u256,
        reserve_field_b: u256,
        reserve_field_c: u256,
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L192-196)
```text
        let reserve_data = ReserveData {
            id: storage.reserves_count,
            oracle_id: oracle_id,
            coin_type: type_name::into_string(type_name::get<CoinType>()),
            is_isolated: is_isolated,
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L540-542)
```text
        let collateral_asset_oracle_id = storage::get_oracle_id(storage, collateral_asset);
        let debt_asset_oracle_id = storage::get_oracle_id(storage, debt_asset);
        let repay_value = calculator::calculate_value(clock, oracle, repay_amount, debt_asset_oracle_id);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L618-622)
```text
        let total_liquidable_amount_in_collateral = calculator::calculate_amount(clock, oracle, liquidable_value, collateral_asset_oracle_id);
        let total_liquidable_amount_in_debt = calculator::calculate_amount(clock, oracle, liquidable_value, debt_asset_oracle_id);
        let executor_bonus_amount_in_collateral = calculator::calculate_amount(clock, oracle, executor_bonus_value, collateral_asset_oracle_id);
        let treasury_amount_in_collateral = calculator::calculate_amount(clock, oracle, treasury_value, collateral_asset_oracle_id);
        let executor_excess_repayment_amount = calculator::calculate_amount(clock, oracle, excess_value, debt_asset_oracle_id);
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L3-5)
```text
use lending_core::account::AccountCap as NaviAccountCap;
use lending_core::dynamic_calculator;
use lending_core::storage::Storage;
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```
