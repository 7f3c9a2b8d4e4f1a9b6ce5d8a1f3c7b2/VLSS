# Audit Report

## Title
Missing Version Verification in Navi Adaptor Read Operations Allows Incompatible Position Valuation

## Summary
The Volo vault's Navi adaptor lacks version compatibility checks when reading critical financial data from Navi Protocol's lending_core Storage. While write operations enforce version verification, read operations used for position valuation do not, creating an asymmetric protection model that allows incorrect USD position values when Navi Protocol upgrades, potentially bypassing loss tolerance limits and corrupting share calculations.

## Finding Description

The vault's `update_navi_position_value` function reads user balances and calculates position values from Navi's lending_core Storage without version verification. [1](#0-0) 

This function calls `calculate_navi_position_value`, which invokes multiple Storage read functions that lack version checks:

- `get_user_balance()` [2](#0-1) 
- `get_reserves_count()` [3](#0-2) 
- `get_coin_type()` [4](#0-3) 
- `get_index()` [5](#0-4) 

Additionally, `dynamic_calculator::calculate_current_index` is called, which also lacks version verification. [6](#0-5) 

In stark contrast, write operations properly enforce version checks. For example, `base_borrow` calls `storage::version_verification(storage)` [7](#0-6)  and `base_repay` does the same. [8](#0-7) 

All friend (write) functions consistently call version verification. [9](#0-8) 

The Storage module provides `version_verification()` [10](#0-9)  and supports runtime version migration via `version_migrate()`. [11](#0-10) 

The current lending_core version is 13, demonstrating active version evolution. [12](#0-11) 

**Root Cause:** The vault assumes Storage read functions will always return data with consistent semantic interpretation, but version migrations can change data semantics (index calculations, balance scaling, rate formulas) without changing function signatures. Write operations abort on version mismatch, but reads do not, creating asymmetric protection that allows silent miscalculations.

**Attack Scenario:**
1. Vault has existing Navi positions from previous operations
2. Navi Protocol upgrades lending_core to a new version (e.g., v13 → v14) and calls `version_migrate()` on the shared Storage object
3. Vault operator runs an operation that interacts with a different protocol but must update values for ALL assets including the existing Navi position
4. Operator calls `update_navi_position_value` to refresh Navi position value
5. Read operations succeed without version verification, interpreting v14 Storage data with v13 assumptions
6. Wrong USD value is calculated and committed to vault's `assets_value` table via `finish_update_asset_value`. [13](#0-12) 
7. No Navi write operations occur in this transaction, so no version check abort
8. Wrong value persists in vault state

## Impact Explanation

When lending_core Storage semantics change after a version upgrade, the vault calculates incorrect USD values for Navi positions, directly corrupting the vault's financial accounting:

1. **Loss Tolerance Bypass**: The vault's loss tolerance check compares `total_usd_value_before` vs `total_usd_value_after`. [14](#0-13)  If Navi positions are underreported, actual losses appear smaller, bypassing the tolerance limit enforced by `update_tolerance()`. [15](#0-14) 

2. **Wrong Share Calculations**: The `get_share_ratio()` function uses `total_usd_value` to calculate share prices. [16](#0-15)  Incorrect total_usd_value leads to wrong share_ratio, affecting all deposit and withdrawal calculations. Users can extract more or less value than entitled.

3. **Fund Distribution Errors**: Since share calculations determine how many shares users receive on deposit and how much principal they get on withdrawal, wrong valuations directly cause fund distribution errors.

4. **Silent Failures**: Unlike write operations that abort on version mismatch, read operations silently proceed with wrong calculations. The vault has no mechanism to detect the incompatibility.

The vault's critical invariant of "total_usd_value correctness" is violated, stored in the vault's `assets_value` table. [17](#0-16) 

## Likelihood Explanation

**Medium-High Likelihood** due to:

1. **Frequent Protocol Upgrades**: Navi Protocol has gone through 13 versions, demonstrating active development and frequent upgrades.

2. **Multi-Protocol Operations**: Vaults commonly have positions across multiple protocols. Operators regularly run operations that interact with one protocol while updating values for all protocols - this is normal vault behavior.

3. **Automatic Trigger**: This manifests automatically during legitimate protocol operations after Navi upgrades. Honest vault operators following standard procedures will trigger it.

4. **No Detection Mechanism**: The vault has no way to detect version incompatibility in read operations.

5. **Sui's Package Model**: In Sui's shared object architecture, when Navi publishes new versions, the vault's local dependencies may point to old package addresses while the shared Storage object's version field is upgraded, creating the version mismatch scenario.

The combination of frequent upgrades, normal multi-protocol operations, and lack of defensive checks makes this realistic in production environments.

## Recommendation

Implement version verification for read operations used in financial calculations:

1. **Add Version Checks to Critical Read Paths**: Modify `calculate_navi_position_value` to verify Storage version before reading data, or create versioned wrapper functions that check compatibility.

2. **Pin Navi Package Versions**: Explicitly track and validate the expected Navi package version in vault configuration, requiring manual upgrade process with compatibility verification.

3. **Add Sanity Checks**: Implement bounds checking on calculated USD values, comparing against previous values to detect anomalous changes that could indicate semantic incompatibility.

4. **Graceful Degradation**: When version mismatch is detected, revert the transaction with a clear error rather than proceeding with potentially incorrect calculations.

## Proof of Concept

This vulnerability requires integration testing with Navi Protocol's version migration functionality. A proof of concept would:

1. Deploy vault with Navi positions at version 13
2. Simulate Navi Storage upgrade to version 14 with semantic changes (e.g., modified index calculation)
3. Call vault operation that triggers `update_navi_position_value`
4. Observe that wrong USD values are calculated and stored without error
5. Verify that loss tolerance checks or share calculations use corrupted values

The test would demonstrate that read operations proceed silently with incompatible data interpretation while write operations would abort, confirming the asymmetric protection model vulnerability.

### Citations

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L145-147)
```text
    public fun version_verification(storage: &Storage) {
        version::pre_check_version(storage.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L149-152)
```text
    public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
        assert!(storage.version < version::this_version(), error::not_available_version());
        storage.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L361-363)
```text
    public fun get_reserves_count(storage: &Storage): u8 {
        storage.reserves_count
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L378-380)
```text
    public fun get_coin_type(storage: &Storage, asset: u8): String {
        table::borrow(&storage.reserves, asset).coin_type
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L398-404)
```text
    public fun get_index(storage: &mut Storage, asset: u8): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        (
            reserve.current_supply_index,
            reserve.current_borrow_index
        )
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L414-427)
```text
    public fun get_user_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        let supply_balance = 0;
        let borrow_balance = 0;

        if (table::contains(&reserve.supply_balance.user_state, user)) {
            supply_balance = *table::borrow(&reserve.supply_balance.user_state, user)
        };
        if (table::contains(&reserve.borrow_balance.user_state, user)) {
            borrow_balance = *table::borrow(&reserve.borrow_balance.user_state, user)
        };

        (supply_balance, borrow_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L506-513)
```text
    public(friend) fun increase_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        let supply_balance = &mut reserve.supply_balance;

        increase_balance(supply_balance, user, amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/dynamic_calculator.move (L264-288)
```text
    public fun calculate_current_index(clock: &Clock, storage: &mut Storage, asset: u8): (u256, u256) {
        let current_timestamp = clock::timestamp_ms(clock);
        let last_update_timestamp = storage::get_last_update_timestamp(storage, asset);

        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);
        let (current_supply_rate, current_borrow_rate) = storage::get_current_rate(storage, asset);

        let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;

        // get new borrow index
        let compounded_interest = calculator::calculate_compounded_interest(
            timestamp_difference,
            current_borrow_rate
        );
        let new_borrow_index = ray_math::ray_mul(compounded_interest, current_borrow_index);

        // get new supply index
        let linear_interest = calculator::calculate_linear_interest(
            timestamp_difference,
            current_supply_rate
        );
        let new_supply_index = ray_math::ray_mul(linear_interest, current_supply_index);

        (new_supply_index, new_borrow_index)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L275-276)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L319-320)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L14-14)
```text
    public fun version(): u64 {13}
```

**File:** volo-vault/sources/volo_vault.move (L115-115)
```text
    assets_value: Table<String, u256>, // Assets value in USD
```

**File:** volo-vault/sources/volo_vault.move (L626-635)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L1174-1187)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
