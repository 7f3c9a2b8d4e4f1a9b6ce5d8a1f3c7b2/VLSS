### Title
Missing Storage Version Verification in Navi Position Valuation Allows Loss Tolerance Bypass

### Summary
The `calculate_navi_position_value()` function reads from Navi's Storage object without verifying its version, creating a risk window during Navi protocol upgrades where unmigrated or outdated Storage data could be interpreted as valid. This can result in incorrect USD position valuations that bypass the vault's loss tolerance checks, potentially leading to undetected fund losses.

### Finding Description

The vulnerability exists in the `calculate_navi_position_value()` function which directly reads from Navi's Storage object without performing version verification: [1](#0-0) 

The function calls multiple Storage getter methods including `get_reserves_count()`, `get_user_balance()`, and `get_coin_type()` without first validating that the Storage version is compatible with the current Navi protocol version.

In contrast, Navi's own protocol enforces version checking for write operations through the `version_verification()` function: [2](#0-1) 

This verification is consistently applied in Navi's write operations such as deposits and withdrawals: [3](#0-2) 

However, the Storage read functions (getters) do NOT perform version verification: [4](#0-3) [5](#0-4) [6](#0-5) 

The version checking mechanism compares the Storage's version field against the current module version: [7](#0-6) 

During a Navi protocol upgrade, the Storage object must be explicitly migrated. However, the migration function only updates the version number without performing actual data transformation: [8](#0-7) 

This creates a vulnerability window where:
1. Navi upgrades their protocol module to a new version
2. The Storage object remains with an old version number (or gets version updated without data migration)
3. Navi write operations fail due to version mismatch
4. Navi read operations succeed (no version check)
5. Volo's `calculate_navi_position_value()` reads potentially stale or incorrectly formatted data

### Impact Explanation

The incorrect position valuations directly impact the vault's loss tolerance mechanism. The calculated Navi position value is used in the operation completion flow: [9](#0-8) 

The loss tolerance check enforces that losses don't exceed the configured limit: [10](#0-9) 

**Concrete Harm Scenarios:**

1. **Overestimated Position Value**: If unmigrated Storage data causes the Navi position to be valued higher than actual, the `total_usd_value_after` is inflated. This makes losses appear smaller (or shows profit when there's actually loss), allowing the `update_tolerance()` check to pass when it should fail. The vault continues operations with hidden losses that could compound over time, resulting in actual fund losses for vault shareholders.

2. **Underestimated Position Value**: If the position is valued lower than actual, it triggers false loss detection, causing unnecessary operational blockage (DoS).

**Severity Justification**: HIGH - This vulnerability can bypass the critical loss_tolerance invariant designed to protect vault funds. During Navi upgrade windows, all vault operations involving Navi positions could use incorrect valuations, potentially allowing losses exceeding the tolerance threshold to go undetected and accumulate.

### Likelihood Explanation

**Feasible Preconditions**: 
The vulnerability activates during Navi protocol upgrades. Given that:
- Navi is a lending protocol that will require upgrades over its lifetime (security patches, feature additions, parameter adjustments)
- The Storage version mechanism exists specifically to handle upgrades
- Write operations enforcing version checks while read operations don't creates an asymmetric state

There will be operational windows where the Storage is either:
- Not yet migrated after module upgrade
- Has version number updated but data not fully migrated
- During this window, Navi write operations fail but read operations succeed

**Execution Practicality**: 
No special attacker capabilities required. During the vulnerability window:
1. Any user or operator calls vault operations involving Navi positions
2. The operation naturally calls `update_navi_position_value()`
3. This reads from unmigrated Storage and calculates incorrect values
4. The operation proceeds with wrong valuations

**Attack Complexity**: LOW - The vulnerability is triggered automatically during normal operations, no malicious action required.

**Detection Constraints**: The incorrect valuations may not be immediately apparent, as they would appear as normal market fluctuations until significant deviations accumulate.

**Probability**: MEDIUM-HIGH - While upgrade windows should be controlled, the combination of factors (no attacker required, automatic trigger during normal operations, realistic precondition) makes this a practical risk that will likely occur during Navi's operational lifetime.

### Recommendation

Add Storage version verification at the beginning of `calculate_navi_position_value()`:

```move
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    // Add this line
    storage::version_verification(storage);
    
    let mut i = storage.get_reserves_count();
    // ... rest of function
}
```

This will cause the function to abort with `error::incorrect_version()` if the Storage version doesn't match the current Navi module version, preventing Volo from operating on unmigrated data.

**Additional Recommendations**:
1. Consider adding a try-catch pattern or graceful fallback for version mismatches
2. Document the dependency on Navi protocol version compatibility
3. Add integration tests that simulate protocol upgrade scenarios
4. Implement monitoring to detect when Navi upgrades occur

**Test Cases to Prevent Regression**:
1. Test `calculate_navi_position_value()` with Storage at different version numbers
2. Verify it aborts when Storage version < current module version
3. Test the complete operation flow fails gracefully during version mismatch
4. Verify operations succeed after proper Storage migration

### Proof of Concept

**Initial State**:
1. Navi protocol is at version V1, Storage object has version = V1
2. Volo vault has Navi positions with known balances
3. Vault operations work correctly with accurate Navi valuations

**Exploit Sequence**:

1. **Navi Protocol Upgrade**:
   - Navi deploys upgraded module to version V2
   - Storage object still has version = V1 (not yet migrated)
   - Changes in V2 affect how reserve data should be interpreted (e.g., interest rate calculation changes, index formula modifications)

2. **Vulnerability Window Opens**:
   - Navi write operations (deposit/borrow) now fail with `error::incorrect_version()` 
   - Navi read operations (get_user_balance, etc.) still succeed without version check

3. **Volo Operation During Window**:
   - Operator initiates vault operation that borrows Navi AccountCap
   - During value update phase, calls `update_navi_position_value()`
   - Function calls `calculate_navi_position_value()` with unmigrated Storage
   - Storage getters return data in V1 format
   - Function interprets V1 data using potentially incompatible V2 semantics
   - Calculates incorrect USD value (e.g., 10% higher than actual due to old index values)

4. **Loss Tolerance Bypass**:
   - `end_op_value_update_with_bag()` compares `total_usd_value_before` with `total_usd_value_after`
   - The inflated Navi position value masks a real 8% loss
   - Loss appears as only 2% (within tolerance)
   - `update_tolerance()` check passes
   - Operation completes successfully despite actual loss exceeding tolerance

**Expected Result**: Operation should fail with version mismatch error or correctly detect loss exceeding tolerance.

**Actual Result**: Operation proceeds with incorrect valuations, bypassing loss protection.

**Success Condition**: The vulnerability is exploited when vault operations complete successfully during Navi upgrade windows despite having incorrect Navi position valuations that mask losses exceeding the configured tolerance threshold.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L184-186)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/version.move (L13-15)
```text
    public fun pre_check_version(v: u64) {
        assert!(v == constants::version(), error::incorrect_version())
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

**File:** volo-vault/sources/volo_vault.move (L626-640)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
```
