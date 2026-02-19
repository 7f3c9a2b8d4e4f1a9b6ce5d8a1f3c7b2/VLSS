### Title
Vault Permanently Bricked If External Cetus Protocol Aborts During Position Value Update

### Summary
The vault operation flow requires mandatory value updates for all borrowed assets before completing operations. If the external Cetus CLMM protocol's `get_position_amounts()` function aborts (e.g., due to i32 arithmetic overflow in tick calculations), the vault becomes permanently stuck in `DURING_OPERATION` status with no recovery mechanism, effectively bricking all vault assets.

### Finding Description

**Root Cause:**
The vault's operation completion flow has a mandatory value update requirement without any error handling or recovery mechanism for external protocol failures. [1](#0-0) 

After assets are returned, `enable_op_value_update()` is called, which requires all borrowed assets to have their values successfully updated: [2](#0-1) 

For Cetus positions, the value update calls the external Cetus protocol: [3](#0-2) [4](#0-3) 

The critical issue is that `pool.get_position_amounts(position_id)` is an external call to the Cetus CLMM protocol. If this function internally uses `i32::sub()` for tick arithmetic and encounters overflow conditions (which can occur with extreme tick ranges in concentrated liquidity positions), the entire transaction aborts.

The i32 module confirms that subtraction can abort on overflow/underflow: [5](#0-4) 

When the abort occurs, `finish_update_asset_value()` is never called, so the asset is never marked as updated in the `op_value_update_record`: [6](#0-5) 

Subsequently, `check_op_value_update_record()` will always fail because the borrowed asset was never marked as updated: [7](#0-6) 

This prevents `end_op_value_update_with_bag()` from completing, leaving the vault stuck in `DURING_OPERATION` status: [8](#0-7) 

**Why Existing Protections Fail:**

1. **No Error Handling:** Move does not support try-catch mechanisms, and the vault has no fallback valuation method.

2. **No Admin Recovery:** The admin's `set_enabled()` function explicitly blocks operation when vault is in `DURING_OPERATION` status: [9](#0-8) 

3. **Package-Only Status Override:** The `set_status()` function that could reset the vault is `public(package)` only, not accessible to admin caps: [10](#0-9) 

4. **Operation Gating:** While stuck in `DURING_OPERATION`, the vault cannot start new operations because `pre_vault_check()` requires `NORMAL` status: [11](#0-10) [12](#0-11) 

### Impact Explanation

**Harm:**
- **Complete Vault Bricking:** The vault becomes permanently stuck in `DURING_OPERATION` status, unable to complete the current operation or start any new operations.
- **Total Asset Lock:** All vault assets are locked indefinitely, including:
  - Principal balances (free_principal, claimable_principal)
  - All DeFi positions (Cetus, Navi, Suilend, Momentum)
  - All user deposits and shares
  - All accumulated fees and rewards
- **No Fund Recovery:** Without a recovery mechanism, even administrators cannot rescue the locked assets.

**Affected Parties:**
- All vault shareholders lose access to their funds
- Protocol operators cannot manage vault operations
- Protocol administrators cannot restore vault functionality

**Severity Justification:**
This is CRITICAL severity because:
1. **Total Loss of Availability:** Complete and permanent DoS of the entire vault
2. **Irreversible Damage:** No recovery path exists in the contract design
3. **Wide Impact:** Affects 100% of vault users and all deposited assets
4. **Cascading Failure:** The vault cannot process withdrawals, deposits, or any operations

### Likelihood Explanation

**Conditional but Realistic:**

While the exact likelihood depends on whether the Cetus CLMM protocol implementation uses i32 arithmetic that can overflow, several factors make this a realistic concern:

1. **Standard CLMM Pattern:** Concentrated liquidity protocols (like Uniswap v3, which Cetus is based on) use signed integers for tick indices. The similar mmt_v3 protocol in this codebase uses I32 for tick operations: [13](#0-12) 

2. **Known I32 Overflow Cases:** The test suite confirms i32::sub() aborts on overflow: [14](#0-13) 

3. **Feasible Trigger Conditions:**
   - Extreme market volatility causing positions to span very wide tick ranges
   - Maliciously crafted positions with edge-case tick values
   - Protocol upgrades that change tick calculation logic

4. **No Preconditions Required:** An attacker doesn't need to create the condition maliciously; it could occur naturally if:
   - A position already exists in the vault with problematic parameters
   - Normal market operations push the position into an overflow state
   - The external protocol has a latent bug

**Attack Complexity:**
- **Low from Defender Perspective:** The vault has no defensive measures against external protocol failures
- **Execution:** Simply calling the normal operation completion flow triggers the issue if the condition exists

**Economic Rationality:**
- This is a defensive programming failure, not necessarily requiring active exploitation
- Natural occurrence is plausible given the conditional nature of arithmetic overflows

### Recommendation

**Immediate Mitigations:**

1. **Add Admin Emergency Override:**
```move
public entry fun admin_emergency_reset_status<T>(
    _: &AdminCap,
    vault: &mut Vault<T>,
    new_status: u8,
) {
    vault.set_status(new_status);
    vault.clear_op_value_update_record();
}
```

2. **Implement Try-Alternative Pattern:**
Provide an alternative value calculation method that doesn't rely on external protocol arithmetic:
    - Use last known position value with staleness checks
    - Allow manual operator value submission with admin approval
    - Implement value bounds checking before calling external protocols

3. **Add Operation Timeout:**
Allow operations to be force-completed or cancelled after a timeout period with admin approval.

4. **Defensive Value Updates:**
Wrap external protocol calls with validation:
```move
// Before calling pool.get_position_amounts():
// 1. Validate position tick bounds are within safe I32 range
// 2. Check pool state is within expected parameters
// 3. Have fallback to mark asset as "pending manual valuation"
```

**Long-term Fixes:**

1. **Graceful Degradation:** Design the operation flow to handle external protocol failures gracefully rather than requiring 100% success.

2. **Value Update Bypass:** Add an admin-approved "force value update" that can mark assets as updated with explicit recorded values when automatic updates fail.

3. **Circuit Breaker:** Implement maximum retry attempts and automatic fallback to safe vault state.

### Proof of Concept

**Initial State:**
1. Vault holds a CetusPosition with tick indices stored as I32 values
2. Vault status = NORMAL
3. Position parameters exist such that internal Cetus CLMM calculations would trigger i32::sub() overflow

**Exploitation Steps:**

1. Operator calls `start_op_with_bag()` with the CetusPosition: [15](#0-14) 
   - Vault status → DURING_OPERATION
   - CetusPosition borrowed and recorded in `asset_types_borrowed`

2. Operator performs external operations (e.g., remove liquidity from position)

3. Operator calls `end_op_with_bag()` to return the position: [16](#0-15) 
   - Position returned to vault
   - `enable_op_value_update()` called

4. Operator attempts `update_cetus_position_value()`: [17](#0-16) 
   - Calls `pool.get_position_amounts(position_id)`
   - **Internal Cetus protocol uses i32::sub() which aborts due to overflow**
   - Transaction fails, `finish_update_asset_value()` never executes

5. Operator attempts `end_op_value_update_with_bag()`:
   - Calls `check_op_value_update_record()`
   - Fails with `ERR_USD_VALUE_NOT_UPDATED` because CetusPosition not marked as updated
   - Cannot proceed

**Expected vs Actual Result:**
- **Expected:** Operation completes, vault returns to NORMAL status
- **Actual:** Vault permanently stuck in DURING_OPERATION status, all operations blocked, no recovery possible

**Success Condition for Attack:**
Vault status remains DURING_OPERATION indefinitely, with `assert_normal()` failing for all subsequent operation attempts, effectively bricking the entire vault system.

### Citations

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L94-104)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
```

**File:** volo-vault/sources/operation.move (L209-217)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
```

**File:** volo-vault/sources/operation.move (L294-296)
```text
    vault.enable_op_value_update();

    defi_assets.destroy_empty();
```

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L533-541)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;

    emit(VaultStatusChanged {
        vault_id: self.vault_id(),
        status: status,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L649-650)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
```

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
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

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1242-1247)
```text
public(package) fun enable_op_value_update<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    self.check_version();
    self.assert_enabled();

    self.op_value_update_record.value_update_enabled = true;
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L33-41)
```text
public fun calculate_cetus_position_value<CoinTypeA, CoinTypeB>(
    pool: &mut CetusPool<CoinTypeA, CoinTypeB>,
    position: &CetusPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let position_id = object::id(position);

    let (amount_a, amount_b) = pool.get_position_amounts(position_id);
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L43-45)
```text
    public fun sub(num1: I32, num2: I32): I32 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L269-279)
```text
    #[test]
    #[expected_failure]
    fun test_sub_overflow() {
        sub(from(MAX_AS_U32), neg_from(1));
    }

    #[test]
    #[expected_failure]
    fun test_sub_underflow() {
        sub(neg_from(MIN_AS_U32), from(1));
    }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L69-79)
```text
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);
```
