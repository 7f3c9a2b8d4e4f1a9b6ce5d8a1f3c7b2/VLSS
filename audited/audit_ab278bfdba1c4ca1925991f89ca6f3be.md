### Title
Missing USD Value Bounds Validation in Receipt Adaptor Allows Storing Unreasonable Asset Values

### Summary
The `finish_update_asset_value` function stores USD values without any bounds validation, allowing extremely large or small values to be recorded when `update_receipt_value` is called. If the oracle returns anomalous prices or cascading valuation issues occur between vaults, the stored asset value will distort the vault's total USD value and share ratio, leading to mispriced deposits and withdrawals that enable fund extraction.

### Finding Description

The vulnerability exists in the receipt value update flow across two functions: [1](#0-0) [2](#0-1) 

**Root Cause:**

The `finish_update_asset_value` function directly assigns the provided `usd_value` to the vault's asset value table without any validation: [3](#0-2) 

**Why Protections Fail:**

1. **No Bounds Checking**: The oracle price retrieval only validates freshness, not value bounds: [4](#0-3) 

2. **No Value Validation**: The receipt value calculation multiplies user positions by oracle prices without sanity checks: [5](#0-4) 

3. **Direct Storage**: The calculated value is stored directly without comparison to expected ranges or previous values: [3](#0-2) 

**Execution Path:**

1. Operator calls `update_receipt_value` during normal operation value update phase
2. `get_receipt_value` calculates USD value using oracle price: `pending_deposit_balance * oracle_price + claimable_principal * oracle_price + shares * share_ratio`
3. If oracle returns extreme price (e.g., 10^30 instead of 1), the multiplication produces enormous values
4. `finish_update_asset_value` stores this without validation
5. The inflated value affects `total_usd_value` calculation: [6](#0-5) 

6. This distorts the share ratio calculation for the entire vault: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**

When an unreasonable asset value is stored, the vault's share ratio becomes incorrect. This causes:

- **New Depositors**: Receive drastically fewer shares than deserved (overpaying per share)
- **Existing Withdrawers**: Receive drastically more principal than deserved (extracting excess funds)

For example, if a receipt asset's USD value is inflated 1000x:
- Vault's `total_usd_value` increases 1000x
- Share ratio increases 1000x  
- A user depositing $1000 receives shares worth only $1 at the inflated ratio
- A user withdrawing shares receives ~1000x more principal than they should

**Affected Parties:**

- All vault depositors (receive wrong share amounts)
- All vault withdrawers (receive wrong principal amounts)
- Vault solvency (gradual drainage through mispriced operations)

**Severity Justification:**

This is a **MEDIUM** severity issue because while the impact is severe (fund theft/loss), it requires an oracle failure or manipulation rather than being directly exploitable by untrusted users. However, oracle issues are realistic in DeFi, and the lack of defensive validation makes this a concrete risk.

### Likelihood Explanation

**Attacker Capabilities:**

This doesn't require an "attacker" in the traditional sense. The vulnerability is triggered when:
- An honest operator performs normal value update operations
- The oracle provides anomalous price data (bug, staleness, manipulation)
- OR cascading valuation issues exist between interconnected vaults

**Attack Complexity:**

LOW - The vulnerability triggers through normal operations:
1. Oracle returns extreme price value (outside expected bounds)
2. Operator calls `update_receipt_value` as part of routine value updates
3. System stores the unreasonable value without validation

**Feasibility Conditions:**

- Oracle compromised, buggy, or manipulated
- Switchboard aggregator returns extreme values
- No operator malice required - honest execution of procedures

**Detection/Operational Constraints:**

- Difficult to detect before impact occurs (no validation alerts)
- Once stored, incorrect values persist until next update
- Share ratio distortion affects all subsequent operations

**Probability Reasoning:**

MEDIUM probability because:
- Oracle failures/manipulation are known DeFi risks
- No bounds checking provides zero defense-in-depth
- System relies entirely on oracle correctness
- Historical precedent exists for oracle issues in production systems

### Recommendation

**Code-Level Mitigation:**

Add value validation in `finish_update_asset_value` before storing:

```move
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();
    
    // ADD: Validate reasonable bounds
    let old_value = *self.assets_value.borrow(asset_type);
    
    // Check for extreme changes (e.g., >10x or <0.1x)
    if (old_value > 0) {
        let max_change = old_value * 10; // 10x increase limit
        let min_change = old_value / 10; // 0.1x decrease limit
        assert!(usd_value <= max_change, ERR_USD_VALUE_TOO_HIGH);
        assert!(usd_value >= min_change, ERR_USD_VALUE_TOO_LOW);
    };
    
    // ADD: Validate absolute bounds based on asset type
    assert!(usd_value <= MAX_REASONABLE_ASSET_VALUE, ERR_USD_VALUE_EXCEEDS_MAX);
    
    // ... rest of function
}
```

**Invariant Checks:**

1. Define maximum reasonable asset value per asset type
2. Add percentage change limits between updates (e.g., max 10x change)
3. Add absolute bounds checking for USD values
4. Consider requiring admin approval for updates exceeding thresholds

**Test Cases:**

```move
#[test]
#[expected_failure(abort_code = ERR_USD_VALUE_TOO_HIGH)]
fun test_extreme_value_rejected() {
    // Setup vault with normal asset value
    // Attempt to update with 1000x inflated value
    // Verify transaction aborts
}

#[test]
fun test_reasonable_value_accepted() {
    // Setup vault with asset value = 1000
    // Update with value in range [100, 10000]
    // Verify update succeeds
}
```

### Proof of Concept

**Required Initial State:**
- Vault A with receipt asset from Vault B
- Vault B configured with oracle for principal coin type
- Operator has OperatorCap for operations

**Transaction Steps:**

1. **Setup**: Vault A holds receipt from Vault B with:
   - `pending_deposit_balance` = 1,000,000 (1M units of principal coin)
   - Normal oracle price = 1e18 (1 USD normalized)

2. **Oracle Failure**: Switchboard aggregator for Vault B's principal coin returns extreme value:
   - Instead of 1e18, returns 1e30 (trillion dollars per unit)
   - This could occur due to oracle bug, stale data, or manipulation

3. **Operator Action**: Honest operator calls during value update phase:
   ```
   receipt_adaptor::update_receipt_value<PrincipalA, PrincipalB>(
       vault_a,
       vault_b, 
       oracle_config,
       clock,
       receipt_asset_type
   )
   ```

4. **Value Calculation**: `get_receipt_value` computes:
   - `pending_deposit_value = 1,000,000 * 1e30 / 1e18 = 1e18` (trillion USD)
   - Returns this enormous value

5. **Storage Without Validation**: `finish_update_asset_value` stores `1e18` directly

**Expected Result**: 
Transaction should abort with "USD value exceeds reasonable bounds"

**Actual Result**: 
Transaction succeeds, storing the unreasonable value. Subsequent operations use distorted share ratio, enabling fund extraction through mispriced withdrawals.

**Success Condition**: 
User who previously had $1000 worth of shares can now withdraw $1,000,000+ worth of principal due to inflated share ratio.

### Citations

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-36)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
    receipt_vault.assert_normal();

    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);

    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L41-76)
```text
public fun get_receipt_value<T>(
    vault: &Vault<T>,
    config: &OracleConfig,
    receipt: &Receipt,
    clock: &Clock,
): u256 {
    vault.assert_vault_receipt_matched(receipt);

    let share_ratio = vault.get_share_ratio(clock);

    let vault_receipt = vault.vault_receipt_info(receipt.receipt_id());
    let mut shares = vault_receipt.shares();

    // If the status is PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS, the share value part is 0
    if (vault_receipt.status() == PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS) {
        shares = shares - vault_receipt.pending_withdraw_shares();
    };

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );

    vault_share_value + pending_deposit_value + claimable_principal_value
}
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

**File:** volo-vault/sources/volo_vault.move (L1287-1292)
```text
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
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
