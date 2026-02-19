### Title
Permanent Vault DoS via Invalid Receipt Leading to Irrecoverable DURING_OPERATION Status Lock

### Summary
When `get_receipt_value()` is called with a Receipt whose `receipt_id` doesn't exist in the vault's receipts table, the function aborts at line 51 during `vault_receipt_info()` call. If this occurs during the operation value update phase, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism, causing complete DoS and fund lockup. [1](#0-0) 

### Finding Description

**Root Cause:**
The `get_receipt_value()` function calls `vault.vault_receipt_info(receipt.receipt_id())` without checking whether the receipt_id exists in the vault's receipts table. [2](#0-1) 

The `vault_receipt_info()` implementation uses `self.receipts.borrow(receipt_id)`, which aborts if the key doesn't exist per Sui Move Table semantics. [3](#0-2) 

**Insufficient Protection:**
The only validation before accessing `vault_receipt_info()` is `assert_vault_receipt_matched()` at line 47, which only checks that the vault_id matches, NOT that the receipt_id exists in the receipts table. [4](#0-3) 

**Attack Vector:**
Operators can add Receipt objects as DeFi assets without validation. The `add_new_defi_asset()` function accepts any Receipt object without verifying the receipt_id exists in the corresponding vault's receipts table. [5](#0-4) 

**Execution Path:**
1. Operator adds invalid Receipt to vault A via `add_new_defi_asset()` (Receipt has valid vault_id for vault B, but receipt_id doesn't exist in vault B's receipts table)
2. Operator initiates operation on vault A - status changes to `VAULT_DURING_OPERATION_STATUS`
3. After `end_op_with_bag()`, operator calls `update_receipt_value()` to update receipt asset value
4. Transaction aborts at line 51 when `vault_receipt_info()` attempts to borrow non-existent receipt_id
5. Cannot proceed to `end_op_value_update_with_bag()` to restore vault to normal status
6. Vault A permanently stuck in `VAULT_DURING_OPERATION_STATUS` [6](#0-5) 

### Impact Explanation

**Permanent Vault DoS:**
Once the vault enters `VAULT_DURING_OPERATION_STATUS`, it cannot return to `VAULT_NORMAL_STATUS` because the operation cannot complete. All user operations are blocked:
- Deposits require `assert_normal()` [7](#0-6) 
- Withdrawals check vault status
- No new operations can start

**No Recovery Mechanism:**
Even AdminCap cannot reset the vault status. The `set_vault_enabled()` function explicitly aborts when vault is in `VAULT_DURING_OPERATION_STATUS`. [8](#0-7) 

The `remove_defi_asset_support()` function that could remove the invalid Receipt requires vault to be in normal status, creating a deadlock. [9](#0-8) 

**Fund Lockup:**
All funds in the vault become permanently inaccessible. Users cannot withdraw, operators cannot execute operations, and the vault cannot be disabled or recovered.

### Likelihood Explanation

**Operator Mistake (Not Malicious):**
This scenario requires an operator to accidentally add an invalid Receipt object. This is realistic because:
- Receipts have `store` ability and can be freely transferred [10](#0-9) 
- No validation exists in `add_new_defi_asset()` to verify receipt validity
- Operator might receive a Receipt created for testing/development that was never properly registered
- Receipt could be from a vault that was reset or migrated

**No Validation Gap:**
There is NO function to validate whether a receipt_id exists before adding it as a DeFi asset. The codebase provides `contains_vault_receipt_info()` but it's never called during receipt asset addition. [11](#0-10) 

**Realistic Operational Flow:**
Operators routinely add DeFi assets during vault composition strategies. The lack of validation makes it easy to accidentally add an improperly initialized Receipt.

### Recommendation

**Add Receipt Validation:**
Implement validation in `get_receipt_value()` or `update_receipt_value()` to check receipt existence before attempting to access it:

```move
public fun get_receipt_value<T>(
    vault: &Vault<T>,
    config: &OracleConfig,
    receipt: &Receipt,
    clock: &Clock,
): u256 {
    vault.assert_vault_receipt_matched(receipt);
    
    // ADD THIS CHECK:
    assert!(
        vault.contains_vault_receipt_info(receipt.receipt_id()),
        ERR_RECEIPT_NOT_FOUND
    );
    
    let share_ratio = vault.get_share_ratio(clock);
    let vault_receipt = vault.vault_receipt_info(receipt.receipt_id());
    // ... rest of function
}
```

**Add Validation at Asset Addition:**
Add validation in `add_new_defi_asset()` when adding Receipt types to verify the receipt_id exists in the corresponding vault:

```move
// For Receipt types, validate receipt_id exists in target vault
if (type_name::get<AssetType>() == type_name::get<Receipt>()) {
    // Validate receipt_id exists in the vault it references
}
```

**Add Emergency Recovery:**
Implement an emergency function that allows AdminCap to force-reset vault status with appropriate safeguards and event logging.

### Proof of Concept

**Initial State:**
- Vault A (USDC vault) exists with normal status
- Vault B (SUI vault) exists with receipts table
- Operator has OperatorCap for Vault A

**Attack Sequence:**

1. **Create Invalid Receipt:**
   - Create a Receipt object with vault_id pointing to Vault B
   - Receipt's receipt_id does NOT exist in Vault B's receipts table
   - (This could happen from test code, development artifacts, or improper initialization)

2. **Operator Adds Invalid Receipt:**
   ```move
   operation::add_new_defi_asset<USDC, Receipt>(
       &operation,
       &operator_cap,
       &mut vault_a,
       0, // idx
       invalid_receipt
   );
   ```
   - No validation occurs, invalid Receipt added successfully

3. **Start Operation:**
   ```move
   operation::start_op_with_bag(...)
   ```
   - Vault A status → `VAULT_DURING_OPERATION_STATUS`

4. **Return Assets:**
   ```move
   operation::end_op_with_bag(...)
   ```
   - Vault A remains in `VAULT_DURING_OPERATION_STATUS`

5. **Attempt Value Update:**
   ```move
   receipt_adaptor::update_receipt_value<USDC, SUI>(
       &mut vault_a,
       &vault_b,
       &config,
       &clock,
       receipt_asset_type
   );
   ```
   - **Transaction ABORTS** at `vault_receipt_info(receipt.receipt_id())`
   - Error: Table access to non-existent key

6. **Result:**
   - Vault A stuck in `VAULT_DURING_OPERATION_STATUS`
   - Cannot call `end_op_value_update_with_bag()` 
   - All user operations blocked forever
   - AdminCap cannot reset status
   - No recovery possible

**Expected:** Transaction should revert with clear error before vault enters unrecoverable state, or validation should prevent adding invalid Receipt.

**Actual:** Vault permanently locked, all funds inaccessible.

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

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L41-51)
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
```

**File:** volo-vault/sources/volo_vault.move (L520-531)
```text
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

**File:** volo-vault/sources/volo_vault.move (L668-673)
```text
public(package) fun assert_vault_receipt_matched<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    receipt: &Receipt,
) {
    assert!(self.vault_id() == receipt.vault_id(), ERR_VAULT_RECEIPT_NOT_MATCH);
}
```

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```

**File:** volo-vault/sources/volo_vault.move (L1390-1395)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1600-1605)
```text
public(package) fun contains_vault_receipt_info<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    receipt_id: address,
): bool {
    self.receipts.contains(receipt_id)
}
```

**File:** volo-vault/sources/volo_vault.move (L1613-1613)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1704-1710)
```text
public fun vault_receipt_info<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    receipt_id: address,
): &VaultReceiptInfo {
    let vault_receipt = self.receipts.borrow(receipt_id);
    vault_receipt
}
```

**File:** volo-vault/sources/receipt.move (L12-15)
```text
public struct Receipt has key, store {
    id: UID,
    vault_id: address, // This receipt belongs to which vault
}
```
