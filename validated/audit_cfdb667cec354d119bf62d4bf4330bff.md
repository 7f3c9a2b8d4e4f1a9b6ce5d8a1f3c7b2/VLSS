### Title
Vault Denial of Service via Incomplete Multi-Step Operation with No Admin Recovery

### Summary
The Volo vault operation system executes rebalancing through a mandatory 3-step process across separate transactions. If an operator initiates an operation but fails to complete all steps, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`, preventing all user deposits, withdrawals, and future operations. Admin cannot forcibly reset the vault status due to an explicit check that blocks status changes during operations, resulting in permanent protocol denial of service.

### Finding Description

The external report identifies a race condition where an iterative process can be interrupted without proper locking or recovery. Volo exhibits the same vulnerability class in its vault operation workflow.

**Root Cause in Volo:**

The vault operation system requires a 3-step process to execute rebalancing operations: [1](#0-0) 

Step 1 transitions the vault from `VAULT_NORMAL_STATUS` (0) to `VAULT_DURING_OPERATION_STATUS` (1): [2](#0-1) 

Step 2 returns borrowed assets but maintains the DURING_OPERATION status: [3](#0-2) 

Step 3 verifies value updates and resets status back to NORMAL: [4](#0-3) [5](#0-4) 

**Why Protections Fail:**

If the operator completes Step 1 but abandons Steps 2-3, the vault remains stuck because:

1. User operations require NORMAL status and will fail: [6](#0-5) [7](#0-6) 

2. Admin cannot reset vault status during operations: [8](#0-7) 

3. No operator can retry - `start_op_with_bag` requires NORMAL status: [1](#0-0) 

4. No timeout mechanism or force-reset admin function exists: [9](#0-8) 

### Impact Explanation

**High Severity - Complete Protocol Denial of Service:**

Once the vault enters DURING_OPERATION status without completion:
- Users cannot submit deposit requests (blocked by `assert_normal()`)
- Users cannot submit withdrawal requests (blocked by `assert_normal()`)
- Users cannot execute pending deposits/withdrawals (blocked by `assert_normal()`)
- Operators cannot start new rebalancing operations (blocked by `assert_normal()`)
- Admin cannot recover the vault using `set_vault_enabled()` (blocked by DURING_OPERATION check)

All user funds remain locked in the vault with no access path. The vault requires protocol upgrade or identical operator to complete the abandoned operation. This breaks the critical invariant that operations must complete or be recoverable.

### Likelihood Explanation

**High Likelihood - Multiple Realistic Scenarios:**

1. **Operator Transaction Failure**: After calling `start_op_with_bag`, subsequent transactions may fail due to:
   - Gas exhaustion during complex DeFi interactions
   - Oracle price staleness causing value update failures
   - Slippage bounds violations in DEX operations
   - Network congestion or RPC failures

2. **Operator Error**: Bot/script bugs causing incomplete operation sequences

3. **Malicious Operator**: Compromised operator intentionally triggering DoS

4. **No Preconditions Required**: Only requires valid OperatorCap, which is a normal operational capability

The vulnerability is reachable through standard protocol operations without requiring privileged access beyond normal operator permissions.

### Recommendation

Add an admin emergency recovery function to forcibly reset vault status:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Force reset to NORMAL regardless of current status
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

Additionally, implement an operation timeout mechanism:
- Record timestamp when entering DURING_OPERATION status
- Allow admin to reset status if timeout exceeded (e.g., 1 hour)
- Or allow same operator to call an `abort_operation()` function that safely returns borrowed assets and resets status

### Proof of Concept

**Initial State:**
- Vault in NORMAL status with active deposits and user funds
- Operator has valid OperatorCap

**Attack Steps:**

1. Operator calls `operation::start_op_with_bag()` with valid parameters
   - Vault status transitions: NORMAL → DURING_OPERATION
   - Assets are borrowed from vault

2. Operator's next transaction fails (gas exhaustion / price staleness / network issue)
   - Or operator intentionally abandons operation
   - `end_op_with_bag()` is never called

3. User attempts deposit via `user_entry::deposit()`
   - Internally calls `vault.request_deposit()`
   - Fails at `self.assert_normal()` check with `ERR_VAULT_NOT_NORMAL`

4. User attempts withdrawal via `user_entry::withdraw()`
   - Internally calls `vault.request_withdraw()`  
   - Fails at `self.assert_normal()` check with `ERR_VAULT_NOT_NORMAL`

5. Admin attempts recovery via `vault_manage::set_vault_enabled(admin_cap, vault, false)`
   - Fails at `assert!(self.status() != VAULT_DURING_OPERATION_STATUS)` check with `ERR_VAULT_DURING_OPERATION`

6. Another operator attempts new operation via `operation::start_op_with_bag()`
   - Fails at `pre_vault_check()` → `vault.assert_normal()` check with `ERR_VAULT_NOT_NORMAL`

**Result:** Vault permanently frozen, all user funds inaccessible, protocol requires upgrade to recover.

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

**File:** volo-vault/sources/operation.move (L94-106)
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
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/operation.move (L209-219)
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
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
```

**File:** volo-vault/sources/operation.move (L299-308)
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

```

**File:** volo-vault/sources/operation.move (L375-376)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```

**File:** volo-vault/sources/volo_vault.move (L519-531)
```text
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

**File:** volo-vault/sources/volo_vault.move (L707-716)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L896-905)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}
```
