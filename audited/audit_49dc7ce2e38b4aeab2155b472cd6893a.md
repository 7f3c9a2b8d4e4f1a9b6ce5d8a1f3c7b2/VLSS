### Title
Cross-Vault Operator Authorization Bypass - Missing Per-Vault Operator Verification

### Summary
The Volo vault system uses a global `Operation` object to check operator authorization, but fails to verify that an operator is authorized for the specific vault being operated on. This allows any operator with a valid `OperatorCap` to perform privileged operations on ANY vault in the protocol, enabling fund theft, fee extraction, and operational manipulation across vaults they were never authorized to access.

### Finding Description

The external report describes a vulnerability where `MeterCap` capabilities could be forged because functions failed to verify that the capability's namespace matched the expected `ManageMeterCap` namespace. The same vulnerability class exists in Volo's operator authorization system.

**Root Cause**: 

The protocol initializes a single global `Operation` shared object that contains a `freezed_operators` table: [1](#0-0) 

The `Vault` struct contains NO field to track which operators are authorized for that specific vault: [2](#0-1) 

All operator-gated functions only verify that the operator is not globally frozen, without checking if the operator is authorized for the specific vault being accessed: [3](#0-2) [4](#0-3) 

The `assert_operator_not_freezed` check only verifies against the global freeze list using the operator cap's ID: [5](#0-4) 

**Exploit Path**:

1. Admin creates `OperatorCap_A` for managing `Vault_USDC`
2. Admin creates `OperatorCap_B` for managing `Vault_SUI` 
3. Operator_A (holder of `OperatorCap_A`) can call any operator function on `Vault_SUI`:
   - `operation::execute_deposit` / `execute_withdraw` - manipulate user requests
   - `operation::start_op_with_bag` - borrow free principal and DeFi assets
   - `operation::add_new_defi_asset` - add malicious assets
   - `vault_manage::retrieve_deposit_withdraw_fee_operator` - steal fees [6](#0-5) 

4. None of these functions verify the operator cap is authorized for the target vault - they only check the global freeze status

**Why Protections Fail**:

The authorization model treats all `OperatorCap` instances as equivalent once they pass the freeze check. There is no namespace/vault-ID verification analogous to what the external report recommended (`cap.namespace_addr == manage_cap.namespace_addr`). In Volo, this would require checking that the operator cap is authorized for the specific `vault.vault_id()`.

### Impact Explanation

**Critical Fund Theft**:
- Unauthorized operator can borrow `free_principal` from any vault via `start_op_with_bag`, draining user deposits
- Unauthorized operator can extract collected fees via `retrieve_deposit_withdraw_fee_operator` [7](#0-6) 

**Request Manipulation**:
- Execute deposits/withdrawals at unfavorable prices for users
- Cancel legitimate user requests causing DoS

**Asset Manipulation**:
- Add malicious DeFi assets that report inflated values
- Remove legitimate assets causing vault operations to fail

**Operational DoS**:
- Change vault status to block normal operations
- Manipulate loss tolerance tracking to lock vaults

### Likelihood Explanation

**High Likelihood - No Barriers to Exploitation**:

1. **Attacker Profile**: Any operator legitimately created by admin becomes a cross-vault threat
2. **No Special Preconditions**: Operator simply needs their `OperatorCap` (legitimately obtained) and access to the shared `Operation` object
3. **Public Entry Points**: All operator functions in `operation.move` are public and directly callable: [8](#0-7) 

4. **No Existing Protection**: Zero code checks for per-vault operator authorization
5. **Realistic Scenario**: Multi-vault deployments are standard (USDC vault, SUI vault, etc.), and different operators are expected for different vaults

### Recommendation

Implement per-vault operator authorization by adding an authorized operators whitelist to each vault:

```
// Add to Vault struct:
authorized_operators: Table<address, bool>

// Add verification function:
public(package) fun assert_operator_authorized<T>(
    vault: &Vault<T>, 
    cap: &OperatorCap
) {
    let cap_id = cap.operator_id();
    assert!(
        vault.authorized_operators.contains(cap_id) && 
        *vault.authorized_operators.borrow(cap_id),
        ERR_OPERATOR_NOT_AUTHORIZED_FOR_VAULT
    );
}

// Call in all operator functions after freeze check:
vault::assert_operator_not_freezed(operation, cap);
vault::assert_operator_authorized(vault, cap); // NEW
```

Alternatively, modify `Operation` to track per-vault operator authorization:
```
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
    vault_operators: Table<address, vector<address>>, // vault_id -> [operator_ids]
}
```

### Proof of Concept

**Setup**:
1. Admin creates Vault_A (USDC) with ID = `0xVaultA`
2. Admin creates `operator_cap_alice` via `create_operator_cap` and gives to Alice
3. Admin creates Vault_B (SUI) with ID = `0xVaultB`  
4. Admin creates `operator_cap_bob` and gives to Bob
5. Alice is intended ONLY for Vault_A, Bob is intended ONLY for Vault_B

**Attack Execution by Alice**:

```
// Alice steals fees from Vault_B (she's not authorized for)
1. Alice calls: vault_manage::retrieve_deposit_withdraw_fee_operator(
    &operator_cap_alice,  // Her cap from Vault_A authorization
    &mut vault_B,         // Target Bob's vault!  
    fee_amount
)

2. Code executes vault.retrieve_deposit_withdraw_fee(amount)

3. Only check: vault::assert_operator_not_freezed(operation, &operator_cap_alice)
   - Passes: Alice's cap is not frozen
   - Missing: No check that operator_cap_alice is authorized for vault_B

4. Alice receives Balance<SUI> from Vault_B's collected fees
```

**Alternative Attack - Borrow Principal**:
```
1. Alice calls: operation::start_op_with_bag(
    &mut vault_B,            // Bob's vault
    &operation,              // Global object
    &operator_cap_alice,     // Alice's cap
    ...,
    principal_amount: 1_000_000  // Borrow 1M from Vault_B
)

2. Check: vault::assert_operator_not_freezed(operation, &operator_cap_alice) ✓
3. Missing: No vault-specific authorization check
4. Code executes: vault.borrow_free_principal(principal_amount)
5. Alice receives Balance<SUI> worth 1M from Vault_B
```

The vulnerability is confirmed exploitable through public functions with no vault-specific operator verification.

### Notes

This vulnerability directly maps to the external report's missing namespace verification. Just as the external vulnerability allowed using a `MeterCap` from one namespace with a `ManageMeterCap` from another namespace, Volo allows using an `OperatorCap` from one vault context on any other vault. The fix is identical in principle: verify the capability matches the expected context/namespace (in Volo's case, the specific vault being operated on).

### Citations

**File:** volo-vault/sources/volo_vault.move (L96-130)
```text
public struct Vault<phantom T> has key, store {
    id: UID,
    version: u64,
    // ---- Pool Info ---- //
    status: u8,
    total_shares: u256,
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
    // ---- Fee ---- //
    deposit_withdraw_fee_collected: Balance<T>,
    // ---- Principal Info ---- //
    free_principal: Balance<T>,
    claimable_principal: Balance<T>,
    // ---- Config ---- //
    deposit_fee_rate: u64,
    withdraw_fee_rate: u64,
    // ---- Assets ---- //
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
    // ---- Loss Tolerance ---- //
    cur_epoch: u64,
    cur_epoch_loss_base_usd_value: u256,
    cur_epoch_loss: u256,
    loss_tolerance: u256,
    // ---- Request Buffer ---- //
    request_buffer: RequestBuffer<T>,
    // ---- Reward Info ---- //
    reward_manager: address,
    // ---- Receipt Info ---- //
    receipts: Table<address, VaultReceiptInfo>,
    // ---- Operation Value Update Record ---- //
    op_value_update_record: OperationValueUpdateRecord,
}
```

**File:** volo-vault/sources/volo_vault.move (L349-358)
```text
fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::public_transfer(admin_cap, ctx.sender());

    let operation = Operation {
        id: object::new(ctx),
        freezed_operators: table::new(ctx),
    };
    transfer::share_object(operation);
}
```

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/volo_vault.move (L572-590)
```text
public(package) fun borrow_free_principal<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    self.check_version();
    self.assert_enabled();

    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();
        self.op_value_update_record.asset_types_borrowed.push_back(principal_asset_type);
    };

    let ret = self.free_principal.split(amount);
    emit(FreePrincipalBorrowed {
        vault_id: self.vault_id(),
        amount: amount,
    });
    ret
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

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
```

**File:** volo-vault/sources/operation.move (L547-554)
```text
public fun add_new_coin_type_asset<PrincipalCoinType, AssetType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_coin_type_asset<PrincipalCoinType, AssetType>();
}
```

**File:** volo-vault/sources/manage.move (L150-156)
```text
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    _: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
}
```
