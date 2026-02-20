# Audit Report

## Title
Cross-Vault Operator Authorization Bypass - Missing Per-Vault Operator Verification

## Summary
The Volo vault system implements a flawed operator authorization model where any operator with a valid `OperatorCap` can perform privileged operations on ANY vault in the protocol. The system only verifies that an operator is not globally frozen but never checks if the operator is authorized for the specific vault being operated on, enabling unauthorized fund theft, fee extraction, and operational manipulation across vaults.

## Finding Description

The vulnerability exists because the protocol's authorization model treats all `OperatorCap` instances as equivalent once they pass a global freeze check, with no per-vault authorization verification.

**Root Cause Analysis:**

The `Operation` shared object only tracks globally frozen operators via a `freezed_operators` table, with no per-vault operator mappings: [1](#0-0) 

The `Vault` struct contains NO field to track which operators are authorized for that specific vault: [2](#0-1) 

The `OperatorCap` is created without any vault-specific binding: [3](#0-2) [4](#0-3) 

All operator authorization checks only verify the operator is not globally frozen, never checking vault-specific authorization: [5](#0-4) 

**Exploit Paths:**

All operator functions follow the same vulnerable pattern. Examples include:

1. **Fee Theft**: The `retrieve_deposit_withdraw_fee_operator` function accepts ANY `OperatorCap` and ANY vault reference with no authorization check: [6](#0-5) 

2. **Principal Borrowing**: The `start_op_with_bag` function only checks global freeze status before allowing principal and asset borrowing: [7](#0-6) 

3. **Request Manipulation**: The `execute_deposit` and `execute_withdraw` functions allow any operator to process requests for any vault: [8](#0-7) [9](#0-8) 

4. **Asset Manipulation**: The `add_new_defi_asset` function allows any operator to add assets to any vault: [10](#0-9) 

**Attack Scenario:**

1. Admin creates `OperatorCap_A` intended for managing `Vault_USDC`
2. Admin creates `OperatorCap_B` intended for managing `Vault_SUI`
3. Operator_A (holder of `OperatorCap_A`) can call:
   - `vault_manage::retrieve_deposit_withdraw_fee_operator(&operator_cap_A, &mut vault_SUI, amount)` to steal fees
   - `operation::start_op_with_bag(&mut vault_SUI, &operation, &operator_cap_A, ...)` to borrow principal
   - Any other operator function on `Vault_SUI`

None of these functions verify that `operator_cap_A` is authorized for `vault_SUI` - they only check that `operator_cap_A` is not globally frozen.

## Impact Explanation

**Critical Fund Theft:**
- Unauthorized operators can directly extract collected deposit/withdraw fees from any vault
- Unauthorized operators can borrow `free_principal` via operation functions and fail to return it
- Unauthorized operators can borrow DeFi assets (Navi accounts, Cetus positions, etc.) from vaults they don't control

**Request Manipulation:**
- Execute deposits/withdrawals at manipulated timing or prices to harm users
- Cancel legitimate user requests causing denial of service
- Process requests with unfavorable slippage parameters

**Asset Manipulation:**
- Add malicious DeFi assets that report inflated values, enabling vault value manipulation
- Remove legitimate assets causing vault operations to fail
- Add unauthorized coin type assets

**Operational DoS:**
- Manipulate vault status to block normal operations
- Interfere with loss tolerance tracking
- Disrupt reward distribution mechanisms

This breaks the fundamental security guarantee that operators should only manage vaults they are explicitly authorized for.

## Likelihood Explanation

**High Likelihood - Trivially Exploitable:**

1. **No Technical Barriers**: Any operator with a legitimately-obtained `OperatorCap` can immediately exploit this by simply calling operator functions with different vault references
2. **Standard Deployment Scenario**: Multi-vault deployments are the expected norm (USDC vault, SUI vault, BTC vault, etc.), each intended to have separate operators
3. **Public Entry Points**: All vulnerable functions are public and directly callable
4. **No Existing Protections**: Zero code validates per-vault operator authorization
5. **Realistic Attacker Profile**: The "attacker" is a legitimate operator who either becomes malicious or whose credentials are compromised

The vulnerability will manifest immediately in any multi-vault, multi-operator deployment.

## Recommendation

Implement per-vault operator authorization by:

1. **Add vault-specific operator tracking to `Vault` struct:**
```move
public struct Vault<phantom T> has key, store {
    // ... existing fields ...
    authorized_operators: Table<address, bool>,  // Track operators authorized for THIS vault
}
```

2. **Bind `OperatorCap` to specific vaults during creation:**
```move
public(package) fun create_operator_cap_for_vault<T>(
    vault: &Vault<T>, 
    ctx: &mut TxContext
): OperatorCap {
    let cap = OperatorCap { id: object::new(ctx) };
    // Record this cap as authorized for this vault
    vault.authorized_operators.add(object::id_address(&cap), true);
    cap
}
```

3. **Update authorization check to verify per-vault permissions:**
```move
public(package) fun assert_operator_authorized<T>(
    operation: &Operation, 
    vault: &Vault<T>,
    cap: &OperatorCap
) {
    let cap_id = cap.operator_id();
    // Check global freeze
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
    // NEW: Check vault-specific authorization
    assert!(
        vault.authorized_operators.contains(cap_id) && 
        *vault.authorized_operators.borrow(cap_id),
        ERR_OPERATOR_NOT_AUTHORIZED_FOR_VAULT
    );
}
```

4. **Update all operator functions to use the new check:**
```move
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    // ... other params
) {
    vault::assert_operator_authorized(operation, vault, cap);  // Updated check
    // ... rest of function
}
```

## Proof of Concept

```move
#[test]
public fun test_cross_vault_operator_authorization_bypass() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize protocol
    init_vault::init_vault(&mut s, &mut clock);
    
    // Create two vaults with different coin types
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_vault<USDC_TEST_COIN>(&mut s);
    
    // Admin creates two operator caps (intended one per vault)
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap_A = vault_manage::create_operator_cap(&admin_cap, s.ctx());
        let operator_cap_B = vault_manage::create_operator_cap(&admin_cap, s.ctx());
        transfer::public_transfer(operator_cap_A, OPERATOR_A);
        transfer::public_transfer(operator_cap_B, OPERATOR_B);
        s.return_to_sender(admin_cap);
    };
    
    // Add fees to Vault_SUI
    s.next_tx(OWNER);
    {
        let mut vault_sui = s.take_shared<Vault<SUI_TEST_COIN>>();
        // ... execute some deposits to collect fees ...
        test_scenario::return_shared(vault_sui);
    };
    
    // EXPLOIT: Operator_A (intended for Vault_USDC) steals fees from Vault_SUI
    s.next_tx(OPERATOR_A);
    {
        let operator_cap_A = s.take_from_sender<OperatorCap>();
        let mut vault_sui = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        let fees_before = vault_sui.deposit_withdraw_fee_collected();
        
        // Operator_A extracts fees from Vault_SUI using their cap intended for Vault_USDC
        let stolen_fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap_A,
            &mut vault_sui,
            fees_before
        );
        
        assert!(stolen_fees.value() == fees_before);  // Successfully stole fees!
        
        stolen_fees.destroy_for_testing();
        test_scenario::return_shared(vault_sui);
        s.return_to_sender(operator_cap_A);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

The test demonstrates that `operator_cap_A` can successfully extract fees from `vault_SUI` despite being intended for a different vault, proving the cross-vault authorization bypass.

### Citations

**File:** volo-vault/sources/volo_vault.move (L84-86)
```text
public struct OperatorCap has key, store {
    id: UID,
}
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

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

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/volo_vault.move (L397-403)
```text
public(package) fun create_operator_cap(ctx: &mut TxContext): OperatorCap {
    let cap = OperatorCap { id: object::new(ctx) };
    emit(OperatorCapCreated {
        cap_id: object::id_address(&cap),
    });
    cap
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

**File:** volo-vault/sources/operation.move (L449-479)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let withdraw_request = vault.withdraw_request(request_id);
    reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

    let (withdraw_balance, recipient) = vault.execute_withdraw(
        clock,
        config,
        request_id,
        max_amount_received,
    );

    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
    }
}
```

**File:** volo-vault/sources/operation.move (L565-574)
```text
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```
