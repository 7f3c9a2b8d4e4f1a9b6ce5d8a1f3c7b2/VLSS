### Title
Insufficient Emergency Recovery Mechanism When All Operators Are Frozen

### Summary
When all operators are frozen via the `set_operator_freezed` function, the vault cannot execute pending deposit and withdrawal requests, effectively locking user funds. While admins can unfreeze operators or create new ones, there is no direct admin override to execute pending requests, creating a critical operational gap during security incidents where operators must be frozen.

### Finding Description

The operator freeze mechanism is implemented through the `Operation` shared object which maintains a `freezed_operators` table: [1](#0-0) 

Admins can freeze operators through the management interface: [2](#0-1) 

All critical vault operations verify that operators are not frozen before execution: [3](#0-2) [4](#0-3) 

**Root Cause:**
The system strictly segregates operator functions from admin functions. Users can submit and cancel requests, but only operators can execute them: [5](#0-4) [6](#0-5) 

When all operators are frozen, there is no admin function to directly execute pending requests. The only recovery paths are:
1. Unfreezing an existing operator
2. Creating a new OperatorCap

However, these require trusting new/unfrozen operators immediately after a security incident.

### Impact Explanation

**Operational Impact:**
- All pending deposit requests remain in the request buffer, unable to be executed
- All pending withdrawal requests cannot be processed, locking users' vault shares
- Users can continue submitting new requests but cannot have them fulfilled
- The vault effectively enters a frozen state until operators are restored

**User Impact:**
- Users with pending deposits have their funds locked in the vault's coin buffer but receive no shares
- Users with pending withdrawals cannot access their principal despite having submitted valid requests
- No timeline guarantee for when frozen operators will be restored

**Severity Justification:**
The vault's two-phase request/execute pattern creates a custody gap. During the frozen period, user funds are held but not accessible, and there's no admin emergency override to manually process legitimate user requests.

### Likelihood Explanation

**Preconditions:**
This scenario occurs when admins freeze all operators, which could happen in several realistic situations:
1. **Security Incident Response**: If operators are suspected of being compromised, admins may freeze all of them as a protective measure
2. **Operational Error**: Admin accidentally freezes all operators without maintaining at least one active operator
3. **Loss of Access**: All OperatorCap holders become unavailable (lost keys, infrastructure failure)

**Complexity:**
The vulnerability manifests through normal protocol operation - no special exploitation required. Once all operators are frozen through legitimate admin action, the vault automatically cannot process any execution requests.

**Feasibility:**
The freeze mechanism is designed as a safety feature, making it likely to be used during security incidents. The lack of a recovery mechanism means that in the exact scenario where maximum caution is needed (compromised operators), there's no way to service users without immediately trusting new operators.

**Note on Validation Criteria:**
This finding relates to system design resilience rather than attacker exploitation. While it requires admin action to trigger, it represents a gap in emergency procedures that affects user fund accessibility during legitimate security responses.

### Recommendation

Add an admin-controlled emergency execution function that allows direct processing of pending deposit/withdrawal requests when the vault is in a critical state:

1. **Implement Admin Emergency Override**: Create `admin_emergency_execute_deposit` and `admin_emergency_execute_withdraw` functions in `manage.move` that require `AdminCap` and can execute requests even when operators are frozen.

2. **Add Safety Guards**: Require additional verification for admin execution:
   - Add a configurable time delay (e.g., 24 hours after operators frozen)
   - Emit special events for audit trail
   - Limit batch sizes for admin execution

3. **Alternative: Multi-Admin Approval**: Implement a multi-signature requirement where multiple AdminCaps must approve emergency execution, preventing unilateral admin actions while maintaining recovery capability.

4. **Update Operation Status Logic**: Add a `VAULT_EMERGENCY_STATUS` that can be set by admin when all operators are frozen, allowing specific admin functions to bypass normal operator requirements.

### Proof of Concept

**Initial State:**
- Vault has active operators
- Users have submitted pending deposit and withdrawal requests
- Vault is functioning normally

**Exploitation Steps:**

1. **Security Incident Occurs**: Operators suspected of compromise
   
2. **Admin Freezes All Operators**: [2](#0-1) 

3. **Users Attempt to Execute Requests**: All execution attempts fail with `ERR_OPERATOR_FREEZED`: [7](#0-6) 

4. **Admin Attempts Recovery**: Admin has only two options:
   - Unfreeze an operator (reintroducing potential security risk)
   - Create new OperatorCap (requires immediate trust in new operator)

5. **Users Cannot Access Funds**: Pending requests remain indefinitely until operators are restored.

**Expected Result**: Admin should have emergency mechanism to execute requests without unfreezing operators.

**Actual Result**: No admin function exists to execute pending requests; vault remains frozen until operators are restored.

**Success Condition**: Vault enters frozen state where pending requests exist but cannot be executed by any available capability.

---

## Notes

While admins can unfreeze operators or create new OperatorCaps as recovery mechanisms, this creates a dilemma during security incidents: the very moment when operators should remain frozen is when users most need their requests processed. The absence of an admin emergency override function means the protocol must choose between user access and security hardening, rather than having a controlled escalation path that maintains both.

The test suite confirms the freeze mechanism works as designed: [8](#0-7) [9](#0-8) 

However, no test validates recovery procedures when all operators are frozen while pending requests exist.

### Citations

**File:** volo-vault/sources/volo_vault.move (L63-63)
```text
const ERR_OPERATOR_FREEZED: u64 = 5_015;
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
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

**File:** volo-vault/sources/manage.move (L88-95)
```text
public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
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

**File:** volo-vault/tests/operation/manage.test.move (L863-913)
```text
// [TEST-CASE: Should freeze/unfreeze operator cap.] @test-case MANAGE-005
public fun test_set_operator_cap_freezed_from_manage() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap = vault_manage::create_operator_cap(&admin_cap, s.ctx());

        transfer::public_transfer(operator_cap, OWNER);
        s.return_to_sender(admin_cap);
    };

    s.next_tx(OWNER);
    {
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        let admin_cap = s.take_from_sender<AdminCap>();

        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );

        assert!(vault::operator_freezed(&operation, operator_cap.operator_id()));

        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            false,
        );

        assert!(!vault::operator_freezed(&operation, operator_cap.operator_id()));

        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
        s.return_to_sender(admin_cap);
    };

    clock.destroy_for_testing();
    s.end();
}
```

**File:** volo-vault/tests/operation/operation.test.move (L1562-1603)
```text
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
public fun test_start_op_fail_op_freezed() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(
            0,
            navi_account_cap,
        );
        test_scenario::return_shared(vault);
    };

    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();

        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );

        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
    };
```
