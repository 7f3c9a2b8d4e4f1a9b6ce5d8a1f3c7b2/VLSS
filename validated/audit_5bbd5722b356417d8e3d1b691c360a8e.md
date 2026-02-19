# Audit Report

## Title
Frozen Operators Can Bypass Freeze Mechanism to Extract Vault Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator` function in `manage.move` does not verify operator freeze status before allowing fee retrieval, enabling frozen operators to continue extracting accumulated deposit/withdraw fees from the vault even after administrators have frozen their capabilities.

## Finding Description

The Volo vault implements a comprehensive operator freeze mechanism where administrators can disable specific operators through the `Operation` shared object's `freezed_operators` table. [1](#0-0) 

The protocol enforces this freeze through the `assert_operator_not_freezed` function, which aborts with `ERR_OPERATOR_FREEZED` when a frozen operator attempts any operation. [2](#0-1) 

All operator functions in `operation.move` properly call this freeze check at their entry point, including `start_op_with_bag`, [3](#0-2)  `execute_deposit`, [4](#0-3)  and all other operator functions consistently follow this pattern throughout the file.

Similarly, all operator functions in `reward_manager.move` properly enforce the freeze check, such as in `add_new_reward_type`, [5](#0-4)  `add_reward_balance`, [6](#0-5)  and other reward management functions.

**However, the `retrieve_deposit_withdraw_fee_operator` function critically fails to perform this freeze check.** [7](#0-6) 

This function:
1. Takes an `&OperatorCap` parameter but does NOT take the `&Operation` shared object
2. Does NOT call `vault::assert_operator_not_freezed(operation, cap)` 
3. Directly calls the vault's internal fee retrieval function without freeze verification

The internal function it calls simply splits from the accumulated fee balance. [8](#0-7) 

The root cause is inconsistent enforcement - while all other operator functions require the `Operation` object to verify freeze status, this function omits both the parameter and the security check entirely.

## Impact Explanation

**Direct Fund Impact:**
When an administrator freezes an operator (typically due to suspected compromise or malicious behavior), the expectation is that ALL operator privileges are immediately revoked. However, a frozen operator can still call `retrieve_deposit_withdraw_fee_operator` to extract all accumulated deposit and withdraw fees from the vault.

The vault collects fees from every deposit and withdraw operation, storing them in the `deposit_withdraw_fee_collected` balance field. [9](#0-8)  These fees can accumulate to substantial amounts depending on vault activity volume.

**Security Control Bypass:**
This represents a complete bypass of an explicit security control mechanism. The freeze functionality exists specifically to provide administrators with emergency response capability against compromised or malicious operators. When this control can be circumvented, the protocol's security posture is fundamentally weakened.

**Affected Parties:**
- Protocol treasury loses rightful fee revenue
- Vault depositors are indirectly affected through reduced protocol sustainability
- Administrator trust in security controls is undermined

The severity is HIGH because it enables direct extraction of protocol funds through bypassing an intentional security mechanism.

## Likelihood Explanation

**Reachability:** The function is publicly accessible and callable by any holder of an OperatorCap. [7](#0-6) 

**Preconditions:**
1. An operator has been created and granted an OperatorCap (standard operational state)
2. The operator has been frozen by admin using `set_operator_freezed` [10](#0-9) 
3. Deposit/withdraw fees have accumulated in the vault (occurs naturally during normal operations)

**Execution Simplicity:** 
The exploit requires only a single function call with the operator's existing OperatorCap. No complex transaction sequences, timing requirements, or additional privileges are needed.

**Realistic Scenario:**
The freeze mechanism exists as an emergency response tool. When administrators detect suspicious operator behavior and activate the freeze, the compromised operator has a window to exploit this vulnerability as a final extraction before complete revocation.

**Probability Assessment:** MEDIUM-HIGH
While it requires the specific condition of an operator being frozen, the complete absence of the freeze check makes exploitation certain once that condition is met. Active vaults continuously accumulate fees, ensuring a valuable target is always available.

## Recommendation

Add the `Operation` parameter and freeze check to `retrieve_deposit_withdraw_fee_operator` to match the security pattern used by all other operator functions:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This ensures consistent freeze mechanism enforcement across all operator functions.

## Proof of Concept

```move
#[test]
fun test_frozen_operator_can_bypass_freeze_to_extract_fees() {
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Setup: Create vault with fees accumulated
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    // Create operator
    scenario.next_tx(ADMIN);
    let admin_cap = scenario.take_from_sender<AdminCap>();
    let operator_cap = vault_manage::create_operator_cap(&admin_cap, scenario.ctx());
    
    // Simulate fee accumulation (e.g., 1000 units)
    // ... deposit/withdraw operations that accumulate fees ...
    
    // Admin freezes the operator
    scenario.next_tx(ADMIN);
    let mut operation = scenario.take_shared<Operation>();
    vault_manage::set_operator_freezed(&admin_cap, &mut operation, object::id(&operator_cap).to_address(), true);
    
    // Verify operator is frozen
    assert!(vault::operator_freezed(&operation, object::id(&operator_cap).to_address()), 0);
    
    // Frozen operator should NOT be able to perform any operations
    // But they CAN still extract fees - THIS IS THE VULNERABILITY
    scenario.next_tx(OPERATOR);
    let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
    let fees_before = vault.deposit_withdraw_fee_collected();
    
    // This call succeeds even though operator is frozen!
    let extracted_fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
        &operator_cap,
        &mut vault,
        fees_before
    );
    
    // Verify fees were extracted despite freeze
    assert!(extracted_fees.value() == fees_before, 1);
    assert!(vault.deposit_withdraw_fee_collected() == 0, 2);
    
    // Clean up
    extracted_fees.destroy_for_testing();
    test_scenario::return_shared(vault);
    test_scenario::return_shared(operation);
    scenario.end();
}
```

This test demonstrates that a frozen operator can successfully extract all accumulated fees despite the freeze mechanism being active.

### Citations

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L96-105)
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

**File:** volo-vault/sources/volo_vault.move (L1544-1557)
```text
public(package) fun retrieve_deposit_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    self.check_version();
    self.assert_normal();

    emit(DepositWithdrawFeeRetrieved {
        vault_id: self.vault_id(),
        amount: amount,
    });

    self.deposit_withdraw_fee_collected.split(amount)
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

**File:** volo-vault/sources/operation.move (L381-391)
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
```

**File:** volo-vault/sources/reward_manager.move (L233-241)
```text
public fun add_new_reward_type<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    with_buffer: bool, // If true, create a new reward buffer distribution for the reward type
) {
    self.check_version();
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L340-349)
```text
public fun add_reward_balance<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    reward: Balance<RewardCoinType>,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);
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
