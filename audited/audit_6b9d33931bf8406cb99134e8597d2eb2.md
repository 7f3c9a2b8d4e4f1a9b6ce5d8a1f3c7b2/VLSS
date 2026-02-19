# Audit Report

## Title
Frozen Operator Can Bypass Freeze Mechanism to Retrieve Deposit/Withdraw Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator` function in manage.move accepts an `OperatorCap` but fails to verify if the operator is frozen before allowing fee retrieval. This completely bypasses the operator freeze security mechanism, allowing frozen operators to continue extracting accumulated deposit and withdraw fees from the vault even after administrative freeze action.

## Finding Description

The vulnerability exists in the `retrieve_deposit_withdraw_fee_operator` function which does not include the `Operation` object as a parameter, making it impossible to perform the freeze status check. [1](#0-0) 

The freeze mechanism relies on checking the `freezed_operators` table stored in the `Operation` shared object. [2](#0-1) 

All legitimate operator functions perform this check via `assert_operator_not_freezed` which requires both the `Operation` object and the `OperatorCap`. [3](#0-2) 

Examples of proper freeze checking in other operator functions include:
- Operation start [4](#0-3) 
- Operation end [5](#0-4) 
- Execute deposit [6](#0-5) 
- Execute withdraw [7](#0-6) 

The internal function only checks version and vault status, not operator freeze status. [8](#0-7) 

## Impact Explanation

**Security Integrity Impact:** The operator freeze mechanism is a critical security control for authorization. This vulnerability allows complete bypass of this invariant, undermining the protocol's ability to respond to security incidents.

**Direct Fund Impact:** Frozen operators can extract all accumulated deposit/withdraw fees from the vault. These fees represent real user funds collected during deposit and withdrawal operations as evidenced by the fee balance storage. [9](#0-8) 

**Who is Affected:**
- Protocol governance loses control over frozen operators
- Vault users' accumulated fees can be drained by malicious/compromised operators even after freeze
- The admin's ability to respond to security incidents is completely undermined

This is CRITICAL because it:
1. Completely bypasses a core security mechanism
2. Allows direct extraction of user funds (fees)
3. Undermines incident response capabilities
4. Requires no additional privilege escalation beyond existing OperatorCap

## Likelihood Explanation

**Attacker Capabilities:** Requires only possession of an `OperatorCap` - a realistic scenario for any operator (legitimate or compromised).

**Attack Complexity:** Trivial - single function call with no complex preconditions.

**Feasibility Conditions:**
- Vault must be in NORMAL status (typical operational state per internal check) [10](#0-9) 
- Fees must have accumulated in the vault (expected during normal operations)
- No other preconditions required

**Detection/Operational Constraints:** 
The scenario where admin freezes an operator (likely due to suspicious activity or compromise) is the exact situation where this vulnerability becomes exploitable. Tests confirm frozen operators should fail operations with `ERR_OPERATOR_FREEZED`. [11](#0-10) 

**Probability:** HIGH - Once an operator is frozen (a defensive action), that operator can immediately exploit this to extract fees before further action can be taken.

## Recommendation

Add the `Operation` parameter to `retrieve_deposit_withdraw_fee_operator` and check operator freeze status before allowing fee retrieval:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // Add this parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add this check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This aligns the function with all other operator functions in the codebase that properly enforce the freeze mechanism.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and accumulate fees
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Accumulate some fees through deposits
    // ... deposit operations that generate fees ...
    
    // Admin freezes the operator
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
    };
    
    // Frozen operator attempts to retrieve fees - SHOULD FAIL but DOESN'T
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This succeeds when it should fail with ERR_OPERATOR_FREEZED
        let fee = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1_000_000,
        );
        
        fee.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L105-105)
```text
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

**File:** volo-vault/sources/operation.move (L105-105)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L218-218)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L391-391)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/tests/operation/operation.test.move (L1562-1562)
```text
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
```
