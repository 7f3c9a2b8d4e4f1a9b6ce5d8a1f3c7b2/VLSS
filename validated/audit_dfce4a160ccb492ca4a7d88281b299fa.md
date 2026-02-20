# Audit Report

## Title
Vault Denial of Service via Incomplete Operation Flow - No Admin Recovery Path

## Summary
The Volo Vault can become permanently stuck in `VAULT_DURING_OPERATION_STATUS` if an operator starts an operation but fails to complete the operation lifecycle. Once stuck, users cannot deposit or withdraw, and administrators have no function to force-reset the vault status back to normal, resulting in a complete protocol DoS with funds locked.

## Finding Description
The Volo vault operation flow requires a complete three-step lifecycle to maintain protocol functionality. The vulnerability occurs when this lifecycle is interrupted without a recovery mechanism.

**Normal Operation Flow:**
1. Operator calls `start_op_with_bag()` which invokes `pre_vault_check()` [1](#0-0) 

2. The `pre_vault_check()` function transitions vault status to `VAULT_DURING_OPERATION_STATUS` [2](#0-1) 

3. The operation must be completed by calling `end_op_value_update_with_bag()` which resets status back to `VAULT_NORMAL_STATUS` [3](#0-2) 

**The Vulnerability:**
If step 3 never executes (due to operator error, network failure, lost keys, or malicious intent), the vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`.

**Why Recovery is Impossible:**
The admin's `set_enabled()` function, which is the intended mechanism for administrative control, explicitly blocks operations when the vault is in `VAULT_DURING_OPERATION_STATUS` [4](#0-3) 

This creates an unrecoverable state because all user operations require `VAULT_NORMAL_STATUS`:
- Deposits are blocked via `assert_normal()` check [5](#0-4) 
- Withdrawals are blocked via `assert_normal()` check [6](#0-5) 
- The `assert_normal()` function requires status to equal `VAULT_NORMAL_STATUS` [7](#0-6) 

**Attack Path:**
1. Operator with valid `OperatorCap` calls `start_op_with_bag()` [8](#0-7) 
2. Vault status transitions to `VAULT_DURING_OPERATION_STATUS`
3. Operator fails to complete operation (software bug, transaction failure, lost keys, or intentional DoS)
4. Vault permanently stuck - users cannot deposit/withdraw
5. Admin cannot recover - `set_enabled()` blocks when vault is during operation
6. Only recovery path is `end_op_value_update_with_bag()` which requires the same operator capability

## Impact Explanation
**HIGH Severity** - This vulnerability results in complete protocol Denial of Service with the following impacts:

1. **Fund Accessibility**: All existing vault funds become inaccessible to users. Users cannot withdraw their deposited principal despite owning valid receipts.

2. **Protocol Functionality**: All core user functions (`request_deposit()` and `request_withdraw()`) become permanently unavailable for that vault instance.

3. **No Recovery Mechanism**: The protocol design includes no administrative override or emergency recovery function. The admin's `set_enabled()` function that should provide such capability explicitly prevents execution during operation status.

4. **Permanent State**: Unlike temporary DoS conditions, this creates a permanent stuck state that cannot be resolved without protocol upgrade or migration to new vault contracts.

5. **Multi-User Impact**: A single operator action (or inaction) affects all vault users simultaneously, making this a systemic risk rather than an isolated user issue.

## Likelihood Explanation
**MEDIUM-HIGH Likelihood** - This vulnerability is realistically exploitable through multiple scenarios:

1. **Low Barrier to Trigger**: Any operator with valid `OperatorCap` can trigger this condition - no key compromise or elevated privileges required beyond normal operator duties.

2. **Multiple Realistic Scenarios**:
   - Operator software bugs during multi-step transaction execution
   - Network failures or transaction timeouts between operation start and completion
   - Operator key loss or unavailability
   - Malicious operator intentionally causing DoS
   - Contract upgrade issues affecting operation flow

3. **No Preventive Controls**: The protocol includes no safeguards against incomplete operations such as timeouts, automatic resets, or admin overrides.

4. **Valid Protocol Operations**: All steps use legitimate protocol functions with proper authorization - there are no abnormal or suspicious patterns that would trigger alerts or blocks.

5. **Production Risk**: In production environments with complex operation workflows and external integrations (Navi, Cetus, Suilend, Momentum), transaction failures between multi-step operations are not uncommon.

## Recommendation
Implement an administrative emergency recovery function that allows admins to force-reset vault status from `VAULT_DURING_OPERATION_STATUS` back to `VAULT_NORMAL_STATUS`. This should include:

1. **Emergency Status Reset Function**:
```move
public(package) fun emergency_reset_status<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    _cap: &AdminCap,
) {
    self.check_version();
    // Allow admin to force reset from DURING_OPERATION to NORMAL
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.set_status(VAULT_NORMAL_STATUS);
        self.clear_op_value_update_record();
    }
}
```

2. **Add to manage.move**:
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    admin_cap: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.emergency_reset_status(admin_cap);
}
```

3. **Additional Safety Measures** (optional but recommended):
   - Add a timelock/delay before emergency reset can be executed
   - Emit clear event logging for emergency actions
   - Implement operation timeout mechanism that auto-recovers after X hours
   - Add operator health checks before allowing operations to start

## Proof of Concept
```move
#[test]
fun test_vault_stuck_in_operation_status_dos() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault and operator
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(ADMIN);
    let admin_cap = scenario.take_from_sender<AdminCap>();
    let operator_cap = vault_manage::create_operator_cap(&admin_cap, scenario.ctx());
    
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let operation = scenario.take_shared<Operation>();
        
        // Step 1: Operator starts operation - vault status becomes DURING_OPERATION
        let (assets, tx_bag, tx_check_bag, principal, coin_asset) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, u64>(
                &mut vault,
                &operation,
                &operator_cap,
                &clock,
                vector::empty(),
                vector::empty(),
                0,
                0,
                scenario.ctx()
            );
        
        // Step 2: Operator fails to complete operation (simulating bug/failure)
        // end_op_with_bag() and end_op_value_update_with_bag() are never called
        
        // Clean up returned values (in real scenario they'd be lost/stuck)
        assets.destroy_empty();
        principal.destroy_zero();
        coin_asset.destroy_zero();
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };
    
    scenario.next_tx(USER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = scenario.take_shared<RewardManager<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1000, scenario.ctx());
        
        // Step 3: User tries to deposit - FAILS with ERR_VAULT_NOT_NORMAL
        // This will abort because vault.assert_normal() fails
        let (request_id, receipt, remaining) = user_entry::deposit(
            &mut vault,
            &mut reward_manager,
            coin,
            1000,
            0,
            option::none(),
            &clock,
            scenario.ctx()
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        
        // Step 4: Admin tries to recover via set_enabled() - FAILS with ERR_VAULT_DURING_OPERATION
        // This will abort because of the explicit check in set_enabled()
        vault_manage::set_vault_enabled(&admin_cap, &mut vault, true);
        
        test_scenario::return_shared(vault);
    };
    
    // Result: Vault permanently stuck, no recovery possible
    test_scenario::return_to_sender(&scenario, admin_cap);
    test_scenario::return_to_sender(&scenario, operator_cap);
    clock.destroy_for_testing();
    scenario.end();
}
```

**Notes:**
- This vulnerability represents a critical design flaw where the operation lifecycle lacks failure recovery mechanisms
- The only way to set status back to `VAULT_NORMAL_STATUS` is through `end_op_value_update_with_bag()` which requires operator capability, creating a single point of failure
- Search results confirm there are only two locations that set status to NORMAL, and one is explicitly blocked during operations
- The issue affects vault availability and user fund accessibility, not fund safety per se, but constitutes HIGH severity due to complete protocol DoS

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

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```
