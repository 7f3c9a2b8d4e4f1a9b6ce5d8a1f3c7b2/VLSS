### Title
Vault Permanent DoS via Incomplete Operation Flow - Status Never Reset to NORMAL

### Summary
The Volo Vault operation flow requires calling three separate public functions (`start_op_with_bag`, `end_op_with_bag`, `end_op_value_update_with_bag`) across potentially different transactions. If an operator completes the first two steps but fails to call the final `end_op_value_update_with_bag`, the vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all user deposits and withdrawals with no recovery mechanism. This maps to the external report's vulnerability class of "denial of service through valid calls where operation status is never reset."

### Finding Description

The vulnerability exists in the three-phase operation pattern implemented in the Volo Vault system:

**Phase 1 - Start Operation**: The `start_op_with_bag` function sets the vault status to `VAULT_DURING_OPERATION_STATUS` (value 1): [1](#0-0) 

**Phase 2 - End Operation**: The `end_op_with_bag` function returns borrowed DeFi assets but does NOT reset the vault status: [2](#0-1) 

**Phase 3 - Status Reset**: Only `end_op_value_update_with_bag` resets the vault status back to NORMAL at line 375: [3](#0-2) 

**Critical User Operations Blocked**: Both `execute_deposit` and `execute_withdraw` require the vault to be in NORMAL status via `assert_normal()`: [4](#0-3) [5](#0-4) 

**No Recovery Mechanism**: The admin's `set_enabled` function explicitly prevents status changes while vault is in DURING_OPERATION status: [6](#0-5) 

The `set_status` function is `public(package)` scoped, preventing direct admin intervention: [7](#0-6) 

### Impact Explanation

**High-Severity Protocol DoS**: Once the vault is stuck in `VAULT_DURING_OPERATION_STATUS`, all critical user operations permanently fail:

1. **Deposit Execution Blocked**: Users cannot execute pending deposit requests, leaving their deposited coins trapped in the request buffer
2. **Withdrawal Execution Blocked**: Users cannot execute pending withdrawal requests, unable to redeem their shares for principal
3. **No Admin Recovery**: The admin cannot use `set_vault_enabled` or any other function to manually reset the status due to the explicit check at line 523
4. **Permanent Lock**: The only way to reset status is through `end_op_value_update_with_bag`, which requires OperatorCap - if the operator refuses or is unable to complete the flow, funds are permanently locked

This represents a complete loss of vault availability and effective loss of user fund access.

### Likelihood Explanation

**High Likelihood - Realistic Operator Error or Attack**:

1. **Separate Transaction Execution**: The three functions are public (not entry) and designed to be called with OperatorCap. While tests show them in the same transaction block, in production they CAN be called separately: [8](#0-7) 

2. **No Atomic Enforcement**: There is no on-chain mechanism forcing all three steps to execute atomically in a single transaction

3. **Realistic Failure Scenarios**:
   - Operator transaction failure between steps due to network issues or gas exhaustion
   - Operator error/misunderstanding of the required sequence
   - Malicious operator intentionally DoSing the vault
   - Operator key compromise where attacker starts operation but doesn't complete it

4. **No Timeout or Expiry**: There is no time-based mechanism to automatically reset the status if an operation remains incomplete

### Recommendation

**Option 1 - Add Admin Emergency Reset Function**:
Add a new admin-only emergency function in `volo_vault.move` that allows forcing status reset from DURING_OPERATION to NORMAL:

```move
public(package) fun emergency_reset_status<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
) {
    self.check_version();
    // Allow resetting only from DURING_OPERATION to NORMAL
    assert!(self.status() == VAULT_DURING_OPERATION_STATUS, ERR_INVALID_STATUS);
    self.set_status(VAULT_NORMAL_STATUS);
    self.clear_op_value_update_record();
}
```

Expose this in `manage.move` with AdminCap requirement.

**Option 2 - Combine Functions into Atomic Operation**:
Refactor the operation flow to ensure steps 2 and 3 are always executed together, preventing partial completion.

**Option 3 - Add Operation Timeout**:
Implement a timestamp-based mechanism where operations automatically expire and status resets if not completed within a configurable timeframe.

### Proof of Concept

**Preconditions**:
- Vault is deployed and initialized with OperatorCap issued
- Vault has at least one DeFi asset (e.g., NaviAccountCap) registered
- Vault status is currently NORMAL (0)

**Exploit Steps**:

1. **Operator calls `start_op_with_bag`**:
   - Vault status changes from NORMAL (0) to DURING_OPERATION (1)
   - Borrows DeFi assets into Bag
   - Returns TxBag and TxBagForCheckValueUpdate structs

2. **Operator calls `end_op_with_bag`**:
   - Returns all borrowed DeFi assets to vault
   - Vault status REMAINS at DURING_OPERATION (1)
   - No status reset occurs

3. **Operator stops here** (accidentally or maliciously):
   - Does NOT call `end_op_value_update_with_bag`
   - Vault is permanently stuck in DURING_OPERATION status

4. **Result - Permanent DoS**:
   - Any user attempting `execute_deposit` fails at `assert_normal()` check
   - Any user attempting `execute_withdraw` fails at `assert_normal()` check  
   - Admin attempting `set_vault_enabled` fails at line 523 check
   - No recovery path exists - vault is permanently unusable
   - All user funds (deposited principal, withdrawal requests) are locked

**Notes**

This vulnerability directly maps to the external report's finding about "denial of service through valid calls where operation status is never reset." The Volo implementation splits a critical state transition across three separately-callable functions without atomic enforcement, creating a DoS attack vector similar to how the external report identified issues with incomplete state transitions in order processing.

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

**File:** volo-vault/sources/operation.move (L209-291)
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

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
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

**File:** volo-vault/sources/volo_vault.move (L807-825)
```text
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

```

**File:** volo-vault/sources/volo_vault.move (L995-1003)
```text
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);
```

**File:** volo-vault/tests/operation/operation.test.move (L103-172)
```text
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();

        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];

        let (
            asset_bag,
            tx_bag,
            tx_bag_for_check_value_update,
            principal_balance,
            coin_type_asset_balance,
        ) = operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            defi_asset_ids,
            defi_asset_types,
            1_000_000_000,
            0,
            s.ctx(),
        );

        // Step 2
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            asset_bag,
            tx_bag,
            principal_balance,
            coin_type_asset_balance,
        );

        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            navi_asset_type,
            &mut storage,
        );

        vault.update_free_principal_value(&config, &clock);
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        let op_value_update_record = vault.op_value_update_record();
        assert!(op_value_update_record.op_value_update_record_value_update_enabled());

        // Step 3
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            tx_bag_for_check_value_update,
        );

        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };
```
