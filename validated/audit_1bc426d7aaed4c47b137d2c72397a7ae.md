### Title
Vault Disabled Status Blocks Withdrawal Cancellations Creating User Fund Lock

### Summary
The Volo vault implements a three-level status system (NORMAL, DURING_OPERATION, DISABLED) with insufficient granularity for emergency responses. When administrators disable the vault during emergencies, users with pending withdrawal requests cannot cancel them to restore their shares, creating a denial-of-service condition. This asymmetric treatment of cancel operations (deposits can be cancelled when disabled, withdrawals cannot) mirrors the external report's vulnerability class where coarse-grained security levels prevent beneficial user actions during emergencies.

### Finding Description
The vulnerability exists in the vault status system's treatment of withdrawal cancellations. The vault defines three status constants [1](#0-0) , and administrators can toggle between NORMAL and DISABLED status via the `set_enabled` function [2](#0-1) .

The root cause is an asymmetry in status validation for cancel operations:

**Deposit cancellations** check `assert_not_during_operation()` [3](#0-2) , which blocks only DURING_OPERATION status and allows both NORMAL and DISABLED states. This is confirmed by the test case that successfully cancels deposits when the vault is disabled [4](#0-3) .

**Withdrawal cancellations** check `assert_normal()` [5](#0-4) , which only allows NORMAL status and blocks both DURING_OPERATION and DISABLED states.

The `assert_normal()` function enforces this restrictive check [6](#0-5) , while `assert_not_during_operation()` is more permissive [7](#0-6) .

The exploit path executes through the public user entry function [8](#0-7)  which calls the vault's `cancel_withdraw` function. When the vault is disabled, the transaction aborts with `ERR_VAULT_NOT_NORMAL` error code [9](#0-8) .

This design forces administrators into an impossible choice: when disabling the vault during emergencies, they simultaneously lock users' shares in pending withdrawal state with no recovery mechanism, as execution of withdrawals also requires NORMAL status [10](#0-9) .

### Impact Explanation
When the vault is disabled during an emergency (via `set_vault_enabled(false)` [11](#0-10) ), users with pending withdrawal requests experience a complete denial of service:

1. Users cannot cancel their withdrawal requests to restore shares to active status (blocked by `assert_normal()`)
2. Operators cannot execute withdrawal requests to fulfill them (also requires NORMAL status)
3. Users' shares remain frozen in the vault receipt's pending state indefinitely

This creates a high-severity availability issue where users lose control of their shares during the exact moment they need emergency access most. The shares are not lost but are completely inaccessible until administrators re-enable the vault, which may be unsafe depending on the nature of the emergency. The vault receipt tracks pending withdrawal shares [12](#0-11) , and these shares cannot be recovered through any user-initiated action when disabled.

### Likelihood Explanation
The likelihood is HIGH because:

1. **Legitimate trigger**: The vulnerability is triggered by the legitimate admin action of disabling the vault during emergencies, not by any malicious behavior
2. **Common scenario**: Administrators would reasonably disable the vault when detecting vulnerabilities, oracle failures, or other critical issues
3. **No preconditions**: Any user who has submitted a withdrawal request (a normal operation) and then experiences vault disabling is affected
4. **No attacker required**: This is triggered through normal protocol operations, not adversarial actions
5. **Confirmed by design**: The test suite explicitly verifies that deposit cancellations work when disabled but contains no tests for withdrawal cancellations when disabled, indicating this asymmetry was not intentional

The entry point is publicly accessible through `cancel_withdraw_with_auto_transfer` [8](#0-7) , and the failure path is deterministic based solely on vault status.

### Recommendation
Align the status check for `cancel_withdraw` with `cancel_deposit` by changing line 952 in volo_vault.move from:
```
self.assert_normal();
```
to:
```
self.assert_not_during_operation();
```

This change allows users to cancel withdrawal requests when the vault is DISABLED (status=2) while still preventing cancellations during active operations (status=1). The logic is sound because cancelling a withdrawal request is a beneficial action that:
- Returns shares from pending to active state without requiring any fund movements
- Does not interact with external protocols or oracles
- Improves users' ability to respond to emergencies
- Should not be blocked by emergency vault disabling

Alternatively, implement a bitmap-based permission system as suggested in the external report, where each operation (request_deposit, execute_deposit, cancel_deposit, request_withdraw, execute_withdraw, cancel_withdraw) can be individually enabled or disabled, providing maximum flexibility for emergency responses.

### Proof of Concept
1. **Setup**: User requests a withdrawal when vault is in NORMAL status:
   - User calls `withdraw_with_auto_transfer` [13](#0-12) 
   - This calls `request_withdraw` which requires NORMAL status [14](#0-13) 
   - User's shares are moved to pending state in the vault receipt

2. **Emergency trigger**: Admin disables vault due to detected vulnerability:
   - Admin calls `set_vault_enabled(&AdminCap, &mut vault, false)` [11](#0-10) 
   - Vault status changes from NORMAL (0) to DISABLED (2) [2](#0-1) 

3. **User attempts recovery**: User tries to cancel withdrawal request to restore shares:
   - User calls `cancel_withdraw_with_auto_transfer` with their receipt and request_id
   - Function calls `vault.cancel_withdraw()` [15](#0-14) 
   - Function checks `self.assert_normal()` at line 952 [16](#0-15) 
   - Transaction aborts with `ERR_VAULT_NOT_NORMAL` (error code 5_022) [9](#0-8) 

4. **Result**: User's shares remain frozen in pending withdrawal state with no recovery mechanism until admin re-enables the vault, which may be indefinitely delayed or unsafe depending on the emergency nature.

### Citations

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
```

**File:** volo-vault/sources/volo_vault.move (L70-70)
```text
const ERR_VAULT_NOT_NORMAL: u64 = 5_022;
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L657-661)
```text
public(package) fun assert_not_during_operation<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
}
```

**File:** volo-vault/sources/volo_vault.move (L761-769)
```text
public(package) fun cancel_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): Coin<PrincipalCoinType> {
    self.check_version();
    self.assert_not_during_operation();
```

**File:** volo-vault/sources/volo_vault.move (L806-814)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
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

**File:** volo-vault/sources/volo_vault.move (L944-952)
```text
public(package) fun cancel_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): u256 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L974-974)
```text
    vault_receipt.update_after_cancel_withdraw(withdraw_request.shares());
```

**File:** volo-vault/tests/deposit/deposit.test.move (L3073-3134)
```text
public fun test_cancel_deposit_success_vault_disabled() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    // Request deposit
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();

        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault,
            &mut reward_manager,
            coin,
            1_000_000_000,
            2_000_000_000,
            option::none(),
            &clock,
            s.ctx(),
        );

        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        vault.set_enabled(false);
        test_scenario::return_shared(vault);
    };

    // Cancel deposit
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();

        let coin = user_entry::cancel_deposit(
            &mut vault,
            &mut receipt,
            0,
            &clock,
            s.ctx(),
        );

        assert!(coin.value() == 1_000_000_000);

        transfer::public_transfer(coin, OWNER);

        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };
```

**File:** volo-vault/sources/user_entry.move (L150-174)
```text
public fun withdraw_with_auto_transfer<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    shares: u256,
    expected_amount: u64,
    receipt: &mut Receipt,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    vault.assert_vault_receipt_matched(receipt);
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
    assert!(shares > 0, ERR_INVALID_AMOUNT);

    let request_id = vault.request_withdraw(
        clock,
        receipt.receipt_id(),
        shares,
        expected_amount,
        ctx.sender(),
    );

    request_id
}
```

**File:** volo-vault/sources/user_entry.move (L176-193)
```text
public fun cancel_withdraw<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt: &mut Receipt,
    request_id: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): u256 {
    vault.assert_vault_receipt_matched(receipt);

    let cancelled_shares = vault.cancel_withdraw(
        clock,
        request_id,
        receipt.receipt_id(),
        ctx.sender(),
    );

    cancelled_shares
}
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
