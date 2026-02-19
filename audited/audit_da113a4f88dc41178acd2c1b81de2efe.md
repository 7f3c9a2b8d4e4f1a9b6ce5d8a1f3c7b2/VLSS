### Title
Immutable Reward Manager Configuration Prevents Critical Updates

### Summary
The `reward_manager` address field in the Vault struct can only be set once during initialization and cannot be updated afterward. This creates a permanent binding to a potentially incorrect, compromised, or outdated reward manager contract, with no recovery mechanism. Since deposit and withdraw operations require the reward manager, this immutability can cause operational failures or lock the vault into using a flawed reward distribution system.

### Finding Description
The vulnerability maps directly to the external report's pattern where a critical configuration field lacks an update mechanism after initialization.

In the Volo vault, the `reward_manager` field is initialized to the zero address during vault creation: [1](#0-0) 

The `set_reward_manager` function can only be called once, enforced by an assertion that checks if the reward manager is still the zero address: [2](#0-1) 

Once set, there is no admin function to update or replace the reward manager. The manage module only provides functions for other vault parameters but not for updating the reward manager: [3](#0-2) 

**Critical Dependency**: Both deposit and withdraw operations require a mutable reference to the RewardManager and call `update_receipt_reward` to track user rewards: [4](#0-3) [5](#0-4) 

**Why Protections Fail**: The assertion at line 476 that prevents re-setting the reward manager was designed to prevent accidental overwrites, but it creates an irrecoverable situation if the wrong address is set or if the reward manager needs to be replaced due to bugs or security issues.

### Impact Explanation
1. **Operational Failure**: If an incorrect reward manager address is set (typo, clipboard error), all deposit and withdraw operations will fail permanently since they require the RewardManager reference.

2. **No Recovery from Bugs**: If the reward manager contract has a critical bug or security vulnerability discovered after deployment, the vault cannot switch to a fixed version.

3. **Upgrade Impossibility**: Protocol improvements to reward distribution logic cannot be deployed to existing vaults.

4. **Fund Lock Risk**: If the reward manager becomes non-functional, users cannot deposit or withdraw from the vault, effectively locking funds.

### Likelihood Explanation
**High Likelihood**:
- **Admin Error**: During vault setup, the admin could easily input the wrong reward manager address through typos or copy-paste errors.
- **Post-Deployment Issues**: Security vulnerabilities or bugs in the reward manager might be discovered after vault creation, requiring replacement.
- **Protocol Evolution**: The protocol may want to upgrade to improved reward distribution mechanisms but cannot update existing vaults.

The exploit path is straightforward:
1. Admin creates vault with `create_vault`
2. Admin calls `create_reward_manager` which internally calls `set_reward_manager`
3. If wrong address is provided or future issues arise, vault is permanently bound to that reward manager
4. No recovery mechanism exists in the protocol

### Recommendation
Add an admin-gated function to update the reward manager address:

```move
public(package) fun update_reward_manager<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    new_reward_manager_id: address,
) {
    self.check_version();
    assert!(new_reward_manager_id != address::from_u256(0), ERR_INVALID_ADDRESS);
    self.reward_manager = new_reward_manager_id;
    
    emit(RewardManagerUpdated {
        vault_id: self.vault_id(),
        old_reward_manager_id: self.reward_manager,
        new_reward_manager_id: new_reward_manager_id,
    });
}
```

This function should be exposed through the manage module with AdminCap authorization.

### Proof of Concept
1. **Setup**: Admin deploys a vault for SUI token using `create_vault<SUI>`
2. **Initial Set**: Admin creates reward manager by calling `create_reward_manager` which sets `vault.reward_manager = reward_manager_address_A`
3. **Error Scenario**: Admin realizes wrong address was used (e.g., reward_manager_address_A instead of intended reward_manager_address_B)
4. **Attempted Fix**: Admin tries to call `set_reward_manager` again with correct address
5. **Failure**: Transaction aborts with `ERR_REWARD_MANAGER_ALREADY_SET` error
6. **Permanent Impact**: 
   - Vault is permanently bound to wrong reward manager
   - If address_A is invalid/buggy, all `execute_deposit` and `execute_withdraw` operations will fail
   - Users cannot deposit or withdraw funds
   - No admin function exists to correct the mistake

### Citations

**File:** volo-vault/sources/volo_vault.move (L447-447)
```text
        reward_manager: address::from_u256(0),
```

**File:** volo-vault/sources/volo_vault.move (L471-483)
```text
public(package) fun set_reward_manager<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    reward_manager_id: address,
) {
    self.check_version();
    assert!(self.reward_manager == address::from_u256(0), ERR_REWARD_MANAGER_ALREADY_SET);
    self.reward_manager = reward_manager_id;

    emit(RewardManagerSet {
        vault_id: self.vault_id(),
        reward_manager_id: reward_manager_id,
    });
}
```

**File:** volo-vault/sources/manage.move (L160-166)
```text
public fun create_reward_manager<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &mut TxContext,
) {
    reward_manager::create_reward_manager<PrincipalCoinType>(vault, ctx);
}
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
