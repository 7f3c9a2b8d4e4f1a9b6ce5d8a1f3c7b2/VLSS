### Title
OperatorCap Unrestricted Transfer Risk Due to `store` Ability

### Summary
The volo-vault `OperatorCap` has the `store` ability, enabling unrestricted transfer to any address via `transfer::public_transfer`. Once an operator's private key is compromised or an operator goes rogue, the capability can be transferred to malicious actors who gain full operator privileges over vault operations, deposits/withdrawals, fee collection, and reward management. While a freeze mechanism exists, it is reactive and creates a window of exploitation.

### Finding Description

The root cause is the capability design of `OperatorCap` in the volo-vault system. The struct is defined with both `key` and `store` abilities: [1](#0-0) 

The `store` ability in Sui Move allows the object to be:
- Transferred using `transfer::public_transfer` without restrictions
- Stored as a field in other objects
- Wrapped/unwrapped freely

The `create_operator_cap` function simply returns the capability without any binding mechanism: [2](#0-1) [3](#0-2) 

**Why existing protections fail:**

The protocol implements a freeze mechanism: [4](#0-3) [5](#0-4) 

However, this is **reactive, not preventive**:
1. The admin must first detect the unauthorized transfer
2. The admin must then call `set_operator_freezed` to freeze the specific cap ID
3. During this detection-to-freeze window, the attacker can execute malicious operations

**Comparison to intended design:**

The liquid_staking module demonstrates the correct design pattern where `OperatorCap` only has the `key` ability and requires an explicit transfer function: [6](#0-5) [7](#0-6) 

This design prevents unauthorized transfers and provides event tracking for ownership changes.

### Impact Explanation

An attacker with a transferred `OperatorCap` gains complete operator-level access to:

1. **Execute deposits/withdrawals with slippage manipulation:** [8](#0-7) [9](#0-8) 

2. **Retrieve protocol fees:** [10](#0-9) 

3. **Start/end vault operations and manipulate assets:** [11](#0-10) 

4. **Add malicious reward balances:** [12](#0-11) 

5. **Add/remove asset types:** [13](#0-12) 

**Severity Justification:** HIGH
- Direct fund impact through fee theft and deposit/withdrawal manipulation
- Security integrity breach of authorization model
- Affects all vault users and protocol revenue
- Window of exploitation before freeze can be applied

### Likelihood Explanation

**Attacker Capabilities:**
- Requires obtaining a valid `OperatorCap` through: (1) compromised operator private key, or (2) rogue operator
- Once obtained, execution is trivial: `transfer::public_transfer(operator_cap, attacker_address)`

**Attack Complexity:** LOW
- Single transaction to transfer capability
- No complex execution sequence required
- All operator functions are immediately accessible

**Feasibility Conditions:**
- Operator key compromise is a realistic threat vector (phishing, malware, insider threat)
- No cryptographic or protocol barriers after initial compromise

**Detection Constraints:**
- Transfer is atomic and instant
- Admin must monitor for unauthorized OperatorCapCreated events or operator behavior changes
- No automatic revocation mechanism

**Economic Rationality:**
- High reward: full operator privileges worth potentially millions in TVL access
- Low cost: single transaction gas fee
- Time advantage: exploitation window before admin detection and freeze

### Recommendation

**Remove the `store` ability from OperatorCap:**

```move
// In volo-vault/sources/volo_vault.move
public struct OperatorCap has key {  // Remove 'store' ability
    id: UID,
}
```

**Implement explicit transfer function with event emission:**

```move
// In volo-vault/sources/manage.move
public struct OperatorCapTransferred has copy, drop {
    from: address,
    to: address,
    cap_id: address,
}

public fun transfer_operator_cap(
    _: &AdminCap,
    cap: OperatorCap,
    to: address,
    ctx: &TxContext,
) {
    let cap_id = object::id_address(&cap);
    transfer::transfer(cap, to);
    emit(OperatorCapTransferred {
        from: ctx.sender(),
        to,
        cap_id,
    });
}
```

**Add invariant checks:**
- Log all OperatorCap transfers with from/to addresses
- Implement time-locked transfer capability (24-48 hour delay)
- Consider multi-sig approval for operator cap transfers

**Test cases to add:**
1. Verify OperatorCap cannot be transferred using `transfer::public_transfer` after removing `store`
2. Verify only admin can initiate transfers via the explicit function
3. Verify transfer events are emitted correctly
4. Test freeze mechanism works correctly for transferred caps

### Proof of Concept

**Initial State:**
- Vault deployed with AdminCap held by admin address
- Admin creates OperatorCap via `create_operator_cap()`
- Admin transfers OperatorCap to trusted_operator address

**Exploitation Sequence:**

1. **Attacker compromises trusted_operator's private key** (or operator goes rogue)

2. **Attacker transfers OperatorCap to malicious address:**
   ```move
   // Transaction from trusted_operator address
   transfer::public_transfer(operator_cap, attacker_address);
   ```

3. **Attacker executes malicious operations** (before admin detects and freezes):
   ```move
   // Retrieve all collected fees
   let fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
       &operator_cap,
       &mut vault,
       fee_balance
   );
   
   // Execute deposits with manipulated slippage
   operation::execute_deposit(
       &operation,
       &operator_cap,
       &mut vault,
       &mut reward_manager,
       &clock,
       &config,
       request_id,
       manipulated_max_shares
   );
   ```

4. **Admin detects unauthorized activity and freezes cap:**
   ```move
   vault_manage::set_operator_freezed(
       &admin_cap,
       &mut operation,
       attacker_cap_id,
       true
   );
   ```

**Expected Result:** Transfer should fail due to lack of `store` ability

**Actual Result:** Transfer succeeds, attacker gains full operator privileges until freeze is applied

**Success Condition:** Attacker successfully transfers OperatorCap and executes at least one privileged operation before admin can freeze the capability.

### Citations

**File:** volo-vault/sources/volo_vault.move (L84-86)
```text
public struct OperatorCap has key, store {
    id: UID,
}
```

**File:** volo-vault/sources/volo_vault.move (L362-378)
```text
public(package) fun set_operator_freezed(
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    if (operation.freezed_operators.contains(op_cap_id)) {
        let v = operation.freezed_operators.borrow_mut(op_cap_id);
        *v = freezed;
    } else {
        operation.freezed_operators.add(op_cap_id, freezed);
    };

    emit(OperatorFreezed {
        operator_id: op_cap_id,
        freezed: freezed,
    });
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

**File:** volo-vault/sources/manage.move (L84-86)
```text
public fun create_operator_cap(_: &AdminCap, ctx: &mut TxContext): OperatorCap {
    vault::create_operator_cap(ctx)
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

**File:** liquid_staking/sources/volo_v1/ownership.move (L12-14)
```text
    public struct OperatorCap has key {
        id: UID,
    }
```

**File:** liquid_staking/sources/volo_v1/ownership.move (L48-54)
```text
    public entry fun transfer_operator(cap: OperatorCap, to: address, ctx: &mut TxContext) {
        transfer::transfer(cap, to);
        event::emit(OperatorCapTransferred {
            from: sui::tx_context::sender(ctx),
            to,
        });
    }
```

**File:** volo-vault/sources/operation.move (L94-107)
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

**File:** volo-vault/sources/operation.move (L547-563)
```text
public fun add_new_coin_type_asset<PrincipalCoinType, AssetType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_coin_type_asset<PrincipalCoinType, AssetType>();
}

public fun remove_coin_type_asset<PrincipalCoinType, AssetType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.remove_coin_type_asset<PrincipalCoinType, AssetType>();
}
```

**File:** volo-vault/sources/reward_manager.move (L340-376)
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

    let reward_type = type_name::get<RewardCoinType>();
    let reward_amount = vault_utils::to_decimals(reward.value() as u256);

    // If the reward amount is too small to make the index increase,
    // the reward will be lost.
    let minimum_reward_amount = vault_utils::mul_with_oracle_price(vault.total_shares(), 1);
    assert!(reward_amount>= minimum_reward_amount, ERR_REWARD_AMOUNT_TOO_SMALL);

    // New reward balance goes into the bag
    let reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    reward_balance.join(reward);

    let reward_amounts = self.reward_amounts.borrow_mut(reward_type);
    *reward_amounts = *reward_amounts + reward_amount;

    self.update_reward_indices(vault, reward_type, reward_amount);

    emit(RewardBalanceAdded {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    })
}
```
