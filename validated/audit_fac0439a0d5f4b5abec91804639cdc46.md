# Audit Report

## Title
Denial of Service Via Unbounded VecMap Growth in Reward Manager

## Summary
The reward manager uses a `VecMap` data structure to track reward types, resulting in O(n²) time complexity for critical user operations. As operators legitimately add more reward types for business purposes, gas costs grow quadratically until transactions exceed gas limits, rendering reward claims and first-time deposits unusable.

## Finding Description

The Volo vault reward manager stores reward type tracking data in a `VecMap<TypeName, u256>` structure [1](#0-0) , which has O(n) lookup complexity inherent to Sui Move's VecMap implementation.

**Unbounded Growth**: The `add_new_reward_type()` function allows operators to add unlimited reward types without any maximum bound check [2](#0-1) . The function simply inserts new entries at line 247 with no size validation.

**O(n²) Complexity Path #1**: The `update_receipt_reward()` function exhibits O(n²) behavior by first calling `keys()` on the VecMap (O(n) operation), then looping through each key and calling `get()` on the VecMap (O(n) per call) [3](#0-2) . This is directly exposed to users via the public `claim_reward()` function which calls `update_receipt_reward()` [4](#0-3) .

**O(n²) Complexity Path #2**: The utility function `clone_vecmap_table()` also exhibits O(n²) behavior by calling `keys()` then looping to call `get()` for each key [5](#0-4) . This is invoked during first-time deposits when `issue_vault_receipt_info()` clones the reward_indices VecMap [6](#0-5) , which is called from the public `deposit()` function for users without existing vault receipt info [7](#0-6) .

The reward buffer also uses VecMap for distributions tracking [8](#0-7) , compounding the issue.

## Impact Explanation

This vulnerability causes **high-confidence protocol-level denial of service** affecting core user operations:

1. **Reward Claiming DoS**: Users with accumulated rewards cannot claim them when the reward type count grows sufficiently high. The O(n²) complexity causes transactions to exceed Sui's gas limits, effectively trapping user funds in the protocol indefinitely with no recovery mechanism.

2. **New Deposit DoS**: First-time depositors cannot create vault positions when reward type count is high, as the `clone_vecmap_table()` operation will exceed gas limits. This blocks protocol growth and new user acquisition entirely.

3. **Progressive Degradation**: As operators legitimately add more reward types for yield optimization (supporting multiple DeFi protocols like Cetus, Suilend, Navi, partner tokens, governance tokens), the protocol gradually becomes unusable without requiring any malicious intent.

4. **No User Recovery Path**: Once enough reward types exist, users have no mechanism to reduce complexity, batch operations, or bypass the affected functions. The DoS is permanent until operators remove reward types.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **No Compromise Required**: Operators adding many reward types (50-100+) is a legitimate business decision for multi-strategy vaults supporting various yield sources. No key compromise or malicious operator is needed to trigger the vulnerability.

2. **Untrusted Actors Affected**: Regular users calling public functions `claim_reward()` and `deposit()` trigger the DoS condition. The vulnerability impacts users, not just operators.

3. **Feasible Preconditions**: A vault supporting Cetus rewards, Suilend rewards, Navi rewards, multiple partner tokens, governance tokens, and native SUI staking rewards could realistically reach 50-100 reward types. With O(n²) complexity, even 50 types equals 2,500 VecMap operations per transaction, easily exceeding practical gas limits.

4. **No Existing Checks**: The codebase contains no maximum reward type limit constant, no pagination mechanism, and no alternative code paths to avoid the O(n²) operations.

## Recommendation

Implement the following mitigations:

1. **Add Maximum Reward Type Limit**: Introduce a `MAX_REWARD_TYPES` constant (e.g., 20-30) and enforce it in `add_new_reward_type()`:
   ```
   const MAX_REWARD_TYPES: u64 = 30;
   assert!(self.reward_indices.size() < MAX_REWARD_TYPES, ERR_TOO_MANY_REWARD_TYPES);
   ```

2. **Replace VecMap with Table**: Migrate `reward_indices` from `VecMap<TypeName, u256>` to `Table<TypeName, u256>`, which provides O(1) lookup complexity. This requires updating `issue_vault_receipt_info()` to iterate differently or maintain a separate vector of active reward types.

3. **Implement Pagination**: For `update_receipt_reward()`, allow updating a subset of reward types per call rather than all at once. Add a batch processing mechanism for reward claims.

4. **Cache Active Reward Types**: Maintain a vector of currently active reward type TypeNames to avoid calling `keys()` repeatedly, though this only reduces complexity to O(n) rather than O(n²).

The most effective solution is migrating to Table for O(1) lookups combined with a reasonable maximum limit.

## Proof of Concept

```move
#[test]
fun test_reward_dos_via_many_types() {
    // Setup vault and reward manager
    let ctx = &mut tx_context::dummy();
    let (vault, reward_manager) = setup_vault_with_rewards(ctx);
    
    // Operator adds 100 reward types (legitimate business operation)
    let i = 0;
    while (i < 100) {
        reward_manager.add_new_reward_type<PrincipalCoin, RewardCoin[i]>(
            &operation, &cap, &clock, false
        );
        i = i + 1;
    };
    
    // User attempts to claim rewards - this will exceed gas limit
    // Expected: Transaction fails due to gas limit with O(n²) = 10,000 operations
    let reward = reward_manager.claim_reward<PrincipalCoin, RewardCoin1>(
        &mut vault, &clock, &mut receipt
    );
    // Gas cost: ~100 (keys) + 100 * 100 (get in loop) = 10,100 VecMap operations
    
    // First-time depositor attempts deposit - also exceeds gas limit  
    let (request_id, receipt, coin) = deposit(
        &mut vault, &mut reward_manager, coin, amount, 
        expected_shares, option::none(), &clock, ctx
    );
    // Gas cost: clone_vecmap_table performs ~10,100 VecMap operations
}
```

### Citations

**File:** volo-vault/sources/reward_manager.move (L136-136)
```text
    reward_indices: VecMap<TypeName, u256>,
```

**File:** volo-vault/sources/reward_manager.move (L141-144)
```text
public struct RewardBuffer has store {
    reward_amounts: Table<TypeName, u256>, // Rewards pending to be distributed to actual rewards (u64)
    distributions: VecMap<TypeName, BufferDistribution>,
}
```

**File:** volo-vault/sources/reward_manager.move (L213-229)
```text
public(package) fun issue_vault_receipt_info<T>(
    self: &RewardManager<T>,
    ctx: &mut TxContext,
): VaultReceiptInfo {
    self.check_version();

    // If the receipt is not provided, create a new one (option is "None")
    let unclaimed_rewards = table::new<TypeName, u256>(ctx);
    let reward_indices = vault_utils::clone_vecmap_table(
        &self.reward_indices(),
        ctx,
    );
    vault_receipt_info::new_vault_receipt_info(
        reward_indices,
        unclaimed_rewards,
    )
}
```

**File:** volo-vault/sources/reward_manager.move (L233-274)
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

    let reward_type = type_name::get<RewardCoinType>();

    self.reward_balances.add(reward_type, balance::zero<RewardCoinType>());
    self.reward_amounts.add(reward_type, 0);
    self.reward_indices.insert(reward_type, 0);

    if (with_buffer) {
        let buffer = &mut self.reward_buffer;
        buffer.reward_amounts.add(reward_type, 0);
        buffer
            .distributions
            .insert(
                reward_type,
                BufferDistribution {
                    rate: 0,
                    last_updated: clock.timestamp_ms(),
                },
            );

        emit(RewardBufferDistributionCreated {
            reward_manager_id: self.id.to_address(),
            vault_id: self.vault_id,
            coin_type: reward_type,
        });
    };

    emit(RewardTypeAdded {
        reward_manager_id: self.id.to_address(),
        vault_id: self.vault_id,
        coin_type: reward_type,
    });
}
```

**File:** volo-vault/sources/reward_manager.move (L596-639)
```text
public fun claim_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt: &mut Receipt,
): Balance<RewardCoinType> {
    self.check_version();
    vault.assert_enabled();
    vault.assert_vault_receipt_matched(receipt);
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    let receipt_id = receipt.receipt_id();

    let vault_receipt = vault.vault_receipt_info(receipt_id);
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Update all reward buffers
    self.update_reward_buffers<PrincipalCoinType>(vault, clock);
    // Update the pending reward for the receipt
    self.update_receipt_reward(vault, receipt_id);

    let reward_type = type_name::get<RewardCoinType>();

    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;

    let vault_reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);

    emit(RewardClaimed {
        reward_manager_id: self.id.to_address(),
        vault_id: receipt.vault_id(),
        receipt_id: receipt.receipt_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    });

    vault_reward_balance.split(reward_amount)
}
```

**File:** volo-vault/sources/reward_manager.move (L644-660)
```text
public(package) fun update_receipt_reward<PrincipalCoinType>(
    self: &RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    receipt_id: address,
) {
    self.check_version();

    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);

    // loop all reward in self.cur_reward_indices
    let reward_tokens = self.reward_indices.keys();

    reward_tokens.do_ref!(|reward_type| {
        let new_reward_idx = *self.reward_indices.get(reward_type);
        vault_receipt_mut.update_reward(*reward_type, new_reward_idx);
    });
}
```

**File:** volo-vault/sources/utils.move (L52-66)
```text
public fun clone_vecmap_table<T0: copy + drop + store, T1: copy + store>(
    t: &VecMap<T0, T1>,
    ctx: &mut TxContext,
): Table<T0, T1> {
    let mut t1 = table::new<T0, T1>(ctx);
    let keys = t.keys();
    let mut i = keys.length();
    while (i > 0) {
        let k = keys.borrow(i - 1);
        let v = *t.get(k);
        t1.add(*k, v);
        i = i - 1;
    };
    t1
}
```

**File:** volo-vault/sources/user_entry.move (L19-61)
```text
public fun deposit<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    mut coin: Coin<PrincipalCoinType>,
    amount: u64,
    expected_shares: u256,
    mut original_receipt: Option<Receipt>,
    clock: &Clock,
    ctx: &mut TxContext,
): (u64, Receipt, Coin<PrincipalCoinType>) {
    assert!(amount > 0, ERR_INVALID_AMOUNT);
    assert!(coin.value() >= amount, ERR_INSUFFICIENT_BALANCE);
    assert!(vault.vault_id() == reward_manager.vault_id(), ERR_VAULT_ID_MISMATCH);

    // Split the coin and request a deposit
    let split_coin = coin.split(amount, ctx);

    // Update receipt info (extract from Option<Receipt>)
    let ret_receipt = if (!option::is_some(&original_receipt)) {
        reward_manager.issue_receipt(ctx)
    } else {
        original_receipt.extract()
    };
    original_receipt.destroy_none();

    vault.assert_vault_receipt_matched(&ret_receipt);

    // If there is no receipt before, create a new vault receipt info record in vault
    let receipt_id = ret_receipt.receipt_id();
    if (!vault.contains_vault_receipt_info(receipt_id)) {
        vault.add_vault_receipt_info(receipt_id, reward_manager.issue_vault_receipt_info(ctx));
    };

    let request_id = vault.request_deposit(
        split_coin,
        clock,
        expected_shares,
        receipt_id,
        ctx.sender(),
    );

    (request_id, ret_receipt, coin)
}
```
