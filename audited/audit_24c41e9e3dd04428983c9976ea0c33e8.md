### Title
Reward Rounding Dust Permanently Locked in RewardManager After User Claims

### Summary
The Volo vault's reward distribution system uses index-based proportional distribution with multiple truncating division operations, causing small leftover amounts to accumulate in the `reward_balances` after all users claim their rewards. Unlike the reward buffer which has `retrieve_undistributed_reward`, there is no operator or admin function to retrieve these leftover rewards from the main `reward_balances`, resulting in permanent fund lockup.

### Finding Description

**Mapping from External Report:**
The external report identified rounding discrepancies in dividend distribution where proportional distribution results in small leftover amounts after all users claim. This same vulnerability class exists in Volo's `reward_manager.move`.

**Root Cause in Volo:**

When rewards are added via `add_reward_balance`, the reward amount (with 9 extra decimals) is used to update the global reward index: [1](#0-0) 

The index calculation performs truncating division: [2](#0-1) 

Where `div_with_oracle_price(reward_amount, total_shares)` = `reward_amount * 1e18 / total_shares`, which rounds down due to integer division.

When users claim rewards, their unclaimed amount is calculated by: [3](#0-2) 

This performs another truncating operation at line 177: `mul_with_oracle_price(new_reward_idx - pre_idx, self.shares)` = `(index_diff * shares) / 1e18`, which also rounds down.

Finally, the claimed amount is converted from decimals: [4](#0-3) 

Where `from_decimals` performs a third truncating division: [5](#0-4) 

**Why Protections Fail:**

The only function to retrieve undistributed rewards is `retrieve_undistributed_reward`, which only retrieves from the `reward_buffer.reward_amounts`: [6](#0-5) 

This function explicitly checks and deducts from `reward_buffer.reward_amounts` (line 680-685), but the actual balance is split from `reward_balances` (line 687-698). There is no function to retrieve leftover amounts from the main `reward_balances` that accumulate due to index-based distribution rounding.

The only other access to `reward_balances` is a test-only function: [7](#0-6) 

### Impact Explanation

**Concrete Impact:**
- Reward tokens become permanently locked in the RewardManager's `reward_balances`
- Accumulates with every reward distribution cycle
- Funds cannot be recovered by admin, operator, or users
- Over time, significant value can be locked depending on reward frequency and distribution patterns

**Severity:** Medium to High
- Direct fund lockup (not theft, but permanent loss of protocol funds)
- Affects protocol treasury/operator funds used for rewards
- Impact scales with protocol usage

### Likelihood Explanation

**Realistic Exploit Path:**
1. Operator adds rewards via `add_reward_balance` with any amount where `(reward_amount * 1e18) % total_shares != 0`
2. Index calculation: `add_index = reward_amount * 1e18 / total_shares` (truncates)
3. Users claim rewards, each receiving: `user_reward = (add_index * user_shares / 1e18) / 1e9` (double truncation)
4. Sum of all user claims < original reward amount
5. Difference remains in `reward_balances` with no retrieval function

**Likelihood:** HIGH
- Occurs naturally with normal operations
- No attacker required - happens automatically
- Preconditions always met: any reward distribution where amounts don't divide evenly
- Not blocked by any existing checks

**Example Scenario:**
- total_shares = 3 (three equal users)
- Operator adds 10 tokens (10 * 1e9 = 10,000,000,000 with decimals)
- add_index = 10,000,000,000 * 1e18 / 3 = 3,333,333,333,333,333,333 (truncated from 3,333,333,333.333...)
- Each user with 1 share claims: (3,333,333,333,333,333,333 * 1 / 1e18) / 1e9 = 3 tokens
- Total claimed: 9 tokens
- Leftover permanently locked: 1 token

### Recommendation

Add an admin-controlled function to retrieve leftover reward balances after accounting for all pending unclaimed rewards:

```move
public fun retrieve_leftover_reward_balance<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    amount: u64,
): Balance<RewardCoinType> {
    self.check_version();
    vault::assert_operator_not_freezed(operation, cap);
    
    let reward_type = type_name::get<RewardCoinType>();
    
    // Calculate maximum retrievable amount
    let actual_balance = self.reward_balances.borrow<TypeName, Balance<RewardCoinType>>(reward_type).value();
    let pending_rewards = self.reward_amounts[reward_type];
    let pending_buffer = self.reward_buffer.reward_amounts[reward_type];
    
    // Only allow retrieval of true leftover (balance - pending distributions)
    let max_retrievable = actual_balance - vault_utils::from_decimals(pending_rewards + pending_buffer) as u64;
    assert!(amount <= max_retrievable, ERR_INSUFFICIENT_REWARD_AMOUNT);
    
    let reward_balance = self.reward_balances.borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    reward_balance.split(amount)
}
```

### Proof of Concept

**Setup:**
1. Create vault with 3 users, each depositing equal amounts to get 1 share each (total_shares = 3)
2. Operator calls `add_new_reward_type<PrincipalCoin, RewardCoin>` to enable USDC rewards
3. Operator calls `add_reward_balance` with 10 USDC tokens

**Execution:**
4. Index increases by: `10 * 1e9 * 1e18 / 3 = 3,333,333,333,333,333,333` (truncated)
5. User1 calls `claim_reward<PrincipalCoin, USDC>`:
   - Unclaimed = `(3,333,333,333,333,333,333 * 1) / 1e18 / 1e9` = 3 USDC
   - Receives 3 USDC
6. User2 claims: receives 3 USDC
7. User3 claims: receives 3 USDC

**Result:**
- Total distributed: 9 USDC
- `reward_balances` still holds: 10 - 9 = 1 USDC
- Calling `retrieve_undistributed_reward` fails (checks buffer, not main balance)
- No function exists to retrieve the 1 USDC leftover
- Funds permanently locked in contract

**Verification:**
Check `reward_balance<PrincipalCoin, USDC>(reward_manager).value()` shows 1 USDC remaining with no way to retrieve it.

---

**Notes:**
- No valid analogs found for External Issues #2 (configuration initialization) or #3 (missing access control)
- All Volo configuration functions properly initialize with provided parameters
- All critical state-changing functions (set_enabled, set_operator_freezed, set_status) require AdminCap or are package-private with proper access control

### Citations

**File:** volo-vault/sources/reward_manager.move (L551-590)
```text
public(package) fun update_reward_indices<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &Vault<PrincipalCoinType>,
    reward_type: TypeName,
    reward_amount: u256,
) {
    self.check_version();
    // assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    // Check if the reward type exists in the rewards & reward_indices bag
    assert!(self.reward_amounts.contains(reward_type), ERR_REWARD_TYPE_NOT_FOUND);

    // Update reward index
    // Reward amount normally is 1e9 decimals (token amount)
    // Shares is normally 1e9 decimals
    // The index is 1e18 decimals
    let total_shares = vault.total_shares();
    assert!(total_shares > 0, ERR_VAULT_HAS_NO_SHARES);

    // Index precision
    // reward_amount * 1e18 / total_shares
    // vault has 1e9 * 1e9 shares (1b TVL)
    // reward amount only needs to be larger than 1
    let add_index = vault_utils::div_with_oracle_price(
        reward_amount,
        total_shares,
    );
    let new_reward_index = *self.reward_indices.get(&reward_type) + add_index;

    *self.reward_indices.get_mut(&reward_type) = new_reward_index;

    emit(RewardIndicesUpdated {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
        inc_reward_index: add_index,
        new_reward_index: new_reward_index,
    })
}
```

**File:** volo-vault/sources/reward_manager.move (L619-623)
```text
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;
```

**File:** volo-vault/sources/reward_manager.move (L664-699)
```text
public fun retrieve_undistributed_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    amount: u64,
    clock: &Clock,
): Balance<RewardCoinType> {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    let reward_type = type_name::get<RewardCoinType>();

    self.update_reward_buffer(vault, clock, reward_type);

    let remaining_reward_amount = self.reward_buffer.reward_amounts[reward_type];
    let amount_with_decimals = vault_utils::to_decimals(amount as u256);
    assert!(remaining_reward_amount >= amount_with_decimals, ERR_INSUFFICIENT_REWARD_AMOUNT);

    *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
        remaining_reward_amount - amount_with_decimals;

    let reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);

    emit(UndistributedRewardRetrieved {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        reward_type,
        amount,
    });

    reward_balance.split(amount)
}
```

**File:** volo-vault/sources/reward_manager.move (L748-758)
```text
#[test_only]
public fun remove_reward_balance<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    reward_type: TypeName,
    amount: u64,
): Balance<RewardCoinType> {
    let reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    reward_balance.split(amount)
}
```

**File:** volo-vault/sources/utils.move (L48-50)
```text
public fun from_decimals(v: u256): u256 {
    v / DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/vault_receipt_info.move (L155-192)
```text
public(package) fun update_reward(
    self: &mut VaultReceiptInfo,
    reward_type: TypeName,
    new_reward_idx: u256,
): u256 {
    let reward_indices = &mut self.reward_indices;

    // get or default
    if (!reward_indices.contains(reward_type)) {
        reward_indices.add(reward_type, 0);
    };
    if (!self.unclaimed_rewards.contains(reward_type)) {
        self.unclaimed_rewards.add(reward_type, 0);
    };

    let (pre_idx, unclaimed_reward) = (
        &mut reward_indices[reward_type],
        &mut self.unclaimed_rewards[reward_type],
    );

    if (new_reward_idx > *pre_idx) {
        // get new reward
        let acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares);

        // set reward and index
        *pre_idx = new_reward_idx;
        *unclaimed_reward = *unclaimed_reward + acc_reward;

        emit(VaultReceiptInfoUpdated {
            new_reward: acc_reward,
            unclaimed_reward: *unclaimed_reward,
        });

        acc_reward
    } else {
        return 0
    }
}
```
