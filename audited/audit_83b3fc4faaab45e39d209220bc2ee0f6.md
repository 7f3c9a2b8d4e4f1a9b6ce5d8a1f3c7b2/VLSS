### Title
Multiple IncentiveV3 Objects Can Exist Without Singleton Enforcement, Enabling Reward Fund Depletion

### Summary
The `create_incentive_v3()` function lacks singleton enforcement, allowing multiple IncentiveV3 shared objects to be created. Since each Incentive object tracks rewards independently but can draw from the same RewardFund during claims, this enables reward duplication where the same underlying deposits earn rewards across multiple Incentive instances, leading to premature RewardFund depletion and unfair distribution.

### Finding Description

**Root Cause:** The `create_incentive_v3` function in the manage module can be called multiple times by any holder of an `IncentiveOwnerCap`, with no mechanism to prevent duplicate Incentive object creation. [1](#0-0) 

Each invocation creates a new shared Incentive object via `transfer::share_object`: [2](#0-1) 

**Why Protections Fail:**

1. **No Singleton Check:** The creation function contains no validation to prevent multiple Incentive objects from existing simultaneously.

2. **Multiple OwnerCaps Possible:** The `IncentiveOwnerCap` itself can be created multiple times, or a single cap can repeatedly call the creation function: [3](#0-2) 

3. **Independent Reward Tracking:** Each Incentive object maintains its own reward state (`user_index`, `user_total_rewards`, `user_rewards_claimed` tables) but all can draw from the same RewardFund.

4. **No RewardFund-Incentive Binding:** When claiming rewards, the function accepts any Incentive and any RewardFund as separate parameters without validating their association: [4](#0-3) 

5. **Public Reward Accrual:** The `update_reward_state_by_asset` function is public, allowing anyone to accrue rewards in any Incentive object for any user: [5](#0-4) 

**Execution Path:**
1. Operator creates official IncentiveV3 object A with reward rules for asset X
2. Someone with IncentiveOwnerCap creates IncentiveV3 object B with identical rules
3. Users deposit asset X into the protocol (tracked in Storage)
4. Reward state updates occur in Incentive A (official path)
5. Attacker calls `update_reward_state_by_asset` with Incentive B for the same users/assets
6. Rewards accrue in both Incentive A and B for the same underlying deposits
7. Users (or attacker) claim from both objects against the same RewardFund
8. RewardFund depletes faster than intended; legitimate users may be unable to claim

### Impact Explanation

**Direct Fund Impact:**
- **RewardFund Depletion:** Reward tokens are distributed multiple times for the same underlying positions, draining the RewardFund faster than the intended distribution schedule
- **Unfair Distribution:** Early claimants from duplicate Incentive objects receive disproportionate rewards, while later legitimate claimants face insufficient funds
- **Quantified Damage:** If N duplicate Incentive objects exist with identical rules, the RewardFund can be drained up to N times faster than designed, potentially leading to 100% fund exhaustion before the reward period ends

**Who Is Affected:**
- Protocol operators lose control over reward distribution economics
- Legitimate users who deposited/borrowed based on advertised reward rates may receive zero rewards
- Protocol reputation suffers from broken reward promises

**Severity Justification:**
Medium severity because:
- Requires IncentiveOwnerCap possession (privileged but not admin-level)
- Direct financial impact on reward distribution integrity
- Violates core invariant of controlled reward allocation
- Does not directly steal vault/LST principal, limiting to reward fund scope

### Likelihood Explanation

**Attacker Capabilities:**
- Requires IncentiveOwnerCap possession - this is a privileged capability but less restricted than admin caps
- Alternatively, a single well-meaning operator with the cap could accidentally create duplicates
- No additional privileged access needed beyond the cap

**Attack Complexity:**
- Low complexity: Single transaction to call `create_incentive_v3` with existing cap
- Setup duplicate rules via standard `create_incentive_v3_pool` and `create_incentive_v3_rule` functions
- Users naturally interact with protocol, accruing rewards in multiple objects
- Claim rewards from duplicate Incentive object using same RewardFund

**Feasibility Conditions:**
- IncentiveOwnerCap exists and can be accessed
- RewardFund has been funded (normal operational state)
- No monitoring in place to detect duplicate Incentive objects
- Protocol functions operate as designed - no special conditions needed

**Detection/Operational Constraints:**
- Difficult to detect in advance - multiple shared objects of same type are valid in Sui
- No on-chain mechanism alerts to duplicate Incentive creation
- Once created, duplicate object persists permanently as shared object

**Probability Assessment:**
Medium-High probability because:
- Single point of failure (no singleton enforcement)
- Normal protocol operations enable the exploit
- Incentive structure (earning extra rewards) motivates exploitation
- Accidental duplication also possible during protocol upgrades/migrations

### Recommendation

**Code-Level Mitigation:**

1. **Add Singleton Registry:** Create a global registry object during module initialization that tracks the canonical Incentive object address:

```move
struct IncentiveRegistry has key {
    id: UID,
    incentive_address: Option<address>,
}

fun init(ctx: &mut TxContext) {
    transfer::share_object(IncentiveRegistry {
        id: object::new(ctx),
        incentive_address: option::none(),
    });
}
```

2. **Enforce Singleton in create_incentive_v3:**

```move
public(friend) fun create_incentive_v3(registry: &mut IncentiveRegistry, ctx: &mut TxContext) {
    assert!(option::is_none(&registry.incentive_address), error::incentive_already_exists());
    
    let id = object::new(ctx);
    let addr = object::uid_to_address(&id);
    
    let i = Incentive { /* ... */ };
    
    option::fill(&mut registry.incentive_address, addr);
    transfer::share_object(i);
}
```

3. **Bind RewardFund to Incentive:** Add incentive_id field to RewardFund and validate during claims:

```move
struct RewardFund<phantom CoinType> has key, store {
    id: UID,
    balance: Balance<CoinType>,
    coin_type: String,
    incentive_id: address, // Add this
}

// In claim function:
assert!(object::uid_to_address(&incentive.id) == reward_fund.incentive_id, error::mismatched_incentive());
```

**Invariant Checks:**
- Assert only one Incentive object exists per protocol deployment
- Validate RewardFund-Incentive pairing during all claim operations
- Add integration tests verifying singleton enforcement

**Test Cases:**
1. Test that second call to `create_incentive_v3` aborts with singleton violation
2. Test that claiming with mismatched Incentive-RewardFund pair fails
3. Test migration path that preserves singleton invariant
4. Fuzz test with multiple concurrent creation attempts

### Proof of Concept

**Required Initial State:**
- Protocol deployed with lending_core modules
- StorageOwnerCap exists for creating IncentiveOwnerCap
- Storage has reserves configured (e.g., SUI at asset_id 0)
- Oracle provides prices

**Transaction Steps:**

1. **Setup - Create First Incentive (Official):**
   - Call `incentive_v2::create_and_transfer_owner(&storage_owner_cap)` → Creates OwnerCap₁
   - Call `manage::create_incentive_v3(&owner_cap₁)` → Creates Incentive A (address 0xAAA)
   - Call `manage::create_incentive_v3_pool<SUI>(&owner_cap₁, &incentive_A, &storage, 0)`
   - Call `manage::create_incentive_v3_rule<SUI, USDT>(&owner_cap₁, &clock, &incentive_A, 1)` (supply rule)
   - Call `manage::create_incentive_v3_reward_fund<USDT>(&owner_cap₁)` → Creates RewardFund
   - Fund RewardFund with 100,000 USDT

2. **Attack - Create Duplicate Incentive:**
   - Call `manage::create_incentive_v3(&owner_cap₁)` again → Creates Incentive B (address 0xBBB) ✓ **No error**
   - Call `manage::create_incentive_v3_pool<SUI>(&owner_cap₁, &incentive_B, &storage, 0)` on Incentive B
   - Call `manage::create_incentive_v3_rule<SUI, USDT>(&owner_cap₁, &clock, &incentive_B, 1)` on Incentive B

3. **Exploit - Duplicate Reward Accrual:**
   - User deposits 1000 SUI via `incentive_v3::entry_deposit<SUI>(..., &incentive_A)` at T=0
   - Wait 30 days (reward rate configured for 100k USDT over 365 days)
   - Expected reward from Incentive A: ~8,219 USDT
   - Call `incentive_v3::update_reward_state_by_asset<SUI>(&clock, &incentive_B, &storage, user)` at T=30
   - User now has ~8,219 USDT claimable from BOTH Incentive A and B (total ~16,438 USDT)

4. **Claim Duplicate Rewards:**
   - Call `incentive_v3::claim_reward_entry<USDT>(&clock, &incentive_A, &storage, &reward_fund, ...)` → Receives 8,219 USDT
   - Call `incentive_v3::claim_reward_entry<USDT>(&clock, &incentive_B, &storage, &reward_fund, ...)` → Receives another 8,219 USDT ✓ **Same RewardFund depleted twice**

**Expected vs Actual Result:**
- **Expected:** Only one Incentive object exists; user receives 8,219 USDT for 30-day deposit
- **Actual:** Two Incentive objects exist; user receives 16,438 USDT from same RewardFund; 365-day fund exhausted in ~182 days

**Success Condition:**
RewardFund balance decreases by 2X the intended distribution rate, confirming duplicate reward claims from multiple Incentive objects against the same fund.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L120-122)
```text
    public fun create_incentive_v3(_: &IncentiveOwnerCap, ctx: &mut TxContext) {
        incentive_v3::create_incentive_v3(ctx)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L215-232)
```text
    public(friend) fun create_incentive_v3(ctx: &mut TxContext) {
        let id = object::new(ctx);
        let addr = object::uid_to_address(&id);

        let i = Incentive {
            id,
            version: version::this_version(),
            pools: vec_map::empty(),
            borrow_fee_rate: 0,
            fee_balance: bag::new(ctx),
        };

        transfer::share_object(i);
        emit(IncentiveCreated{
            sender: tx_context::sender(ctx),
            incentive_id: addr,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L443-480)
```text
    fun base_claim_reward_by_rule<RewardCoinType>(clock: &Clock, storage: &mut Storage, incentive: &mut Incentive, reward_fund: &mut RewardFund<RewardCoinType>, coin_type: String, rule_id: address, user: address): (u256, Balance<RewardCoinType>) {
        assert!(vec_map::contains(&incentive.pools, &coin_type), error::pool_not_found());

        let pool = vec_map::get_mut(&mut incentive.pools, &coin_type);
        assert!(vec_map::contains(&pool.rules, &rule_id), error::rule_not_found());

        let rule = vec_map::get_mut(&mut pool.rules, &rule_id);
        let reward_coin_type = type_name::into_string(type_name::get<RewardCoinType>());
        assert!(rule.reward_coin_type == reward_coin_type, error::invalid_coin_type());

        // continue if the rule is not enabled
        if (!rule.enable) {
            return (rule.global_index, balance::zero<RewardCoinType>())
        };

        // update the user reward
        update_reward_state_by_rule(clock, storage, pool.asset, rule, user);

        let user_total_reward = *table::borrow(&rule.user_total_rewards, user);

        if (!table::contains(&rule.user_rewards_claimed, user)) {
            table::add(&mut rule.user_rewards_claimed, user, 0);
        };
        let user_reward_claimed = table::borrow_mut(&mut rule.user_rewards_claimed, user);

        let reward = if (user_total_reward > *user_reward_claimed) {
            user_total_reward - *user_reward_claimed
        } else {
            0
        };
        *user_reward_claimed = user_total_reward;

        if (reward > 0) {
            return (rule.global_index, balance::split(&mut reward_fund.balance, (reward as u64)))
        } else {
            return (rule.global_index, balance::zero<RewardCoinType>())
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L516-534)
```text
    public fun update_reward_state_by_asset<T>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, user: address) {
        version_verification(incentive);
        let coin_type = type_name::into_string(type_name::get<T>());
        if (!vec_map::contains(&incentive.pools, &coin_type)) {
            return
        };
        let pool = vec_map::get_mut(&mut incentive.pools, &coin_type);
        let (user_effective_supply, user_effective_borrow, total_supply, total_borrow) = get_effective_balance(storage, pool.asset, user);

        // update rewards
        let rule_keys = vec_map::keys(&pool.rules);
        while (vector::length(&rule_keys) > 0) {
            let key = vector::pop_back(&mut rule_keys);
            let rule = vec_map::get_mut(&mut pool.rules, &key);

            // update the user reward
            update_reward_state_by_rule_and_balance(clock, rule, user, user_effective_supply, user_effective_borrow, total_supply, total_borrow);
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L112-114)
```text
    public fun create_and_transfer_owner(_: &StorageOwnerCap, ctx: &mut TxContext) {
        transfer::public_transfer(OwnerCap {id: object::new(ctx)}, tx_context::sender(ctx));
    }
```
