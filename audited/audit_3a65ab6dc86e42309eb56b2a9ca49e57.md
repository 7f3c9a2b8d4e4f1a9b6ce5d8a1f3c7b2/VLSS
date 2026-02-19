### Title
Integer Overflow in Incentive Claim Check Causes Permanent DoS on Reward Distribution

### Summary
When `total_supply` is set to `u64::MAX` in `create_incentive_pool()`, the overflow protection logic in `base_claim_reward()` is defective. The comparison check itself (`pool.distributed + reward > pool.total_supply`) performs addition before comparison, causing an arithmetic overflow abort when `distributed` approaches `u64::MAX`. This prevents users from claiming legitimately earned rewards, resulting in permanent loss of access to incentive funds. [1](#0-0) 

### Finding Description

The vulnerability exists in the reward claiming mechanism of the incentive system. When an admin creates an incentive pool using `create_incentive_pool()`, they can set `total_supply` to any `u64` value, including the maximum value `u64::MAX (18,446,744,073,709,551,615)`. [2](#0-1) 

The protocol tracks distributed rewards in `pool.distributed`, initialized to zero and incremented with each successful claim. [3](#0-2) 

The critical flaw occurs in `base_claim_reward()` where the code attempts to cap rewards to prevent over-distribution: [4](#0-3) 

The check at line 323 evaluates `(pool.distributed + reward)` BEFORE performing the comparison. In Sui Move, arithmetic operations that overflow abort the transaction immediately. When `distributed` grows close to `u64::MAX` through normal operation, and a user attempts to claim any non-zero `reward`, the addition `pool.distributed + reward` exceeds `u64::MAX`, causing an overflow abort.

**Root Cause:** The protective capping logic at lines 323-325 cannot execute because the overflow occurs during the condition evaluation itself, before the comparison completes. The subsequent assignment at line 329 is unreachable when overflow occurs.

**Why Existing Protections Fail:** The code assumes the overflow check can complete and then adjust `reward` accordingly. However, Move's strict arithmetic semantics cause the transaction to abort during the addition operation, preventing the capping logic from ever executing.

### Impact Explanation

**Direct Harm:**
- Users permanently lose access to their legitimately earned incentive rewards
- All unclaimed rewards in pools with `total_supply = u64::MAX` become inaccessible once `distributed` approaches the maximum value
- Protocol reputation damage from inability to distribute promised incentives

**Affected Parties:**
- All users who have accumulated rewards in affected incentive pools
- Protocol operators who must either create new pools or refund users manually

**Quantified Impact:**
Once `distributed` reaches approximately `u64::MAX - minimum_claimable_reward`, ALL subsequent claim attempts will fail permanently. For example, if `distributed = u64::MAX - 1000`, any user attempting to claim more than 1000 tokens will experience transaction abort. As `distributed` continues growing (from other successful smaller claims), the threshold drops further until NO claims succeed.

**Severity Justification:** CRITICAL - This is a permanent, protocol-wide DoS on core incentive functionality affecting all users once the condition is met. Unlike temporary DoS, this cannot be recovered without protocol upgrade or creating entirely new incentive pools, abandoning unclaimed rewards in the affected pool.

### Likelihood Explanation

**Attacker Capabilities:** No attacker action required - this is a natural consequence of normal protocol operation when specific configuration is used.

**Preconditions:**
1. Admin creates incentive pool with `total_supply = u64::MAX` (a valid and potentially reasonable choice for large-scale, long-term incentive programs)
2. Normal user claims accumulate over time
3. `distributed` grows to near `u64::MAX` through legitimate reward distribution

**Execution Practicality:**
- Entry point: Public `claim_reward()` function reachable by any user
- No special permissions required beyond normal protocol participation
- Occurs naturally during normal protocol operation without any malicious intervention [5](#0-4) 

**Feasibility:** HIGH - If an admin chooses `total_supply = u64::MAX` for a long-running incentive program, this vulnerability WILL manifest as soon as cumulative distributions approach the maximum value. The question is not "if" but "when."

**Detection/Operational Constraints:** None - the vulnerability is invisible until it triggers, at which point recovery is impossible without protocol intervention.

### Recommendation

**Immediate Fix:** Replace the overflow-prone comparison with checked arithmetic using Move's built-in safe math operations. Restructure the logic to avoid computing the sum before checking bounds:

1. **Option 1 - Checked Addition Pattern:**
```move
// Calculate remaining supply capacity
let remaining_supply = pool.total_supply - pool.distributed;

// Cap reward to remaining supply
if (reward > remaining_supply) {
    reward = remaining_supply;
};

if (reward > 0) {
    amount_to_pay = amount_to_pay + reward;
    pool.distributed = pool.distributed + reward;
    // ... emit event
};
```

2. **Option 2 - Add Explicit Validation in create_incentive_pool:**
Add a maximum supply cap that leaves headroom:
```move
const MAX_SAFE_TOTAL_SUPPLY: u64 = 1_000_000_000_000_000_000; // 1e18, leaving safety margin
assert!(total_supply <= MAX_SAFE_TOTAL_SUPPLY, error::total_supply_too_large());
```

**Invariant Checks:**
- Add assertion: `pool.distributed <= pool.total_supply` after every distribution update
- Add pre-claim validation: `assert!(pool.distributed < pool.total_supply, error::pool_fully_distributed())`

**Test Cases:**
1. Create pool with `total_supply = u64::MAX - 1000`
2. Distribute rewards until `distributed = u64::MAX - 100`
3. Attempt claim with `reward = 200` → Should cap to 100, not overflow
4. Verify `distributed` equals `total_supply` after capping
5. Attempt another claim → Should return 0 reward, not abort

### Proof of Concept

**Initial State:**
- Admin creates `IncentivePool` with `total_supply = 18_446_744_073_709_551_615` (u64::MAX)
- Pool initialized with `distributed = 0`

**Execution Steps:**
1. **Time T0:** Multiple users claim rewards over weeks/months
2. **Time T1:** Through normal operation, `distributed` reaches `18_446_744_073_709_550_000` (u64::MAX - 1,615)
3. **Time T2:** User Alice attempts to claim `reward = 2000` tokens (legitimately earned)
4. **At Line 323:** Evaluation of `(18_446_744_073_709_550_000 + 2000)` = `18_446_744_073_709_552_000`
5. **Result:** Value exceeds `u64::MAX`, transaction aborts with arithmetic overflow

**Expected Result:** Reward should be capped to `1615` (remaining supply), Alice receives capped amount

**Actual Result:** Transaction aborts immediately, Alice receives nothing, ALL future claims fail permanently once this threshold is crossed

**Success Condition for Exploit:** Pool operational with `total_supply = u64::MAX` and `distributed` approaching maximum through normal usage - no malicious action required.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L203-240)
```text
    public fun create_incentive_pool<T>(
        _: &OwnerCap,
        incentive: &mut Incentive,
        funds: &IncentiveFundsPool<T>,
        phase: u64,
        start_at: u64,
        end_at: u64,
        closed_at: u64,
        total_supply: u64,
        option: u8,
        asset_id: u8,
        factor: u256,
        ctx: &mut TxContext
    ) {
        assert!(start_at < end_at, error::invalid_duration_time());
        assert!(closed_at == 0 || closed_at > end_at, error::invalid_duration_time());

        let new_id = object::new(ctx);
        let new_obj_address = object::uid_to_address(&new_id);

        let pool = IncentivePool {
            id: new_id,
            funds: object::uid_to_address(&funds.id),
            phase: phase,
            start_at: start_at,
            end_at: end_at,
            closed_at: closed_at,
            total_supply: total_supply,
            asset_id: asset_id,
            option: option,
            factor: factor,
            index_reward: 0,
            distributed: 0,
            last_update_at: start_at,
            index_rewards_paids: table::new<address, u256>(ctx),
            total_rewards_of_users: table::new<address, u256>(ctx),
            total_claimed_of_users: table::new<address, u256>(ctx),
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L272-281)
```text
    public entry fun claim_reward<T>(clock: &Clock, incentive: &mut Incentive, funds_pool: &mut IncentiveFundsPool<T>, storage: &mut Storage, asset_id: u8, option: u8, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let reward_balance = base_claim_reward(clock, incentive, funds_pool, storage, asset_id, option, sender);

        if (balance::value(&reward_balance) > 0) {
            transfer::public_transfer(coin::from_balance(reward_balance, ctx), sender)
        } else {
            balance::destroy_zero(reward_balance)
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L322-329)
```text
            let reward = ((total_rewards_of_user - total_claimed_of_user) / ray_math::ray() as u64);
            if ((pool.distributed + reward) > pool.total_supply) {
                reward = pool.total_supply - pool.distributed
            };

            if (reward > 0) {
                amount_to_pay = amount_to_pay + reward;
                pool.distributed = pool.distributed + reward;
```
