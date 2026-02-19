### Title
Integer Division Truncation Allows Borrowers to Permanently Skip Interest Accrual via Rapid State Updates

### Summary
The `update_state()` function in lending_core divides millisecond timestamp differences by 1000 to convert to seconds, causing truncation to zero for sub-second intervals. When `timestamp_difference = 0`, no interest accrues, but the `last_update_timestamp` is still advanced, permanently skipping that time period from interest calculations. Borrowers can exploit this by triggering rapid transactions (e.g., every 500ms) to avoid paying significant interest over time.

### Finding Description

The vulnerability exists in the state update mechanism that calculates accrued interest: [1](#0-0) 

The critical flaw occurs at the division operation that converts milliseconds to seconds. When two transactions occur within the same second (less than 1000ms apart), `timestamp_difference` truncates to zero. [2](#0-1) [3](#0-2) 

Both interest calculation functions return `ray_math::ray()` (representing 1.0, meaning no interest) when `timestamp_difference = 0`. However, the timestamp is still updated: [4](#0-3) [5](#0-4) 

This permanently skips the sub-second time period from interest calculations - it is never recovered in subsequent updates.

**Entry Points:** All lending operations call `update_state_of_all()`: [6](#0-5) 

These are accessible via public entry functions: [7](#0-6) 

### Impact Explanation

**Direct Financial Loss:**
- **Lenders**: Lose interest income on their supplied assets
- **Protocol Treasury**: Loses reserve factor income from interest
- **Borrowers**: Illegitimately avoid paying interest obligations

**Quantified Example** (for $10M borrowed at 10% APY):
- Normal interest: ~$2.74/second
- Attacker executes transaction every 500ms (2 tx/second)
- Each update: `timestamp_difference = 500/1000 = 0` → no interest accrues
- Time skipped: ~50% of all seconds
- Interest avoided: ~$1,370/day or ~$500,000/year
- Gas costs (at ~$0.0001/tx): ~$17/day
- **Net profit to attacker: ~$1,353/day or ~$494,000/year**

For larger positions or multiple borrowers coordinating this attack, losses scale linearly. This represents a critical breach of the interest accrual invariant and direct fund theft from lenders.

### Likelihood Explanation

**High Likelihood - All Conditions Met:**

1. **Reachable Entry Point**: Any user can call `entry_deposit()`, `entry_withdraw()`, `entry_borrow()`, or `entry_repay()` in incentive_v3 module to trigger state updates.

2. **Feasible Preconditions**: 
   - Attacker only needs a borrow position (obtained through normal protocol usage)
   - No special privileges required
   - Sui's fast finality (sub-second) enables rapid transaction submission

3. **Execution Practicality**:
   - Simple to automate with a bot that submits minimal transactions (e.g., deposit 1 wei) every 500-900ms
   - Each transaction is valid and passes all protocol checks
   - No rate limiting exists in lending_core module

4. **Economic Rationality**:
   - For positions > $1M, annual interest saved >> annual gas costs
   - Break-even at relatively small positions (~$50k-100k depending on gas prices)
   - Attack scales with position size and number of attackers
   - Risk-free profit with no downside beyond gas costs

**Detection/Prevention Gaps:**
- No minimum time requirement between state updates
- No monitoring for rapid transaction patterns
- No accumulated time tracking to prevent skipping

The attack is practical, profitable, and difficult to detect without specialized monitoring.

### Recommendation

**Primary Fix - Use Millisecond Precision:**

Modify `update_state()` to track time in milliseconds instead of seconds, eliminating truncation:

```move
// In logic.move, update_state():
let timestamp_difference_ms = current_timestamp - last_update_timestamp as u256;

// In calculator.move, update interest calculation functions:
public fun calculate_compounded_interest(
    timestamp_difference_ms: u256,
    rate: u256
): u256 {
    if (timestamp_difference_ms == 0) {
        return ray_math::ray()
    };
    // Convert rate from per-year to per-millisecond
    let rate_per_ms = rate / (constants::seconds_per_year() * 1000);
    // Rest of calculation using millisecond precision
    ...
}

public fun calculate_linear_interest(
    timestamp_difference_ms: u256,
    rate: u256
): u256 {
    ray_math::ray() + rate * timestamp_difference_ms / (constants::seconds_per_year() * 1000)
}
```

**Alternative Fix - Accumulate Remainder:**

Track sub-second remainder and carry it forward:

```move
// In Storage reserve struct, add:
accumulated_ms: u64  // Tracks sub-second remainder

// In update_state():
let total_ms = (current_timestamp - last_update_timestamp as u256) + (accumulated_ms as u256);
let timestamp_difference = total_ms / 1000;
let new_accumulated_ms = (total_ms % 1000) as u64;
// Update accumulated_ms in storage
```

**Additional Protection - Minimum Update Interval:**

```move
// In update_state():
let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;
assert!(timestamp_difference > 0 || current_timestamp == last_update_timestamp, ERROR_TOO_FREQUENT);
```

**Test Cases to Add:**
1. Rapid successive deposits/withdrawals within 1 second
2. Verify interest accrues correctly for sub-second intervals
3. Compare accumulated interest over time with/without rapid updates
4. Stress test with 100+ transactions per second

### Proof of Concept

**Initial State:**
- User has borrowed 10,000,000 USDC from lending pool
- Current borrow rate: 10% APY (~0.000000317 per second = 317 basis points per billion seconds)
- Pool last_update_timestamp: T₀ = 1000000000000 ms

**Attack Sequence:**

1. **T = T₀ + 500ms**: Attacker deposits 1 wei USDC
   - Triggers `update_state_of_all()`
   - `timestamp_difference = (1000000000500 - 1000000000000) / 1000 = 500 / 1000 = 0`
   - Interest calculation: `calculate_compounded_interest(0, rate)` returns `ray_math::ray()` (no interest)
   - `last_update_timestamp` updated to 1000000000500
   - **Interest accrued: 0 USDC** (should be ~$1.585)

2. **T = T₀ + 1000ms**: Attacker deposits 1 wei USDC again
   - `timestamp_difference = (1000000001000 - 1000000000500) / 1000 = 500 / 1000 = 0`
   - **Interest accrued: 0 USDC** (should be ~$1.585)
   - `last_update_timestamp` updated to 1000000001000

3. **T = T₀ + 1500ms**: Attacker deposits 1 wei USDC again
   - `timestamp_difference = (1000000001500 - 1000000001000) / 1000 = 500 / 1000 = 0`
   - **Interest accrued: 0 USDC** (should be ~$1.585)
   - `last_update_timestamp` updated to 1000000001500

**Expected vs Actual Result:**

After 1.5 seconds:
- **Expected total interest**: ~$4.755 (1.5 seconds × $3.17/second)
- **Actual interest accrued**: $0.00
- **Time permanently lost**: 1.5 seconds (never recoverable)

**Success Condition:** 
Attacker's borrow balance remains unchanged despite time passage, confirming zero interest accrual. This can be verified by querying `user_loan_balance()` before and after the sequence - the balance should increase by expected interest but remains the same.

**Automation:** Deploy bot that monitors block timestamps and submits minimal transactions every 500ms indefinitely, achieving ~50% interest avoidance for the life of the loan.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L243-251)
```text
    public(friend) fun update_state_of_all(clock: &Clock, storage: &mut Storage) {
        let count = storage::get_reserves_count(storage);

        let i = 0;
        while (i < count) {
            update_state(clock, storage, i);
            i = i + 1;
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L256-263)
```text
    fun update_state(clock: &Clock, storage: &mut Storage, asset: u8) {
        // e.g. get the current timestamp in milliseconds
        let current_timestamp = clock::timestamp_ms(clock);

        // Calculate the time difference between now and the last update
        let last_update_timestamp = storage::get_last_update_timestamp(storage, asset);
        let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L285-286)
```text
        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_treasury_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L55-62)
```text
    public fun calculate_compounded_interest(
        timestamp_difference: u256,
        rate: u256
    ): u256 {
        // // e.g. get the time difference of the last update --> (1685029315718 - 1685029255718) / 1000 == 60s
        if (timestamp_difference == 0) {
            return ray_math::ray()
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L90-95)
```text
    public fun calculate_linear_interest(
        timestamp_difference: u256,
        rate: u256
    ): u256 {
        ray_math::ray() + rate * timestamp_difference / constants::seconds_per_year()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L490-492)
```text
        reserve.current_supply_index = new_supply_index;
        reserve.last_update_timestamp = last_update_timestamp;
        reserve.treasury_balance = reserve.treasury_balance + scaled_treasury_amount;
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L780-796)
```text
    public entry fun entry_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_coin<CoinType>(clock, storage, pool, asset, deposit_coin, amount, ctx);
    }
```
