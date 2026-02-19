### Title
Unbounded Reserve Iteration Causes Protocol-Wide DoS as Reserve Count Approaches Maximum

### Summary
The lending protocol iterates through ALL reserves (up to 255) before every deposit, withdraw, borrow, repay, and liquidate operation via `update_state_of_all()`. As the protocol naturally grows and adds more assets, gas consumption increases linearly, eventually exceeding Sui's computation limits and rendering the entire protocol unusable, with all user funds effectively locked.

### Finding Description

The root cause is in the `update_state_of_all()` function which unconditionally iterates through every reserve: [1](#0-0) 

This function is called at the start of every core operation:
- Deposit operations: [2](#0-1) 
- Withdraw operations: [3](#0-2) 
- Borrow operations: [4](#0-3) 
- Repay operations: [5](#0-4) 
- Liquidate operations: [6](#0-5) 
- Flash loan repayments: [7](#0-6) 

The protocol allows up to 255 reserves: [8](#0-7) 

For each reserve, `update_state()` performs multiple storage reads and expensive computations: [9](#0-8) 

All public entry points are affected: [10](#0-9) 

The developers acknowledged this issue with a comment: [11](#0-10) 

There are NO mechanisms to:
- Batch reserve updates across transactions
- Skip reserves that don't need updating
- Limit the number of active reserves
- Cache recent updates to reduce redundant work

### Impact Explanation

**Complete Protocol DoS**: Once reserve count reaches a critical threshold (likely 50-100 reserves depending on Sui's gas limits), ALL protocol operations will fail due to gas exhaustion. This affects:

1. **Deposits**: Users cannot deposit funds
2. **Withdrawals**: Users cannot withdraw their funds (funds locked)
3. **Borrows**: Users cannot borrow assets
4. **Repayments**: Borrowers cannot repay loans, accumulating interest
5. **Liquidations**: Unhealthy positions cannot be liquidated, causing protocol insolvency risk
6. **Flash Loans**: Flash loan functionality becomes unusable

**Critical During Market Stress**: Liquidations are most needed during volatile markets when positions become unhealthy. If liquidations fail due to gas limits, the protocol faces cascading insolvency.

**Permanent Lock-In**: Users who deposited funds before the threshold cannot withdraw them, as withdraw operations also require iterating through all reserves.

**No Recovery Path**: Even if admins pause reserve additions, existing reserves still cause the DoS condition.

### Likelihood Explanation

**High Likelihood Through Natural Growth**: This is NOT a malicious attack but an inevitable consequence of normal protocol operations:

1. **Expected Behavior**: Multi-asset lending protocols naturally add more reserves over time to support additional tokens (USDC, USDT, SUI, ETH, BTC, stablecoins, LSTs, governance tokens, etc.). Major protocols like Aave support 30+ assets.

2. **Admin-Controlled But Non-Malicious**: While reserve addition requires admin capabilities ( [12](#0-11) ), this represents normal protocol expansion, not a security compromise.

3. **No Warning Threshold**: The protocol enforces only the hard limit of 255 reserves ( [13](#0-12) ) without any mechanism to prevent approaching dangerous gas consumption levels.

4. **Progressive Degradation**: The protocol will gradually become slower and more expensive before completely failing, but users may not notice until it's too late and their funds are locked.

5. **Irreversible**: Once many reserves are added, the protocol cannot be "fixed" without a complete redesign and migration.

### Recommendation

**Immediate Mitigation**:
1. Implement a conservative reserve limit (e.g., 20-30 reserves) well below the gas limit threshold
2. Add gas consumption monitoring/testing for operations with maximum reserve count

**Long-term Solution**:
```
Replace update_state_of_all() with selective updates:

1. Track last_update timestamp per reserve
2. Only update reserves with:
   - Recent user activity (deposit/borrow in last N blocks)
   - Significant time elapsed since last update
   - Active borrows requiring interest accrual

3. Implement batched update transactions:
   - Separate update_reserves() entry function
   - Allow keeper bots to update reserves in batches
   - Remove requirement for updates before every operation

4. Add lazy evaluation:
   - Update individual reserves on-demand when accessed
   - Cache computed indices for short periods
```

**Test Cases**:
1. Benchmark gas consumption with 10, 25, 50, 100, 150, 255 reserves
2. Test all operations (deposit/withdraw/borrow/repay/liquidate) at each threshold
3. Simulate market stress with maximum reserves and multiple concurrent liquidations
4. Verify operations fail gracefully (revert with clear error) rather than hanging

### Proof of Concept

**Initial State**:
- Protocol has 80+ reserves initialized (realistic for a mature lending protocol)
- Multiple users have deposited funds across various reserves
- Market volatility creates unhealthy positions requiring liquidation

**Exploitation Sequence**:

1. **Normal User Action**: User attempts to withdraw their deposited USDC
   - Transaction calls `entry_withdraw<USDC>()` 
   - Function calls `lending::withdraw_coin()` → `base_withdraw()`
   - `base_withdraw()` calls `logic::execute_withdraw()`
   - `execute_withdraw()` calls `update_state_of_all()`

2. **Gas Exhaustion**:
   - Loop iterates through all 80+ reserves
   - Each iteration performs 6+ storage table reads
   - Each iteration performs multiple ray_math operations (mul, div)
   - Each iteration performs storage writes
   - Total gas consumption: ~(80 reserves × gas_per_reserve) exceeds Sui computation limit

3. **Transaction Failure**: Transaction reverts with "computation limit exceeded" or similar error

4. **Protocol Paralysis**:
   - ALL withdraw attempts fail (users cannot access funds)
   - ALL deposit attempts fail (new users cannot use protocol)
   - ALL borrow attempts fail (no new loans possible)
   - ALL repay attempts fail (borrowers cannot reduce debt)
   - **CRITICAL**: ALL liquidate attempts fail (protocol becomes insolvent)

**Success Condition**: Transaction reverts before completion due to gas limit, demonstrating complete protocol DoS with no recovery mechanism available to users or admins.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L47-47)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L81-81)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L131-131)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L168-168)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L207-207)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L241-241)
```text
    // May cause an increase in gas
```

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L256-288)
```text
    fun update_state(clock: &Clock, storage: &mut Storage, asset: u8) {
        // e.g. get the current timestamp in milliseconds
        let current_timestamp = clock::timestamp_ms(clock);

        // Calculate the time difference between now and the last update
        let last_update_timestamp = storage::get_last_update_timestamp(storage, asset);
        let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;

        // Get All required reserve configurations
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);
        let (current_supply_rate, current_borrow_rate) = storage::get_current_rate(storage, asset);
        let (_, _, _, reserve_factor, _) = storage::get_borrow_rate_factors(storage, asset);
        let (_, total_borrow) = storage::get_total_supply(storage, asset);

        // Calculate new supply index via linear interest
        let linear_interest = calculator::calculate_linear_interest(timestamp_difference, current_supply_rate);
        let new_supply_index = ray_math::ray_mul(linear_interest, current_supply_index);

        // Calculate new borrowing index via compound interest
        let compounded_interest = calculator::calculate_compounded_interest(timestamp_difference, current_borrow_rate);
        let new_borrow_index = ray_math::ray_mul(compounded_interest, current_borrow_index);

        // Calculate the treasury amount
        let treasury_amount = ray_math::ray_mul(
            ray_math::ray_mul(total_borrow, (new_borrow_index - current_borrow_index)),
            reserve_factor
        );
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);

        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_treasury_amount);
        // storage::increase_balance_for_pool(storage, asset, scaled_supply_amount, scaled_borrow_amount + scaled_reserve_amount) // **No need to double calculate interest
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L182-182)
```text
            logic::update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L11-11)
```text
    public fun max_number_of_reserves(): u8 {255}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L780-795)
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L154-155)
```text
    public entry fun init_reserve<CoinType>(
        _: &StorageAdminCap,
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L178-179)
```text
        let current_idx = storage.reserves_count;
        assert!(current_idx < constants::max_number_of_reserves(), error::no_more_reserves_allowed());
```
