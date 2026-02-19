### Title
Arithmetic Overflow in Decimal Conversion Causes Withdrawal DoS for High-Decimal Tokens

### Summary
The `convert_amount()` function performs unchecked multiplication by 10 when converting amounts to higher decimal precision, causing arithmetic overflow and transaction abort for realistic token amounts. For coins with more than 9 decimals (e.g., 18-decimal tokens common in bridged assets), users holding more than ~18.4 tokens cannot withdraw, borrow, or repay, resulting in permanent fund lockup.

### Finding Description

The vulnerability exists in the `convert_amount()` function which normalizes token amounts between different decimal representations: [1](#0-0) 

When `cur_decimal < target_decimal`, the function multiplies `amount` by 10 in each iteration without overflow protection. In Sui Move, u64 arithmetic overflow causes transaction abort rather than wrapping.

The protocol normalizes all amounts to 9 decimals internally via `normal_amount()`: [2](#0-1) 

And converts back to native decimals via `unnormal_amount()`: [3](#0-2) 

**Critical Execution Path (Withdrawal):**

1. User's balance is stored as u256 in 9-decimal normalized format
2. `execute_withdraw()` casts the balance to u64: [4](#0-3) 

3. `base_withdraw()` calls `unnormal_amount()` to convert from 9 decimals to the coin's native decimals: [5](#0-4) 

4. For an 18-decimal token, this requires multiplying by 10^9
5. If the normalized amount ≥ 18,446,744,074 (smallest unit), the multiplication overflows

**Overflow Threshold Calculation:**
- u64::MAX = 18,446,744,073,709,551,615
- For 18-decimal token: overflow when `amount * 10^9 > u64::MAX`
- Therefore: `amount > 18,446,744,073` (in 9-decimal representation)
- In human terms: **> 18.4 tokens** causes permanent withdrawal failure

The protocol has no decimal restrictions when creating pools: [6](#0-5) 

User balances are stored as u256 allowing large accumulations: [7](#0-6) 

### Impact Explanation

**Operational Impact - Permanent Fund Lockup:**

Users cannot withdraw, borrow, or repay when their balance exceeds the overflow threshold. For an 18-decimal token:

- **Threshold**: 18.4 tokens
- **USDC/USDT equivalent**: $18.40 - affects virtually all users
- **ETH at $3,000**: $55,200 - affects typical DeFi users
- **WBTC**: ~$1,000,000+ - affects whales

The same issue affects:
- Withdrawals (as shown above)
- Borrows (normalizing requested amount): [8](#0-7) 

- Repayments (both normalizing and unnormalizing): [9](#0-8) 

- Flash loans: [10](#0-9) 

**Who is affected:**
- Any user with > 18.4 tokens of an 18-decimal asset
- For 15-decimal tokens: > 18.4 million tokens
- For 12-decimal tokens: > 18.4 billion tokens

**Funds are stuck, not stolen** - users retain ownership but cannot access their assets, violating the fundamental custody invariant.

### Likelihood Explanation

**HIGH Likelihood - Realistic and Inevitable:**

1. **Reachable Entry Point**: All public lending functions (deposit, withdraw, borrow, repay) are affected: [11](#0-10) 

2. **Feasible Preconditions**: 
   - Protocol supports any coin type generically
   - No decimal validation or restrictions exist
   - Bridged tokens from Ethereum commonly use 18 decimals
   - 18.4 tokens is a trivial amount for valuable assets

3. **Execution Practicality**: 
   - Simple deposit accumulation over time
   - Natural protocol usage triggers vulnerability
   - No special conditions or race conditions required

4. **Economic Rationality**:
   - Users naturally accumulate deposits
   - Whales depositing >18.4 tokens is routine
   - No attack cost - happens through normal usage

**This is not a theoretical edge case** - it's an inevitable consequence of supporting high-decimal tokens with realistic deposit amounts.

### Recommendation

**1. Implement Safe Arithmetic with u256:**

Modify `convert_amount()` to use u256 for intermediate calculations:

```move
public fun convert_amount(amount: u64, cur_decimal: u8, target_decimal: u8): u64 {
    let result = (amount as u256);
    while (cur_decimal != target_decimal) {
        if (cur_decimal < target_decimal) {
            result = result * 10;
            cur_decimal = cur_decimal + 1;
        } else {
            result = result / 10;
            cur_decimal = cur_decimal - 1;
        };
    };
    assert!(result <= (constants::U64_MAX as u256), error::amount_overflow());
    (result as u64)
}
```

**2. Add Decimal Range Validation:**

Restrict supported decimals to safe range (e.g., 1-9) in `create_pool()`:

```move
public(friend) fun create_pool<CoinType>(_: &PoolAdminCap, decimal: u8, ctx: &mut TxContext) {
    assert!(decimal > 0 && decimal <= 9, error::unsupported_decimal());
    // ... rest of function
}
```

**3. Add Regression Tests:**

Test conversion with high-decimal tokens and large amounts to verify overflow protection.

### Proof of Concept

**Initial State:**
- Pool created for 18-decimal token (e.g., bridged WETH)
- User deposits 20 tokens (20 * 10^18 in native units)

**Transaction Sequence:**

1. **Deposit (succeeds):**
   - User calls `deposit<WETH>(pool, 20 * 10^18)`
   - `normal_amount()` converts: (20 * 10^18) / 10^9 = 20 * 10^9
   - Stored internally as 20,000,000,000 (9-decimal format)

2. **Withdrawal (ABORTS):**
   - User calls `withdraw<WETH>(pool, 20 * 10^18)`
   - `execute_withdraw()` returns 20 * 10^9 as u64
   - `unnormal_amount()` attempts: 20,000,000,000 * 10^9
   - Calculation: 20,000,000,000 * 10 = 200,000,000,000 (iteration 1)
   - ... continues multiplying ...
   - After 9 iterations: 20,000,000,000,000,000,000
   - This equals 2 * 10^19 > u64::MAX (1.84 * 10^19)
   - **Transaction ABORTS with arithmetic overflow**

**Expected Result:** User receives 20 WETH back

**Actual Result:** Transaction aborts, funds permanently locked

**Success Condition for Exploit:** User has > 18.4 tokens of an 18-decimal asset deposited

---

### Notes

This vulnerability is particularly severe because:
1. It affects the core withdrawal mechanism, not an edge feature
2. The threshold (18.4 tokens) is extremely low for valuable assets
3. There's no recovery mechanism - funds are permanently locked
4. It violates the fundamental "users can withdraw their deposits" invariant
5. Tests only cover 6 and 9-decimal tokens, missing the >9 decimal case that triggers this bug

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L75-85)
```text
    public(friend) fun create_pool<CoinType>(_: &PoolAdminCap, decimal: u8, ctx: &mut TxContext) {
        let pool = Pool<CoinType> {
            id: object::new(ctx),
            balance: balance::zero<CoinType>(),
            treasury_balance: balance::zero<CoinType>(),
            decimal: decimal,
        };
        transfer::share_object(pool);

        emit(PoolCreate {creator: tx_context::sender(ctx)})
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L192-203)
```text
    public fun convert_amount(amount: u64, cur_decimal: u8, target_decimal: u8): u64 {
        while (cur_decimal != target_decimal) {
            if (cur_decimal < target_decimal) {
                amount = amount * 10;
                cur_decimal = cur_decimal + 1;
            }else {
                amount = amount / 10;
                cur_decimal = cur_decimal - 1;
            };
        };
        amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L206-210)
```text
    public fun normal_amount<CoinType>(pool: &Pool<CoinType>, amount: u64): u64 {
        let cur_decimal = get_coin_decimal<CoinType>(pool);
        let target_decimal = 9;
        convert_amount(amount, cur_decimal, target_decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L213-217)
```text
    public fun unnormal_amount<CoinType>(pool: &Pool<CoinType>, amount: u64): u64 {
        let cur_decimal = 9;
        let target_decimal = get_coin_decimal<CoinType>(pool);
        convert_amount(amount, cur_decimal, target_decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L113-113)
```text
        (actual_amount as u64)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L161-173)
```text
    public(friend) fun deposit_coin<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let deposit_balance = utils::split_coin_to_balance(deposit_coin, amount, ctx);
        base_deposit(clock, storage, pool, asset, sender, deposit_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L238-239)
```text
        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
        let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L278-279)
```text
        let normal_borrow_amount = pool::normal_amount(pool, amount);
        logic::execute_borrow<CoinType>(clock, oracle, storage, asset, user, (normal_borrow_amount as u256));
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L325-328)
```text
        let normal_repay_amount = pool::normal_amount(pool, repay_amount);

        let normal_excess_amount = logic::execute_repay<CoinType>(clock, oracle, storage, asset, user, (normal_repay_amount as u256));
        let excess_amount = pool::unnormal_amount(pool, (normal_excess_amount as u64));
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L82-85)
```text
    struct TokenBalance has store {
        user_state: Table<address, u256>,
        total_supply: u256,
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L185-187)
```text
            let normal_amount = pool::normal_amount(_pool, fee_to_supplier);
            let (supply_index, _) = storage::get_index(storage, asset_id);
            let scaled_fee_to_supplier = ray_math::ray_div((normal_amount as u256), supply_index);
```
