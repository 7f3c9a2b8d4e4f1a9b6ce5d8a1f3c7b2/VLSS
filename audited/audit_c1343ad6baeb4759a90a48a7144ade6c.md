### Title
Withdraw Accounting Corruption Due to Decimal Rounding - User Balance Decreased While Zero Coins Transferred

### Summary
In `base_withdraw()`, when `normal_withdrawable_amount` is less than the decimal conversion threshold, `pool::unnormal_amount()` rounds down to zero due to integer division, causing the protocol to decrease user balances in storage while transferring zero coins from the pool. This creates an accounting mismatch where funds remain locked in the pool but are no longer tracked as belonging to any user.

### Finding Description

The vulnerability exists in the withdraw flow where accounting updates occur before decimal rounding:

**Execution Flow in base_withdraw():** [1](#0-0) 

The amount is first normalized to 9 decimals, then: [2](#0-1) 

Inside `execute_withdraw()`, the **critical accounting update occurs**: [13](#0-12) 

The user's balance is decreased by `actual_amount` in normalized form, then the function returns this amount: [7](#0-6) 

**Back in base_withdraw(), the rounding issue occurs:** [3](#0-2) 

The `unnormal_amount()` function performs integer division: [8](#0-7) 

Which uses `convert_amount()` that divides repeatedly for decimal reduction: [9](#0-8) 

For coins with 6 decimals, converting from 9 to 6 requires dividing by 1000. Any `normal_withdrawable_amount < 1000` results in `withdrawable_amount = 0`.

**Zero withdrawal is explicitly allowed:** [10](#0-9) 

**Why Existing Protections Fail:**

The validation only checks non-zero amounts in normalized form, not after conversion: [11](#0-10) 

The dust handling logic only addresses remaining balances after withdrawal, not the withdrawn amount itself: [12](#0-11) 

**Root Cause**: Accounting is updated in `logic::execute_withdraw()` with the full normalized amount, but the actual coin transfer in `pool::withdraw_balance()` uses the rounded-down amount. These values diverge when integer division rounds to zero.

### Impact Explanation

**Direct Harm:**
1. **User Fund Loss**: Users lose deposited collateral without receiving any coins in return
2. **Protocol Accounting Corruption**: The pool contains coins no longer tracked as belonging to any user, creating "phantom funds"
3. **Systematic Issue**: Affects all coins with decimals < 9 (common for USDC, USDT at 6 decimals)

**Quantified Impact:**
- For 6-decimal coins: Any withdrawal where `normal_withdrawable_amount < 1000` transfers 0 coins
- 999 normalized units ≈ 0.000000999 in value representation
- User balance decreased by 999, but receives 0 coins
- The 999 units remain in pool but are untracked in storage

**Who is Affected:**
- Users with dust/small balances
- Users where `actual_amount = min(requested, balance)` yields sub-threshold amounts
- Any user withdrawing from pools with coins having < 9 decimals

**Severity**: HIGH - Direct financial loss combined with protocol accounting corruption violating fundamental custody invariants.

### Likelihood Explanation

**Attacker Capabilities:**
- No special capabilities required - any regular user can trigger
- Can occur unintentionally during normal operations
- Natural occurrence with dust balances from rounding or interest accrual

**Attack Complexity:**
- Minimal: Simply call withdraw when balance < rounding threshold
- Triggerable by:
  - Withdrawing dust amounts directly
  - Partial withdrawals where available < requested
  - Natural accumulation of sub-threshold interest/rewards

**Feasibility Conditions:**
- Requires coins with decimals < 9 (standard: USDC=6, USDT=6, WBTC=8)
- User has balance resulting in `normal_withdrawable_amount < 10^(9-decimal)`
- No trusted role compromise needed
- Executable via public entry functions

**Economic Rationality:**
While individual losses may be small (< $0.001 for amounts < 1000 normalized units), the cumulative protocol-level accounting corruption is material and violates custody invariants.

**Detection Constraints:**
- Transactions complete successfully without errors
- Events emit `withdrawable_amount=0` but appear normal
- Users may not notice micro-amounts disappearing
- Accumulates silently across many users

**Probability**: HIGH - Will naturally occur as users accumulate dust or make small withdrawals from sub-9-decimal asset pools.

### Recommendation

**Exact Code-Level Mitigation:**

Add validation in `base_withdraw()` after unnormal conversion to prevent zero-amount accounting mismatches:

```move
fun base_withdraw<CoinType>(...): Balance<CoinType> {
    // ... existing code ...
    
    let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
    
    // NEW: Ensure rounding didn't zero out a non-zero accounting decrease
    assert!(
        normal_withdrawable_amount == 0 || withdrawable_amount > 0,
        error::withdrawal_rounds_to_zero()
    );
    
    let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
    // ... rest of function
}
```

**Alternative Approaches:**
1. Modify `execute_withdraw()` to validate post-conversion amounts before accounting updates
2. Implement automatic dust sweeping to treasury when balances fall below rounding thresholds
3. Enforce minimum withdrawal amounts that account for decimal conversion losses

**Invariant Checks:**
- Assert: `(normalized_amount == 0) ⟺ (unnormalized_amount == 0)`
- Assert: Pool balance decrease equals storage balance decrease (accounting consistency)

**Test Cases:**
1. Withdraw with balance = 999 normalized units for 6-decimal coin → should revert
2. Withdraw with balance = 1-999 for various decimals < 9 → should revert or handle properly
3. Verify accounting: user balance decrease = actual coins transferred
4. Test dust handling integrates correctly with minimum thresholds

### Proof of Concept

**Initial State:**
- Pool created with USDC (6 decimals)
- User has 999 normalized units balance (e.g., from previous operations leaving dust)

**Transaction Steps:**

1. User calls withdraw requesting full balance or any amount
2. `base_withdraw()` executes:
   - Normalizes request amount
   - Calls `logic::execute_withdraw()` which:
     - Calculates `actual_amount = min(999, token_amount) = 999`
     - **Calls `decrease_supply_balance(storage, asset, user, 999)`** ← User balance now 0
     - Returns 999
   - Converts back: `unnormal_amount(999)`
     - `convert_amount(999, 9, 6)` = 999 ÷ 1000 = 0 (integer division)
   - Calls `pool::withdraw_balance(pool, 0, user)` ← Returns empty balance

**Expected vs Actual:**
- **Expected**: User balance decreased by 999 AND receives corresponding coins, OR transaction reverts
- **Actual**: User storage balance decreased by 999 BUT receives 0 coins, pool retains the funds

**Observable Corruption:**
- User's storage balance: 0 (decreased from 999)
- User's received coins: 0
- Pool coin balance: Unchanged (still contains ~999 units worth)
- **Accounting gap**: 999 normalized units exist in pool but belong to no one in storage

**Success Condition**: Transaction completes successfully with `WithdrawEvent{amount: 0}` emitted, user lost ~999 normalized units of value, protocol has untracked funds.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L228-228)
```text
        let normal_withdraw_amount = pool::normal_amount(pool, amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L229-236)
```text
        let normal_withdrawable_amount = logic::execute_withdraw<CoinType>(
            clock,
            oracle,
            storage,
            asset,
            user,
            (normal_withdraw_amount as u256)
        );
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L238-238)
```text
        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L239-239)
```text
        let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L88-90)
```text
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L100-108)
```text
        if (token_amount > actual_amount) {
            if (token_amount - actual_amount <= 1000) {
                // Tiny balance cannot be raised in full, put it to treasury 
                storage::increase_treasury_balance(storage, asset, token_amount - actual_amount);
                if (is_collateral(storage, asset, user)) {
                    storage::remove_user_collaterals(storage, asset, user);
                }
            };
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L113-113)
```text
        (actual_amount as u64)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L126-129)
```text
        if (amount == 0) {
            let _zero = balance::zero<CoinType>();
            return _zero
        };
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L213-217)
```text
    public fun unnormal_amount<CoinType>(pool: &Pool<CoinType>, amount: u64): u64 {
        let cur_decimal = 9;
        let target_decimal = get_coin_decimal<CoinType>(pool);
        convert_amount(amount, cur_decimal, target_decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L35-46)
```text
    public fun validate_withdraw<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_supply_balance >= scale_borrow_balance + amount, error::insufficient_balance())
    }
```
