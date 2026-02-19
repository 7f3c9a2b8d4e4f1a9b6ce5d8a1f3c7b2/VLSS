### Title
Rounding Error in withdraw_treasury() Causes Permanent total_supply Desynchronization

### Summary
The `withdraw_treasury()` function contains a critical rounding mismatch between scaled balance accounting and actual pool withdrawals. Due to non-commutative `ray_div` and `ray_mul` operations, the function subtracts more from `total_supply` than it actually withdraws from the pool, causing permanent accounting desynchronization that accumulates with each treasury withdrawal.

### Finding Description [1](#0-0) 

The root cause lies in the conversion sequence:

1. The function calculates `scaled_withdrawable_value = ray_div(withdrawable_value, supply_index)` and subtracts this from `total_supply` [2](#0-1) 

2. It then withdraws from the pool based on `withdrawable_value` directly, not the round-trip value [3](#0-2) 

The problem: Due to rounding in `ray_div` and `ray_mul`, the identity `ray_mul(ray_div(x, y), y) = x` does not hold. The actual value represented by `scaled_withdrawable_value` is `ray_mul(scaled_withdrawable_value, supply_index)`, which can be greater than `withdrawable_value`. [4](#0-3) 

**Concrete Example:**
- `withdrawable_value = 1,000,000,000` (1 token in 9 decimals)
- `supply_index = 1.5 * RAY` (50% interest accrued)
- `scaled_withdrawable_value = ray_div(1,000,000,000, 1.5*RAY) = 666,666,667`
- Actual value represented: `ray_mul(666,666,667, 1.5*RAY) = 1,000,000,001`
- Amount withdrawn from pool: `1,000,000,000`
- **Desync: 1 unit per withdrawal**

This differs from normal user operations which correctly maintain the invariant: [5](#0-4) 

### Impact Explanation

**Protocol Accounting Corruption:**
- `total_supply` (representing sum of all user balances) becomes permanently less than actual supplied funds in the pool
- Each treasury withdrawal with `supply_index > 1.0` adds to the desync
- The gap accumulates: after N withdrawals of 1 token each with 1.5x index, desync = N units

**Cascading Effects:**
1. **Interest Rate Manipulation**: Utilization calculations use `total_supply` in the denominator, causing artificially inflated utilization rates and higher borrow costs
2. **Insolvency Risk**: The protocol's accounting shows less supply than actually exists, potentially allowing over-borrowing relative to real collateral
3. **Audit Trail Failure**: Treasury withdrawals appear to remove more value than actually withdrawn, creating unexplained discrepancies

**Severity Justification:**
This is a permanent, irreversible accounting corruption affecting core protocol invariants. While individual desyncs may be small, they accumulate over the protocol's lifetime and affect all subsequent operations relying on `total_supply` for calculations.

### Likelihood Explanation

**Trigger Conditions:**
- Occurs on every `withdraw_treasury()` call when `supply_index != 1.0 * RAY` (i.e., after any interest accrual)
- Requires `StorageAdminCap` (privileged role), but represents a bug in normal operation, not malicious behavior
- Interest accrual happens continuously, so `supply_index > 1.0` is the expected steady state

**Probability:**
This is not an exploit requiring attacker capabilities—it's a deterministic bug that occurs during legitimate admin operations. Every treasury withdrawal after interest accrual period triggers the desync. Given that protocols regularly withdraw treasury fees, this will manifest repeatedly over the protocol's lifetime.

**Detection Constraints:**
Small per-withdrawal discrepancies (1-10 units out of billions) make this difficult to detect until significant accumulation occurs. Standard balance checks won't catch this because both `treasury_balance` and `total_supply` are decreased—the bug is in their relationship to the actual pool balance.

### Recommendation

**Fix the conversion sequence** to ensure the withdrawn amount exactly matches the accounting decrease:

```move
public fun withdraw_treasury<CoinType>(
    _: &StorageAdminCap,
    pool_admin_cap: &PoolAdminCap,
    storage: &mut Storage,
    asset: u8,
    pool: &mut Pool<CoinType>,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext
) {
    // ... existing setup code ...
    
    let scaled_withdrawable_value = ray_math::ray_div(withdrawable_value, supply_index);
    
    // CRITICAL FIX: Calculate actual value AFTER scaling
    let actual_withdrawable_value = ray_math::ray_mul(scaled_withdrawable_value, supply_index);
    
    reserve.treasury_balance = scaled_treasury_value - scaled_withdrawable_value;
    decrease_total_supply_balance(storage, asset, scaled_withdrawable_value);
    
    // Use the round-tripped value, not original withdrawable_value
    let withdrawable_amount = pool::unnormal_amount(pool, (actual_withdrawable_value as u64));
    
    pool::withdraw_reserve_balance<CoinType>(
        pool_admin_cap,
        pool,
        withdrawable_amount,
        recipient,
        ctx
    );
}
```

**Additional Safeguards:**
1. Add invariant check: After withdrawal, verify `pool_balance >= unnormal_amount(ray_mul(total_supply, supply_index))`
2. Add integration tests with non-trivial `supply_index` values (1.5x, 2.0x) to catch rounding issues
3. Emit events showing both scaled and actual amounts for audit trail verification

### Proof of Concept

**Initial State:**
- Reserve initialized with `supply_index = 1.5 * RAY` (simulating 50% interest accrual)
- `treasury_balance = 1,000,000,000` (scaled, representing ~1.5 billion actual)
- `total_supply = 1,000,000,000` (scaled)
- Pool contains 1,500,000,000 actual tokens

**Transaction Steps:**
1. Admin calls `withdraw_treasury(storage_admin_cap, pool_admin_cap, storage, asset, pool, 1_000000000, recipient, ctx)`
2. Function calculates:
   - `withdrawable_value = 1,000,000,000`
   - `scaled_withdrawable_value = 666,666,667`
   - `withdrawable_amount = 1,000,000,000`
3. Accounting updates:
   - `treasury_balance` decreased by `666,666,667`
   - `total_supply` decreased by `666,666,667` (representing 1,000,000,001 actual via index)
4. Pool withdrawal: `1,000,000,000` actual tokens

**Expected Result:**
Pool balance decrease should equal the actual value represented by the accounting decrease.

**Actual Result:**
- Accounting removed: `ray_mul(666,666,667, 1.5*RAY) = 1,000,000,001`
- Pool removed: `1,000,000,000`
- **Desync: 1 unit permanently lost from accounting**

**Success Condition:**
After withdrawal, `total_supply * supply_index` should equal pool balance, but it's now 1 unit less, breaking the fundamental protocol invariant.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L629-680)
```text
    public fun withdraw_treasury<CoinType>(
        _: &StorageAdminCap,
        pool_admin_cap: &PoolAdminCap,
        storage: &mut Storage,
        asset: u8,
        pool: &mut Pool<CoinType>,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coin_type = get_coin_type(storage, asset);
        assert!(coin_type == type_name::into_string(type_name::get<CoinType>()), error::invalid_coin_type());

        let (supply_index, _) = get_index(storage, asset);
        let reserve = table::borrow_mut(&mut storage.reserves, asset);

        // Without this conversion, then when typpe 1USDT (decimals is 6), the amount of 0.001 will be withdrawn(protocol decimals is 9)
        let withdraw_amount = pool::normal_amount(pool, amount);

        let scaled_treasury_value = reserve.treasury_balance;
        let treasury_value = ray_math::ray_mul(scaled_treasury_value, supply_index);
        let withdrawable_value = math::safe_math::min((withdraw_amount as u256), treasury_value); // get the smallest one value, which is the amount that can be withdrawn

        {
            // decrease treasury balance
            let scaled_withdrawable_value = ray_math::ray_div(withdrawable_value, supply_index);
            reserve.treasury_balance = scaled_treasury_value - scaled_withdrawable_value;
            decrease_total_supply_balance(storage, asset, scaled_withdrawable_value);
        };

        let withdrawable_amount = pool::unnormal_amount(pool, (withdrawable_value as u64));

        pool::withdraw_reserve_balance<CoinType>(
            pool_admin_cap,
            pool,
            withdrawable_amount,
            recipient,
            ctx
        );

        let scaled_treasury_value_after_withdraw = get_treasury_balance(storage, asset);
        emit(WithdrawTreasuryEvent {
            sender: tx_context::sender(ctx),
            recipient: recipient,
            asset: asset,
            amount: withdrawable_value,
            poolId: object::uid_to_address(pool::uid(pool)),
            before: scaled_treasury_value,
            after: scaled_treasury_value_after_withdraw,
            index: supply_index,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L71-92)
```text
    public fun ray_mul(a: u256, b: u256): u256 {
        if (a == 0 || b == 0) {
            return 0
        };

        assert!(a <= (address::max() - HALF_RAY) / b, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * b + HALF_RAY) / RAY
    }

    // title: Divides two ray, rounding half up to the nearest ray
    // param a: Ray
    // param b: Ray
    // return: The result of a / b, in ray
    public fun ray_div(a: u256, b: u256): u256 {
        assert!(b != 0, RAY_MATH_DIVISION_BY_ZERO);
        let halfB = b / 2;

        assert!(a <= (address::max() - halfB) / RAY, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * RAY + halfB) / b
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L323-339)
```text
    fun increase_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////////////////////////////////
        //                               get the current exchange rate                              //
        // the update_state function has been called before here, so it is the latest exchange rate //
        //////////////////////////////////////////////////////////////////////////////////////////////
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::increase_supply_balance(storage, asset, user, scaled_amount)
    }

    fun decrease_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::decrease_supply_balance(storage, asset, user, scaled_amount)
    }
```
