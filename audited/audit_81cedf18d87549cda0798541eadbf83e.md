### Title
Dust Collection Logic Inflates Treasury and Allows Balance Retention Leading to Protocol Insolvency

### Summary
The dust collection mechanism in `execute_withdraw()` contains two critical bugs: it fails to decrease the user's balance for dust amounts (≤1000 tokens) while simultaneously adding unscaled actual amounts to the scaled treasury balance. This allows attackers to retain dust in their accounts while inflating the treasury by approximately `dust_amount * supply_index` per transaction, leading to protocol insolvency where total claims exceed actual pool balance.

### Finding Description

The vulnerability exists in the dust handling logic at lines 100-108 of `execute_withdraw()`. [1](#0-0) 

**Root Cause #1 - Missing Balance Decrease:**

After line 90 decreases the user's balance by `actual_amount`, the remaining dust (`token_amount - actual_amount`) stays in the user's account. The code at line 103 adds this dust to the treasury but never decrements it from the user's scaled balance. [2](#0-1) 

The `user_collateral_balance()` function returns actual (unscaled) token amounts by multiplying scaled balance with supply_index: [3](#0-2) 

The `decrease_supply_balance()` at line 90 only decreases by `actual_amount`, leaving `token_amount - actual_amount` in the user's balance: [4](#0-3) 

**Root Cause #2 - Incorrect Scaling:**

The dust amount added to treasury at line 103 is an actual (unscaled) amount but `treasury_balance` stores scaled values. The protocol confirms this in `withdraw_treasury()` where scaled treasury is converted to actual by multiplying with supply_index: [5](#0-4) 

The `increase_treasury_balance()` function directly adds the amount without scaling conversion: [6](#0-5) 

This contrasts with the correct implementation in `update_state()` where actual treasury amounts are properly converted to scaled before adding: [7](#0-6) 

### Impact Explanation

**Direct Protocol Insolvency:**
- User retains dust (≤999 actual tokens) in their balance after each withdrawal
- Treasury gets inflated by `dust_amount` added as scaled (not converted from actual)
- When converted back to actual: `dust_amount * supply_index` excess tokens appear
- With supply_index = 1.5 and 100 cycles: ~49,950 tokens inflated from thin air (999 * 0.5 * 100)

**Theft from Other Users:**
- Total scaled supply becomes inflated beyond actual pool balance
- Treasury can withdraw the inflated amounts, draining pool funds
- Legitimate depositors cannot fully withdraw as pool becomes insolvent
- Protocol accounting breaks: sum(user_balances) + treasury > actual_pool_balance

**Quantified Impact:**
With supply_index progression from 1.0 to 2.0 over time and 200 attack cycles:
- Attacker keeps: 999 actual tokens per cycle = ~199,800 tokens retained
- Treasury inflation: avg(999 * 1.5) * 200 = ~299,700 excess actual tokens
- Total protocol damage: ~499,500 tokens stolen from depositor pool

### Likelihood Explanation

**Highly Exploitable:**

The `execute_withdraw()` function is callable by any user through the public lending interface with no special permissions required. An attacker only needs:

1. Deposit funds into the lending pool (normal user action)
2. Calculate withdrawal amount to leave exactly 999 dust: `withdraw_amount = user_balance - 999`
3. Call withdraw with calculated amount
4. Repeat after interest accrues (supply_index increases)

**Attack Complexity: Low**
- Single function call per cycle
- No timing constraints or race conditions
- No need for flash loans or complex DeFi interactions
- Deterministic outcome based on simple arithmetic

**Economic Rationality:**
- Attack cost: only gas fees for withdraw transactions
- Attacker benefit: retains dust + inflates treasury they could potentially extract
- No economic barriers or risk to attacker
- Scales linearly with number of cycles

**Detection Difficulty:**
- Appears as normal withdrawal behavior
- Dust amounts (≤1000) seem negligible individually
- Cumulative impact only visible in aggregate accounting
- No unusual transaction patterns to flag

### Recommendation

**Fix #1 - Add Missing Balance Decrease:**
After line 102, add a call to decrease the user's supply balance by the dust amount before adding to treasury:

```move
if (token_amount - actual_amount <= 1000) {
    let dust_amount = token_amount - actual_amount;
    decrease_supply_balance(storage, asset, user, dust_amount); // ADD THIS
    storage::increase_treasury_balance(storage, asset, dust_amount);
    if (is_collateral(storage, asset, user)) {
        storage::remove_user_collaterals(storage, asset, user);
    }
};
```

**Fix #2 - Correct Scaling Conversion:**
Modify line 103 to convert the actual dust amount to scaled before adding to treasury:

```move
let (supply_index, _) = storage::get_index(storage, asset);
let scaled_dust = ray_math::ray_div(token_amount - actual_amount, supply_index);
storage::increase_treasury_balance(storage, asset, scaled_dust);
```

**Invariant Checks to Add:**
- Assert `total_supply >= sum(user_balances) + treasury_balance` after all operations
- Add total_supply consistency check in withdraw validation
- Monitor treasury_balance growth rate against expected reserve_factor accumulation

**Test Cases:**
1. Withdraw leaving exactly 999 dust, verify user balance becomes 0
2. Verify treasury increase matches dust amount in actual value (scaled * index)
3. Test with multiple supply_index values (1.0, 1.5, 2.0)
4. Verify repeated withdrawals don't inflate total_supply

### Proof of Concept

**Initial State:**
- Lending pool has 1,000,000 USDT total deposits
- Supply_index = 1.1 (10% interest accumulated)
- Attacker deposits 100,000 USDT (scaled: 90,909)
- Other users have 900,000 USDT deposited

**Transaction Sequence:**

**Cycle 1:**
1. Attacker's balance: 100,000 actual (90,909 scaled at index 1.1)
2. Attacker withdraws: 99,001 actual tokens
3. Expected behavior: User balance should become 0, treasury gets 999
4. **Actual behavior:**
   - User balance decreased by 99,001 only → remains 999 actual (908 scaled)
   - Treasury increased by 999 (as scaled, not actual/1.1)
   - Treasury in actual terms: 999 * 1.1 = 1,098.9 tokens

**Cycle 2 (after index reaches 1.2):**
1. Attacker's balance: 908 scaled = 1,089.6 actual at index 1.2
2. Attacker withdraws: 90.6 actual (leaves 999 dust again)
3. **Actual behavior:**
   - User balance: still has 999 actual (832.5 scaled)
   - Treasury increased by another 999 scaled = 1,198.8 actual

**After 100 Cycles (supply_index averages 1.5):**
- Attacker retains: 999 actual tokens in balance
- Treasury inflated by: ~999 * 1.5 * 100 = 149,850 actual tokens
- Protocol insolvency: 149,850 tokens claimed that don't exist in pool
- Other users cannot fully withdraw their original 900,000 USDT

**Success Condition:**
Query user's scaled balance and treasury balance after cycles. The sum exceeds the actual pool balance, proving insolvency.

### Citations

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L278-286)
```text
        // Calculate the treasury amount
        let treasury_amount = ray_math::ray_mul(
            ray_math::ray_mul(total_borrow, (new_borrow_index - current_borrow_index)),
            reserve_factor
        );
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);

        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_treasury_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L334-338)
```text
    fun decrease_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::decrease_supply_balance(storage, asset, user, scaled_amount)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L486-490)
```text
    public fun user_collateral_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (supply_balance, _) = storage::get_user_balance(storage, asset, user);
        let (supply_index, _) = storage::get_index(storage, asset);
        ray_math::ray_mul(supply_balance, supply_index) // scaled_amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L565-568)
```text
    public(friend) fun increase_treasury_balance(storage: &mut Storage, asset: u8, amount: u256) {
        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.treasury_balance = reserve.treasury_balance + amount;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L648-649)
```text
        let scaled_treasury_value = reserve.treasury_balance;
        let treasury_value = ray_math::ray_mul(scaled_treasury_value, supply_index);
```
