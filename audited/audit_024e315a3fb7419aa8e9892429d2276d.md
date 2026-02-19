### Title
Treasury Balance Inflation Through Unbalanced Tiny Balance Transfer

### Summary
The `execute_withdraw()` function in `lending_core::logic` credits tiny user balances (≤1000 units) to the treasury without first deducting them from the user's account, violating conservation of funds. This allows treasury_balance to be inflated beyond actual fees collected, corrupting protocol accounting and enabling potential fund extraction through treasury withdrawal operations.

### Finding Description

The vulnerability exists in the withdrawal flow where tiny balances are transferred to treasury. [1](#0-0) 

After decreasing the user's balance by `actual_amount`, the code checks if a tiny remainder exists. [2](#0-1) 

The critical issue is that `storage::increase_treasury_balance()` is called with the tiny balance amount, but there is no corresponding `decrease_supply_balance()` call to remove this amount from the user's account. The `increase_treasury_balance()` function is a friend-only function that simply adds to the treasury balance. [3](#0-2) 

The user's balance was only decreased by `actual_amount` at line 90, meaning after that operation, the user still holds `token_amount - actual_amount` units. When this tiny remainder is added to the treasury without being subtracted from the user, it exists in both places simultaneously.

The `decrease_supply_balance()` function properly converts actual amounts to scaled amounts and decreases both user balance and total supply. [4](#0-3) 

However, this critical deduction step is missing for the tiny balance transfer to treasury.

### Impact Explanation

**Direct Fund Impact:**
- Treasury balance becomes inflated beyond actual fees collected from the protocol
- The total supply balance increases without corresponding deposits, breaking the fundamental accounting invariant
- Each withdrawal leaving a tiny balance adds phantom funds to the system
- Treasury withdrawal operations using `withdraw_treasury()` will reference this inflated balance, potentially allowing extraction of funds that don't exist in the pool

**Quantified Damage:**
- For every withdrawal leaving ≤1000 units, the treasury gains up to 1000 units while the user retains those same units
- An attacker can repeatedly deposit and partially withdraw to accumulate inflated treasury balance
- With 1000 operations, an attacker could inflate treasury_balance by up to 1,000,000 units (1000 * 1000)

**Affected Parties:**
- Protocol treasury accounting becomes unreliable
- Future treasury withdrawals may fail when attempting to withdraw inflated balances
- Legitimate suppliers/lenders have diluted claims as phantom balances exist
- Protocol governance decisions based on treasury balance will be incorrect

### Likelihood Explanation

**Reachable Entry Point:**
The `execute_withdraw()` function is callable through the public lending interface, requiring only a valid user withdrawal request. [5](#0-4) 

**Attack Complexity:**
- Low complexity: Simply deposit funds and withdraw in amounts that leave tiny balances
- No special permissions required beyond normal user operations
- Can be executed repeatedly in a single transaction or across multiple transactions

**Feasible Preconditions:**
- Attacker needs sufficient capital to deposit (any amount works)
- Must withdraw amounts that leave remainders ≤1000 units
- Example: Deposit 10,000 units, withdraw 9,500 units → 500 unit remainder goes to treasury while staying in user account

**Economic Rationality:**
- Attack cost is only transaction fees
- Direct benefit is inflated treasury balance which could be exploited through:
  - Governance manipulation based on treasury size
  - Future vulnerabilities in treasury withdrawal logic
  - Corrupted protocol metrics affecting integrations

**Detection Constraints:**
- No event explicitly tracks this double-counting
- Treasury balance increases appear legitimate
- User balances retain the tiny amounts, which may go unnoticed

### Recommendation

**Immediate Fix:**
Add a `decrease_supply_balance()` call before crediting the tiny balance to treasury:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let tiny_amount = token_amount - actual_amount;
        // NEW: Decrease user balance before crediting treasury
        decrease_supply_balance(storage, asset, user, tiny_amount);
        storage::increase_treasury_balance(storage, asset, tiny_amount);
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

**Invariant Checks:**
- Add assertion that `total_supply = sum(user_balances) + treasury_balance + borrow_balance`
- Emit event when tiny balances are transferred to treasury for audit trail
- Add test case verifying user balance reaches zero when tiny balance goes to treasury

**Regression Testing:**
- Test withdrawal leaving exactly 1000 units
- Test withdrawal leaving 999 units  
- Test withdrawal leaving 1001 units (should not trigger tiny balance transfer)
- Verify treasury balance and user balance sum correctly in all cases

### Proof of Concept

**Initial State:**
- User deposits 10,100 tokens to reserve
- Supply index = 1.0 (for simplicity)
- User's scaled balance = 10,100
- Treasury balance = 0

**Transaction Steps:**

1. User calls withdraw for 10,000 tokens
2. `execute_withdraw()` processes:
   - `token_amount = 10,100` (user's full balance)
   - `actual_amount = min(10,000, 10,100) = 10,000`
   - `decrease_supply_balance(storage, asset, user, 10,000)` → user's balance becomes 100
   - Condition `token_amount > actual_amount` is true (10,100 > 10,000)
   - Condition `token_amount - actual_amount <= 1000` is true (100 ≤ 1000)
   - `storage::increase_treasury_balance(storage, asset, 100)` → treasury gains 100
   - **NO corresponding decrease of user balance by 100**

**Expected Result:**
- User balance: 0 (all funds either withdrawn or transferred to treasury)
- Treasury balance: 100
- Total accounted: 100

**Actual Result:**
- User balance: 100 (still holds the tiny amount)
- Treasury balance: 100 (gained the same tiny amount)
- Total accounted: 200 (inflated by 100)

**Success Condition:**
Query user balance and treasury balance after withdrawal - their sum exceeds the original deposit amount, proving funds were duplicated rather than transferred.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-75)
```text
    public(friend) fun execute_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256 // e.g. 100USDT -> 100000000000
    ): u64 {
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L334-338)
```text
    fun decrease_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::decrease_supply_balance(storage, asset, user, scaled_amount)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L565-568)
```text
    public(friend) fun increase_treasury_balance(storage: &mut Storage, asset: u8, amount: u256) {
        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.treasury_balance = reserve.treasury_balance + amount;
    }
```
