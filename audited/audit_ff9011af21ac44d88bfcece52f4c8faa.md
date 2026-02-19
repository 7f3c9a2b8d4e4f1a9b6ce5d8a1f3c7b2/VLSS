### Title
Precision Loss in Decimal Normalization Causes Permanent Fund Leakage in Lending Protocol

### Summary
The lending protocol normalizes all token amounts to 9 decimals for internal accounting, but deposits the full original amount into the pool. For tokens with >9 decimals, integer division during normalization rounds down, causing users to lose dust amounts permanently. This creates a growing discrepancy between the pool's physical balance and the accounted balance, with dust accumulating in the pool but credited to no user.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The `base_deposit()` function deposits the full `deposit_amount` into the pool at line 188, but only credits the user with `normal_deposit_amount` (normalized to 9 decimals) at line 191. The normalization process uses integer division that rounds down: [2](#0-1) 

When `cur_decimal > target_decimal` (9), line 198 performs `amount = amount / 10` repeatedly, losing precision on each division. For an 18-decimal token, up to 999,999,999 units (10^9 - 1) can be lost per deposit.

**Execution Flow:**
1. User deposits amount with original decimals (e.g., 1000000000000000005 for 18 decimals)
2. Full amount deposited to pool: [3](#0-2) 
3. Amount normalized (rounds down to 1000000000): [4](#0-3) 
4. User credited with normalized amount: [5](#0-4) 
5. Lost dust (5 units) remains in pool unaccounted

**Why Protections Fail:** Validation only checks `amount != 0`, not precision loss: [6](#0-5) 

**Same Issue in Other Functions:**
- `base_repay()`: [7](#0-6) 
- `base_borrow()`: [8](#0-7) 
- `base_liquidation_call()`: [9](#0-8) 

### Impact Explanation

**Direct Fund Impact:**
- **Per-transaction loss:** For 18-decimal tokens, up to 999,999,999 units (~10^-9 tokens) lost per deposit/repay/liquidation
- **USD value:** For a $1 token, ~$0.000000001 per transaction
- **Cumulative impact:** Over 1 billion transactions, ~$1,000 accumulated as unaccounted dust in pool
- **Affected users:** All depositors/repayers using tokens with >9 decimals (common for bridged ERC20 tokens)

**Custody Integrity:**
The pool's physical balance diverges from the sum of accounted balances. Interest rate calculations use accounted balances [10](#0-9) , so the dust doesn't affect rates, but the discrepancy creates long-term accounting integrity issues for protocol upgrades, migrations, or audits.

**Permanent Loss:**
Users cannot recover lost dust because withdrawals use the same normalization: [11](#0-10) 

The dust becomes permanently locked in the pool with no mechanism to distribute or recover it.

### Likelihood Explanation

**Certainty:** This occurs deterministically on every deposit/repay/liquidation for tokens with >9 decimals.

**Attacker Capabilities:** None required - this is an inherent design issue affecting all legitimate users. No special permissions or economic capital needed.

**Attack Complexity:** No attack vector - users suffer losses through normal protocol usage.

**Feasibility:** 100% - happens automatically on every affected transaction. Common tokens like USDC (if bridged with 18 decimals), WETH, or other ERC20-style tokens on Sui would trigger this.

**Detection:** Protocol operators can detect accumulating dust by comparing pool's actual balance with calculated accounted balances, but users have no way to prevent or avoid the loss.

### Recommendation

**Immediate Fix:**
1. Modify `base_deposit()` to normalize the amount BEFORE depositing to pool:
```
// Convert FIRST, then deposit only the normalized amount
let normal_deposit_amount = pool::normal_amount(pool, deposit_amount);
let normalized_actual_amount = pool::unnormal_amount(pool, normal_deposit_amount);
let truncated_balance = balance::split(&mut deposit_balance, normalized_actual_amount);
pool::deposit_balance(pool, truncated_balance, user);
// Return excess dust to user
if (balance::value(&deposit_balance) > 0) {
    transfer::public_transfer(coin::from_balance(deposit_balance, ctx), user);
};
```

2. Apply same fix to `base_repay()`, `base_borrow()`, and `base_liquidation_call()`

**Alternative Approach:**
Consider using higher precision for internal accounting (e.g., 18 decimals instead of 9) to accommodate common token standards without precision loss.

**Invariant Checks:**
Add assertion to verify pool balance equals sum of accounted balances (converted to original decimals) within acceptable tolerance.

**Test Cases:**
1. Deposit 1000000000000000001 units of 18-decimal token, verify user credited with full amount (no dust loss)
2. Repay with dust, verify excess includes the dust
3. Multi-operation sequence to verify no cumulative dust accumulation

### Proof of Concept

**Initial State:**
- Pool for 18-decimal token exists
- User has 1000000000000000005 units (1.000000000000000005 tokens)

**Transaction Steps:**
1. User calls `deposit()` with amount = 1000000000000000005
2. `base_deposit()` executes:
   - Line 187: `deposit_amount` = 1000000000000000005
   - Line 188: Pool receives full 1000000000000000005 units
   - Line 190: `normal_deposit_amount` = normal_amount(1000000000000000005) = 1000000000 (9 decimals)
   - Line 191: User credited with 1000000000 (normalized)

3. User attempts to withdraw full balance:
   - User's normalized balance: 1000000000
   - Unnormalized: 1000000000000000000 (18 decimals)
   - User receives: 1000000000000000000

**Expected vs Actual:**
- **Expected:** User deposits X, can withdraw X
- **Actual:** User deposits 1000000000000000005, can only withdraw 1000000000000000000
- **Lost:** 5 units permanently locked in pool, unaccounted for

**Success Condition:**
Pool's `balance::value(&pool.balance)` exceeds the sum of all users' accounted balances (when converted back to original decimals). This discrepancy grows with each deposit/repay operation.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L176-198)
```text
    fun base_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        user: address,
        deposit_balance: Balance<CoinType>,
    ) {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let deposit_amount = balance::value(&deposit_balance);
        pool::deposit_balance(pool, deposit_balance, user);

        let normal_deposit_amount = pool::normal_amount(pool, deposit_amount);
        logic::execute_deposit<CoinType>(clock, storage, asset, user, (normal_deposit_amount as u256));

        emit(DepositEvent {
            reserve: asset,
            sender: user,
            amount: deposit_amount,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L228-239)
```text
        let normal_withdraw_amount = pool::normal_amount(pool, amount);
        let normal_withdrawable_amount = logic::execute_withdraw<CoinType>(
            clock,
            oracle,
            storage,
            asset,
            user,
            (normal_withdraw_amount as u256)
        );

        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
        let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L266-289)
```text
    fun base_borrow<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        user: address,
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let normal_borrow_amount = pool::normal_amount(pool, amount);
        logic::execute_borrow<CoinType>(clock, oracle, storage, asset, user, (normal_borrow_amount as u256));

        let _balance = pool::withdraw_balance(pool, amount, user);
        emit(BorrowEvent {
            reserve: asset,
            sender: user,
            amount: amount
        });

        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L310-343)
```text
    fun base_repay<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        repay_balance: Balance<CoinType>,
        user: address,
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let repay_amount = balance::value(&repay_balance);
        pool::deposit_balance(pool, repay_balance, user);

        let normal_repay_amount = pool::normal_amount(pool, repay_amount);

        let normal_excess_amount = logic::execute_repay<CoinType>(clock, oracle, storage, asset, user, (normal_repay_amount as u256));
        let excess_amount = pool::unnormal_amount(pool, (normal_excess_amount as u64));

        emit(RepayEvent {
            reserve: asset,
            sender: user,
            amount: repay_amount - excess_amount
        });

        if (excess_amount > 0) {
            let _balance = pool::withdraw_balance(pool, excess_amount, user);
            return _balance
        } else {
            let _balance = balance::zero<CoinType>();
            return _balance
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L408-472)
```text
    fun base_liquidation_call<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_balance: Balance<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        executor: address,
        liquidate_user: address
    ): (Balance<DebtCoinType>, Balance<CollateralCoinType>) {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let debt_amount = balance::value(&debt_balance);
        pool::deposit_balance(debt_pool, debt_balance, executor);

        let normal_debt_amount = pool::normal_amount(debt_pool, debt_amount);
        let (
            normal_obtainable_amount,
            normal_excess_amount,
            normal_treasury_amount
        ) = logic::execute_liquidate<DebtCoinType, CollateralCoinType>(
            clock,
            oracle,
            storage,
            liquidate_user,
            collateral_asset,
            debt_asset,
            (normal_debt_amount as u256)
        );

        // The treasury balance
        let treasury_amount = pool::unnormal_amount(collateral_pool, (normal_treasury_amount as u64));
        pool::deposit_treasury(collateral_pool, treasury_amount);

        // The total collateral balance = collateral + bonus
        let obtainable_amount = pool::unnormal_amount(collateral_pool, (normal_obtainable_amount as u64));
        let obtainable_balance = pool::withdraw_balance(collateral_pool, obtainable_amount, executor);

        // The excess balance
        let excess_amount = pool::unnormal_amount(debt_pool, (normal_excess_amount as u64));
        let excess_balance = pool::withdraw_balance(debt_pool, excess_amount, executor);

        let collateral_oracle_id = storage::get_oracle_id(storage, collateral_asset);
        let debt_oracle_id = storage::get_oracle_id(storage, debt_asset);

        let (_, collateral_price, _) = oracle::get_token_price(clock, oracle, collateral_oracle_id);
        let (_, debt_price, _) = oracle::get_token_price(clock, oracle, debt_oracle_id);

        emit(LiquidationEvent {
            sender: executor,
            user: liquidate_user,
            collateral_asset: collateral_asset,
            collateral_price: collateral_price,
            collateral_amount: obtainable_amount + treasury_amount,
            treasury: treasury_amount,
            debt_asset: debt_asset,
            debt_price: debt_price,
            debt_amount: debt_amount - excess_amount,
        });

        return (excess_balance, obtainable_balance)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L15-33)
```text
    public fun validate_deposit<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        // e.g. Pool total collateral of 100ETH
        let (supply_balance, _) = storage::get_total_supply(storage, asset);
        let (current_supply_index, _) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);

        // e.g. The pool has a maximum collateral capacity of 10000 ETH
        let supply_cap_ceiling = storage::get_supply_cap_ceiling(storage, asset);

        // e.g. estimate_supply
        let estimate_supply = (scale_supply_balance + amount) * ray_math::ray();

        // e.g. supply_cap_ceiling >= estimate_supply?
        assert!(supply_cap_ceiling >= estimate_supply, error::exceeded_maximum_deposit_cap());
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L10-22)
```text
    public fun caculate_utilization(storage: &mut Storage, asset: u8): u256 {
        let (total_supply, total_borrows) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);
        let scale_borrow_amount = ray_math::ray_mul(total_borrows, current_borrow_index);
        let scale_supply_amount = ray_math::ray_mul(total_supply, current_supply_index);

        if (scale_borrow_amount == 0) {
            0
        } else {
            // Equation: utilization = total_borrows / (total_cash + total_borrows)
            ray_math::ray_div(scale_borrow_amount, scale_supply_amount)
        }
    }
```
