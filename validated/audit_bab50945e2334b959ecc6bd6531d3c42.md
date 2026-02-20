# Audit Report

## Title
Division by Zero DoS in Flash Loan Repayment When No Depositors Exist

## Summary
The flash loan repayment mechanism in the Navi lending protocol dependency unconditionally attempts to distribute supplier fees through division by `total_supply`, causing transaction abortion when no depositors exist. This creates a complete DoS condition for flash loan functionality during initial asset deployment or after full user withdrawal.

## Finding Description

The vulnerability exists in the flash loan repayment flow's fee distribution logic. When a flash loan is repaid, the system attempts to distribute supplier fees by calling `cumulate_to_supply_index()`, which performs division by the reserve's `total_supply` without checking if any depositors exist.

The execution path is:
1. User calls `flash_repay_with_ctx()` [1](#0-0) 
2. This invokes `flash_loan::repay()` which unconditionally calls fee distribution [2](#0-1) 
3. The `cumulate_to_supply_index()` function retrieves `total_supply` and performs `ray_div(amount, total_supply)` [3](#0-2) 
4. The `ray_div()` function explicitly asserts the divisor is non-zero, causing a panic with error code 1103 [4](#0-3) 

The root architectural issue is that pool balance (flash loan liquidity source) is independent from storage `total_supply` (depositor balance tracking). When reserves are initialized, `total_supply` starts at zero [5](#0-4)  and only increases through user deposits via the lending protocol.

Flash loan issuance validates loan bounds and pool liquidity but does not verify depositor existence [6](#0-5) , allowing loans to be issued even when `total_supply = 0`.

## Impact Explanation

This vulnerability causes complete denial-of-service for flash loan functionality under realistic operational conditions:

- **Operational Impact**: All flash loan repayment transactions abort with error 1103 when `total_supply = 0`
- **Affected Parties**: Flash loan users cannot complete transactions; protocol loses flash loan fee revenue
- **Persistence**: The DoS condition persists until at least one user makes a deposit to the lending protocol
- **Critical Periods**: Affects new asset launches, post-market-stress scenarios with full withdrawals, and initial protocol deployment

The severity is high because this is a complete functional DoS of a core DeFi primitive (flash loans) that occurs under legitimate, non-adversarial conditions.

## Likelihood Explanation

The vulnerability is highly likely to occur in practice:

**Reachable Entry Points**: Flash loan functions are publicly accessible [7](#0-6) 

**Feasible Preconditions**:
1. Pool has liquidity (admin-funded or residual from previous activity)
2. No current depositors exist (`total_supply = 0`)
3. Occurs naturally during:
   - Initial protocol deployment when pools are pre-funded before lending activity
   - Market stress causing all users to fully withdraw
   - New asset launches with pool liquidity but no immediate depositor adoption

**Execution Practicality**: Requires no special permissions, follows standard flash loan workflow (loan → logic → repay), and produces deterministic error 1103 with no economic attack cost beyond standard flash loan parameters.

## Recommendation

Add a check in `cumulate_to_supply_index()` to handle the zero `total_supply` case gracefully:

```move
public(friend) fun cumulate_to_supply_index(storage: &mut Storage, asset: u8, amount: u256) {
    let (total_supply, _) = storage::get_total_supply(storage, asset);
    
    // Guard against division by zero when no depositors exist
    if (total_supply == 0) {
        // Option 1: Skip fee distribution (fees can accumulate in treasury)
        return
        // Option 2: Direct to treasury instead
        // storage::increase_treasury_balance(storage, asset, amount);
        // return
    };
    
    let (supply_index, borrow_index) = storage::get_index(storage, asset);
    let last_update_at = storage::get_last_update_timestamp(storage, asset);
    
    let result = ray_math::ray_mul(
        ray_math::ray_div(amount, total_supply) + ray_math::ray(),
        supply_index,
    );
    
    storage::update_state(storage, asset, borrow_index, result, last_update_at, 0);
    emit_state_updated_event(storage, asset, @0x0);
}
```

Alternatively, add validation in `flash_loan::repay()` before calling `cumulate_to_supply_index()` to check if `total_supply > 0`.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize a reserve with `total_supply = 0`
2. Fund the pool with liquidity (bypassing deposit logic)
3. Take a flash loan (succeeds because pool has liquidity)
4. Attempt to repay the flash loan
5. Observe transaction abort with error 1103 due to division by zero

The PoC would confirm that flash loan repayment is impossible when no depositors exist, despite pool liquidity being available.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-549)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }

    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }

    public fun flash_repay_with_ctx<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, receipt: FlashLoanReceipt<CoinType>, repay_balance: Balance<CoinType>, ctx: &mut TxContext): Balance<CoinType> {
        base_flash_repay<CoinType>(clock, storage, pool, receipt, tx_context::sender(ctx), repay_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L148-150)
```text
        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L189-189)
```text
            logic::cumulate_to_supply_index(storage, asset_id, scaled_fee_to_supplier);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L304-309)
```text
        let (total_supply, _) = storage::get_total_supply(storage, asset);
        let (supply_index, borrow_index) = storage::get_index(storage, asset);
        let last_update_at = storage::get_last_update_timestamp(storage, asset);

        let result = ray_math::ray_mul(
            ray_math::ray_div(amount, total_supply) + ray_math::ray(), // (amount / totalSupply) + 1
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L85-86)
```text
    public fun ray_div(a: u256, b: u256): u256 {
        assert!(b != 0, RAY_MATH_DIVISION_BY_ZERO);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L206-209)
```text
            supply_balance: TokenBalance {
                user_state: table::new<address, u256>(ctx),
                total_supply: 0,
            },
```
