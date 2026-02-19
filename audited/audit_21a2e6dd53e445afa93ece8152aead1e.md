### Title
Suilend Staker Withdrawal and Fee Claim DoS Due to Unaccounted Liquid Staking Redemption Fees

### Summary
The `unstake_n_sui()` function in the Suilend staker calculates the LST amount to redeem expecting to receive at least `sui_amount_out` SUI, but does not account for redemption fees applied by `liquid_staking::redeem()`. When unstake fees are configured (up to 5%), the actual SUI returned is less than expected, causing subsequent `balance::split()` operations in `withdraw()` and `claim_fees()` to abort due to insufficient balance.

### Finding Description

The vulnerability exists in the interaction between `unstake_n_sui()` and its callers: [1](#0-0) 

The `unstake_n_sui()` function calculates the LST amount using ceiling division to ensure at least `sui_amount_out` worth of SUI is requested, then calls `liquid_staking::redeem()`. However, the liquid staking protocol applies unstake fees to redemptions: [2](#0-1) [3](#0-2) 

The `unstake()` function (redeem implementation) deducts fees from the SUI before returning: [4](#0-3) 

After `unstake_n_sui()` joins the reduced SUI amount to `sui_balance`, the caller `withdraw()` attempts to split the full expected amount: [5](#0-4) 

If fees were deducted, line 93 will abort because `sui_balance` has less than `withdraw_amount`.

The same issue affects `claim_fees()`: [6](#0-5) 

### Impact Explanation

**Operational Impact - HIGH Severity:**

1. **Withdrawal DoS**: When Suilend reserves need liquidity and must unstake from the staker, withdrawals will fail if unstake fees are non-zero. This affects:
   - User withdrawals from lending markets
   - Protocol liquidations requiring asset retrieval
   - Any operation calling `reserve::unstake_sui_from_staker()` [7](#0-6) 

2. **Fee Claim DoS**: Staking rewards cannot be claimed when fees are configured, preventing protocol fee collection. [8](#0-7) 

3. **Duration**: The DoS persists as long as unstake fees remain configured in the liquid staking protocol.

4. **Affected Users**: All users and protocols attempting to withdraw from SUI reserves backed by the staker, and protocol fee receivers.

### Likelihood Explanation

**HIGH Likelihood:**

1. **Reachable Entry Point**: The vulnerability triggers through normal Suilend reserve operations - any withdrawal requiring unstaking hits this path. No special privileges needed.

2. **Feasible Preconditions**: Only requires that liquid staking unstake fees be non-zero. The fee configuration allows up to 5% (500 bps), and any non-zero value triggers the issue. [9](#0-8) 

3. **Automatic Triggering**: Not an attack - happens automatically during legitimate operations whenever the reserve's available balance is insufficient and must unstake.

4. **Current State**: If unstake fees are currently configured in the liquid staking protocol used by the staker, the vulnerability is actively affecting operations.

### Recommendation

**Immediate Fix:**

Modify `unstake_n_sui()` to track the actual SUI received and return that amount, allowing callers to handle the shortfall:

```move
fun unstake_n_sui<P: drop>(
    staker: &mut Staker<P>,
    system_state: &mut SuiSystemState,
    sui_amount_out: u64,
    ctx: &mut TxContext,
): u64 {  // Return actual amount received
    if (sui_amount_out == 0) {
        return 0
    };
    
    let before_balance = staker.sui_balance.value();
    
    // ... existing LST calculation and redeem call ...
    
    let actual_received = staker.sui_balance.value() - before_balance;
    actual_received
}
```

Then update callers to use the actual amount:

- In `withdraw()`: Check if actual amount < expected, and either request more or handle partial fulfillment
- In `claim_fees()`: Use actual amount received instead of calculated `excess_sui`

**Alternative Fix:**

Pre-calculate fees and increase the LST redemption amount accordingly:

```move
// Account for max possible fee when calculating LST to redeem
let fee_adjusted_amount = sui_amount_out * 10000 / (10000 - max_unstake_fee_bps);
let lst_to_redeem = calculate_lst_for_sui(fee_adjusted_amount);
```

**Invariant Check:**

Add assertion after redemption:
```move
assert!(staker.sui_balance.value() >= expected_minimum, EInsufficientRedemption);
```

**Test Cases:**
1. Test withdrawal with non-zero unstake fees configured
2. Test claim_fees with various fee percentages (0%, 1%, 5%)
3. Test edge case where fees consume entire redemption amount

### Proof of Concept

**Initial State:**
- Suilend reserve has SUI deposits staked via the staker
- Liquid staking protocol has `unstake_fee_bps = 100` (1% fee)
- Staker has minimal `sui_balance`, most SUI is in `lst_balance`

**Exploit Steps:**

1. User initiates withdrawal of 1000 SUI from Suilend reserve
2. Reserve calls `reserve::unstake_sui_from_staker(liquidity_request)`
3. Function determines `withdraw_amount = 1000` and calls `staker::withdraw(staker, 1000, ...)`
4. `withdraw()` sees `sui_balance < 1000`, calculates `unstake_amount = 1000`
5. Calls `unstake_n_sui(system_state, 1000, ctx)`
6. `unstake_n_sui()` redeems LST for 1000 SUI
7. `liquid_staking::redeem()` deducts 1% fee (10 SUI), returns only 990 SUI
8. `sui_balance` now has 990 SUI
9. `withdraw()` line 93 tries to `split(1000)` from balance with only 990 SUI
10. **Transaction aborts with insufficient balance error**

**Expected Result:**
Withdrawal succeeds, user receives requested SUI

**Actual Result:**
Transaction aborts, withdrawal fails due to arithmetic underflow in balance split operation

**Success Condition:**
Any withdrawal or fee claim operation requiring unstaking fails when unstake fees are configured, demonstrating the DoS condition.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L88-94)
```text
        if (withdraw_amount > staker.sui_balance.value()) {
            let unstake_amount = withdraw_amount - staker.sui_balance.value();
            staker.unstake_n_sui(system_state, unstake_amount, ctx);
        };

        let sui = staker.sui_balance.split(withdraw_amount);
        staker.liabilities = staker.liabilities - sui.value();
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L147-152)
```text
        if (excess_sui > staker.sui_balance.value()) {
            let unstake_amount = excess_sui - staker.sui_balance.value();
            staker.unstake_n_sui(system_state, unstake_amount, ctx);
        };

        let sui = staker.sui_balance.split(excess_sui);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L163-189)
```text
    fun unstake_n_sui<P: drop>(
        staker: &mut Staker<P>,
        system_state: &mut SuiSystemState,
        sui_amount_out: u64,
        ctx: &mut TxContext,
    ) {
        if (sui_amount_out == 0) {
            return
        };

        let total_sui_supply = (staker.liquid_staking_info.total_sui_supply() as u128);
        let total_lst_supply = (staker.liquid_staking_info.total_lst_supply() as u128);

        // ceil lst redemption amount
        let lst_to_redeem =
            ((sui_amount_out as u128) * total_lst_supply + total_sui_supply - 1) / total_sui_supply;
        let lst = balance::split(&mut staker.lst_balance, (lst_to_redeem as u64));

        let sui = liquid_staking::redeem(
            &mut staker.liquid_staking_info,
            coin::from_balance(lst, ctx),
            system_state,
            ctx,
        );

        staker.sui_balance.join(sui.into_balance());
    }
```

**File:** liquid_staking/sources/fee_config.move (L8-8)
```text
    const MAX_UNSTAKE_FEE_BPS: u64 = 500; // 5%
```

**File:** liquid_staking/sources/fee_config.move (L52-55)
```text
    public(package) fun set_unstake_fee_bps(self: &mut FeeConfig, fee: u64) {
        self.unstake_fee_bps = fee;
        self.validate_fees();
    }
```

**File:** liquid_staking/sources/fee_config.move (L83-90)
```text
    public(package) fun calculate_unstake_fee(self: &FeeConfig, sui_amount: u64): u64 {
        if (self.unstake_fee_bps == 0) {
            return 0
        };

        // ceil(sui_amount * unstake_fee_bps / 10_000)
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```

**File:** liquid_staking/sources/stake_pool.move (L294-312)
```text
        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);

        // deduct fee
        let redeem_fee_amount = self.fee_config.calculate_unstake_fee(sui.value());
        let redistribution_amount = 
            if(total_lst_supply(metadata) == lst.value()) {
                0
            } else {
                self.fee_config.calculate_unstake_fee_redistribution(redeem_fee_amount)
            };

        let mut fee = sui.split(redeem_fee_amount as u64);
        let redistribution_fee = fee.split(redistribution_amount);

        self.fees.join(fee);
        self.join_to_sui_pool(redistribution_fee);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L848-848)
```text
        let fees = staker::claim_fees(staker, system_state, ctx);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L869-899)
```text
    public(package) fun unstake_sui_from_staker<P, T>(
        reserve: &mut Reserve<P>,
        liquidity_request: &LiquidityRequest<P, T>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        assert!(reserve.coin_type == type_name::get<SUI>() && type_name::get<T>() == type_name::get<SUI>(), EWrongType);
        if (!dynamic_field::exists_(&reserve.id, StakerKey {})) {
            return
        };

        let balances: &Balances<P, SUI> = dynamic_field::borrow(&reserve.id, BalanceKey {});
        if (liquidity_request.amount <= balance::value(&balances.available_amount)) {
            return
        };
        let withdraw_amount = liquidity_request.amount - balance::value(&balances.available_amount);

        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});
        let sui = staker::withdraw(
            staker,
            withdraw_amount, 
            system_state, 
            ctx
        );

        let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );
        balance::join(&mut balances.available_amount, sui);
    }
```
