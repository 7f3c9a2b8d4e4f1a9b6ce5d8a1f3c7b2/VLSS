### Title
Last Fee Receiver Receives Disproportionate Share Due to Accumulated Rounding Errors

### Summary
The `claim_fees()` function distributes fees among multiple receivers based on weights, but uses `balance::withdraw_all()` for the last receiver instead of calculating their exact proportional share. This causes the last receiver to receive all accumulated rounding dust from integer division, potentially giving them significantly more than their fair share when many receivers exist.

### Finding Description

The vulnerability exists in `claim_fees()` function where fee distribution logic handles multiple receivers: [1](#0-0) 

For each non-last receiver (i < num_fee_receivers - 1), the code calculates the proportional fee amount using integer division: `(total_fees as u128) * (weight_i as u128) / (total_weight as u128)`, then splits that amount from the balance. However, for the last receiver (i == num_fee_receivers - 1), it uses `balance::withdraw_all()` to give them all remaining balance. [2](#0-1) [3](#0-2) 

The root cause is that integer division rounds down for each calculation. With N receivers, the first (N-1) receivers each potentially lose up to 1 unit due to rounding, and the last receiver gains all this accumulated "dust" - up to (N-1) units total.

The same issue affects both regular fees and ctoken_fees distribution, as both use identical logic.

### Impact Explanation

**Quantified Impact:**
The maximum absolute excess for the last receiver = (N-1) units, where N is the number of fee receivers.

The relative impact = `(N-1) × total_weight / (total_fees × weight_last)`

**Concrete Examples:**

1. **Scenario with 100 equal-weight receivers:**
   - 100 receivers (weight=1 each, total_weight=100)
   - total_fees = 9,999
   - Ideal per receiver: 99.99
   - First 99 receivers: each gets floor(9999×1/100) = 99
   - Last receiver: gets 9999 - (99×99) = 198
   - **Last receiver receives ~98% MORE than fair share**

2. **Scenario with last receiver having small weight:**
   - 10 receivers: weights [50,5,5,5,5,5,5,5,5,10], total=100
   - total_fees = 99
   - Receiver 0 gets 49, Receivers 1-8 get 4 each (32 total)
   - Last receiver (weight=10) gets: 99-49-32 = 18
   - Ideal for last: 9.9, Actual: 18
   - **Last receiver receives ~82% MORE than fair share**

3. **Scenario with very small fee amounts:**
   - 5 equal receivers (weight=20 each)
   - total_fees = 4
   - First 4 receivers: floor(4×20/100) = 0 each
   - Last receiver: gets all 4
   - **First 4 receivers get NOTHING, last gets 500% more**

**Who is affected:**
- Fee receivers configured in the protocol lose their proportional share (first N-1 receivers)
- The last fee receiver in the list consistently benefits
- The unfairness is systemic and occurs on every fee claim

**Severity justification:**
Low severity because impact is bounded by (N-1) units absolute, but can be significant percentage-wise with many receivers, small weights for last receiver, or small fee amounts.

### Likelihood Explanation

**Reachability:** 
The `claim_fees()` function is an entry function callable by anyone, requiring no special permissions. [4](#0-3) 

**Preconditions:**
- Multiple fee receivers must be configured (set by LendingMarketOwnerCap holder)
- Fee amounts don't divide evenly by weights
- This is NOT a trusted role compromise - having multiple fee receivers is legitimate protocol design (e.g., treasury, dev fund, insurance fund, DAO) [5](#0-4) 

**Execution:**
The issue occurs automatically and deterministically every time fees are claimed with multiple receivers. The last receiver in the configured list consistently receives extra funds.

**Probability:**
- Guaranteed to occur with any non-divisible fee amounts and multiple receivers
- Impact magnitude depends on number of receivers, fee amounts, and weight distribution
- Not exploitable by untrusted users, but represents systemic unfairness in fee distribution

### Recommendation

**Fix the distribution logic to calculate exact share for last receiver:**

Replace the withdraw_all() calls with proper proportional calculation for the last receiver. Modify the logic at lines 1155-1159 and 1169-1173:

```move
let fee_amount = (total_fees as u128) * (fee_receivers.weights[i] as u128) / (fee_receivers.total_weight as u128);
let fee = balance::split(&mut fees, fee_amount as u64);
```

For both fees and ctoken_fees, always use the proportional calculation. Any remaining dust (which should be minimal, < N units) can be:
1. Kept in the reserve for next claim
2. Distributed to the first receiver
3. Split evenly among all receivers using a fair rounding scheme

**Add invariant checks:**
- Assert that total distributed equals expected total within acceptable rounding bounds
- Verify no single receiver gets more than their proportional share plus reasonable rounding error

**Test cases:**
- Test with 100 receivers, various fee amounts (both divisible and non-divisible)
- Test with unequal weight distributions
- Test with small fee amounts (< number of receivers)
- Verify each receiver gets within 1 unit of their exact proportional share

### Proof of Concept

**Initial State:**
- LendingMarket with reserve containing accumulated fees
- FeeReceivers configured with 10 receivers: weights [50,5,5,5,5,5,5,5,5,10], total_weight=100

**Execution:**
1. Fees accumulate to 99 units (both regular and ctoken fees)
2. Anyone calls `claim_fees<P, T>(lending_market, reserve_array_index, system_state, ctx)`

**Expected Result (Fair Distribution):**
- Receiver 0: 49 units (50% of 99 ≈ 49.5)
- Receivers 1-8: 4 units each (5% of 99 ≈ 4.95 each)
- Receiver 9: 10 units (10% of 99 ≈ 9.9)

**Actual Result:**
- Receiver 0: 49 units (calculated: floor(99×50/100) = 49)
- Receivers 1-8: 4 units each (calculated: floor(99×5/100) = 4)
- Receiver 9: 18 units (withdraw_all of remaining: 99-49-32 = 18)

**Success Condition:**
The last receiver (Receiver 9) receives 18 units instead of their proportional share of ~10 units, representing an ~82% excess. This demonstrates the vulnerability where the last receiver consistently benefits from accumulated rounding errors.

**Notes**

This is a systemic accounting issue in the fee distribution mechanism. While not directly exploitable by untrusted attackers (since fee receiver configuration requires admin privileges), it represents a fairness problem in the protocol's economic design. The issue becomes more pronounced with:
- Larger numbers of fee receivers (common in DAOs with multiple stakeholder groups)
- Smaller fee amounts relative to number of receivers
- Unequal weight distributions where the last receiver has a small weight

The vulnerability is deterministic and occurs on every fee claim, making it a predictable source of unfairness in fee distribution rather than a one-time exploit.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1103-1129)
```text
    public fun set_fee_receivers<P>(
        _: &LendingMarketOwnerCap<P>,
        lending_market: &mut LendingMarket<P>,
        receivers: vector<address>,
        weights: vector<u64>,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        assert!(vector::length(&receivers) == vector::length(&weights), EInvalidFeeReceivers);
        assert!(vector::length(&receivers) > 0, EInvalidFeeReceivers);

        let total_weight = vector::fold!(weights, 0, |acc, weight| acc + weight);
        assert!(total_weight > 0, EInvalidFeeReceivers);

        if (dynamic_field::exists_(&lending_market.id, FeeReceiversKey {})) {
            let FeeReceivers { .. } = dynamic_field::remove<FeeReceiversKey, FeeReceivers>(
                &mut lending_market.id,
                FeeReceiversKey {},
            );
        };

        dynamic_field::add(
            &mut lending_market.id,
            FeeReceiversKey {},
            FeeReceivers { receivers, weights, total_weight },
        );
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1131-1137)
```text
    entry fun claim_fees<P, T>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1152-1183)
```text
        num_fee_receivers.do!(|i| {
            let fee_amount =
                (total_fees as u128) * (fee_receivers.weights[i] as u128) / (fee_receivers.total_weight as u128);
            let fee = if (i == num_fee_receivers - 1) {
                balance::withdraw_all(&mut fees)
            } else {
                balance::split(&mut fees, fee_amount as u64)
            };

            if (balance::value(&fee) > 0) {
                transfer::public_transfer(coin::from_balance(fee, ctx), fee_receivers.receivers[i]);
            } else {
                balance::destroy_zero(fee);
            };

            let ctoken_fee_amount =
                (total_ctoken_fees as u128) * (fee_receivers.weights[i] as u128) / (fee_receivers.total_weight as u128);
            let ctoken_fee = if (i == num_fee_receivers - 1) {
                balance::withdraw_all(&mut ctoken_fees)
            } else {
                balance::split(&mut ctoken_fees, ctoken_fee_amount as u64)
            };

            if (balance::value(&ctoken_fee) > 0) {
                transfer::public_transfer(
                    coin::from_balance(ctoken_fee, ctx),
                    fee_receivers.receivers[i],
                );
            } else {
                balance::destroy_zero(ctoken_fee);
            };
        });
```
