### Title
Borrow Fee Rounding Down Allows Systematic Fee Avoidance Through Transaction Splitting

### Summary
The `get_borrow_fee()` function in the lending_core incentive_v3 module uses floor division when calculating borrow fees, causing fractional fees to be truncated rather than rounded up. Attackers can exploit this by splitting large borrows into many small transactions, systematically avoiding up to 9% of borrow fees when fee rates are set at their maximum of 10%.

### Finding Description
The vulnerability exists in the borrow fee calculation: [1](#0-0) 

The fee calculation uses floor division: [2](#0-1) 

This calculation is invoked in all borrow flows: [3](#0-2) 

The protocol enforces a maximum borrow fee rate of 10%: [4](#0-3) 

However, there is no minimum borrow amount beyond non-zero: [5](#0-4) 

This is inconsistent with the liquid_staking module, which explicitly uses ceiling division to prevent fee loss: [6](#0-5) 

### Impact Explanation
When the borrow fee rate is set at its maximum of 10% (1000 bps), an attacker borrowing 99 tokens pays only 9 tokens in fees (should be 9.9), avoiding 0.9 tokens per transaction. By systematically splitting large borrows:

- Borrowing 1,000,000 USDC normally: 100,000 USDC fee
- Split into 10,101 borrows of 99 USDC each: 90,909 USDC total fees  
- **Fee avoidance: 9,091 USDC (~9% of expected fees)**

The protocol loses these fees permanently. At 1% fee rates, the impact is proportionally smaller but still present. The actual severity depends on the configured fee rate and borrow volume.

### Likelihood Explanation
The attack is technically and economically feasible:

**Attacker capabilities:** Any user with sufficient collateral can borrow repeatedly through public entry functions.

**Attack complexity:** Low - simply split desired borrow amount into many small transactions.

**Economic rationality:** For 10,101 transactions on Sui at ~$0.001 gas each = ~$10 total cost. Net savings of ~$9,081 makes this highly profitable for high-value tokens.

**Constraints:** Attacker needs sufficient collateral for all borrows and must still repay principal plus interest. However, the one-time fee savings can be substantial, especially for large positions.

The attack becomes less economically viable at lower fee rates (e.g., 1% fee yields only ~$90 savings) but remains a protocol value leak.

### Recommendation
Modify `get_borrow_fee()` to use ceiling division, consistent with the liquid_staking approach:

```move
fun get_borrow_fee(incentive: &Incentive, amount: u64): u64 {
    if (incentive.borrow_fee_rate > 0) {
        // Use ceiling division to prevent fee loss
        (((amount as u128) * (incentive.borrow_fee_rate as u128) + 9999) / 10000) as u64
    } else {
        0
    }
}
```

Additionally, consider implementing a minimum borrow amount to reduce the attack surface, similar to flash loan minimums. Add test cases that verify fees are correctly collected even for edge-case amounts (e.g., 99, 999, 9999 tokens at maximum fee rate).

### Proof of Concept
**Initial state:** Protocol has borrow fee rate set to 1000 (10%), user has sufficient collateral.

**Attack sequence:**
1. User wants to borrow 100,000 tokens total
2. Instead of single borrow: `entry_borrow(100000)` → fee = 10,000 tokens
3. User makes 1,011 borrows: `entry_borrow(99)` each
4. Each transaction: fee = (99 * 1000) / 10000 = 9 tokens (not 9.9)
5. Total fees paid: 1,011 * 9 = 9,099 tokens
6. Total borrowed: ~100,089 tokens

**Expected result:** User should pay ~10,000 tokens in fees

**Actual result:** User pays only 9,099 tokens in fees

**Success condition:** Fee avoidance of ~901 tokens (~9% savings) minus gas costs (~$10), netting ~$891 profit for a $100k position.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L18-18)
```text
    public fun percentage_benchmark(): u64 {10000}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L312-323)
```text
    public(friend) fun set_borrow_fee_rate(incentive: &mut Incentive, rate: u64, ctx: &TxContext) {
        version_verification(incentive); // version check
        // max 10% borrow fee rate
        assert!(rate <= constants::percentage_benchmark() / 10, error::invalid_value());

        incentive.borrow_fee_rate = rate;

        emit(BorrowFeeRateUpdated{
            sender: tx_context::sender(ctx),
            rate: rate,
        });
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L890-896)
```text
    fun get_borrow_fee(incentive: &Incentive, amount: u64): u64 {
        if (incentive.borrow_fee_rate > 0) {
            amount * incentive.borrow_fee_rate / constants::percentage_benchmark()
        } else {
            0
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L913-917)
```text
        let fee = get_borrow_fee(incentive_v3, amount);

        let _balance =  lending::borrow_coin<CoinType>(clock, oracle, storage, pool, asset, amount + fee, ctx);

        deposit_borrow_fee(incentive_v3, &mut _balance, fee);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L56-58)
```text
    public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());
```

**File:** liquid_staking/sources/fee_config.move (L79-81)
```text
        // ceil(sui_amount * sui_stake_fee_bps / 10_000)
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```
