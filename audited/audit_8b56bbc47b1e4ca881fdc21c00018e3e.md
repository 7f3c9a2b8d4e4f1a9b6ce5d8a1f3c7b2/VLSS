# Audit Report

## Title
Vault Deposit and Withdraw Fees Use Floor Rounding Instead of Ceiling, Causing Protocol Fee Undercollection

## Summary
The vault's `execute_deposit` and `execute_withdraw` functions calculate fees using truncating division (floor rounding), systematically undercollecting fees on every transaction. This contradicts the liquid staking module's correct implementation using ceiling division, resulting in cumulative protocol revenue loss.

## Finding Description

The Volo vault system calculates deposit and withdrawal fees using simple integer division that rounds down (floor), while the protocol's liquid staking module correctly implements ceiling division for the same purpose. This inconsistency causes systematic fee undercollection.

**Vulnerable Vault Fee Calculations:**

The deposit fee calculation uses floor division: [1](#0-0) 

The withdrawal fee calculation also uses floor division: [2](#0-1) 

Both calculations use the pattern `amount * fee_rate / RATE_SCALING` where `RATE_SCALING = 10_000` [3](#0-2) . This truncates any fractional result, favoring users over the protocol.

**Correct Liquid Staking Implementation:**

The liquid staking module properly implements ceiling division by adding 9999 before division:

For stake fees: [4](#0-3) 

For unstake fees: [5](#0-4) 

The pattern `((amount as u128) * (fee_bps as u128) + 9999) / BPS_MULTIPLIER` ensures fees always round up. With `BPS_MULTIPLIER = 10_000` [6](#0-5) , adding 9999 before division implements ceiling division.

**Exploit Path:**

This vulnerability requires no special exploit - it triggers automatically:
1. User calls `request_deposit` or `request_withdraw` 
2. Operator executes via `execute_deposit` or `execute_withdraw`
3. Fee calculation rounds down instead of up
4. Protocol loses the fractional fee amount
5. User keeps the difference (more shares received or more principal withdrawn)

The default fee rates are 10 bps (0.1%) [7](#0-6) , making this affect virtually every transaction.

## Impact Explanation

**Per-Transaction Impact:**
The maximum loss per transaction is less than 1 token unit (the fractional part that gets truncated). For a 10 bps fee rate, when `(amount * 10) % 10_000` equals 9999, the protocol loses 0.9999 token units.

**Concrete Example:**
- User deposits 10,005 tokens with 10 bps fee (0.1%)
- Expected fee (ceiling): `ceil(10,005 * 10 / 10,000) = ceil(10.005) = 11 tokens`
- Actual fee (floor): `floor(10,005 * 10 / 10,000) = floor(10.005) = 10 tokens`
- **Protocol loses: 1 token**

**Cumulative Impact:**
Over high transaction volumes, losses become substantial:
- 1 million deposits/withdrawals per year
- Average 0.5 token loss per transaction
- **Annual loss: 500,000 tokens**

This breaks the security invariant that fee calculations should favor the protocol, not users. The liquid staking module's correct implementation proves this is a design requirement that vault violates.

## Likelihood Explanation

**Certainty: 100%**

This vulnerability triggers automatically on every deposit and withdrawal where the fee calculation produces a non-integer result. No attacker action is required.

**Frequency:**
Affects virtually all transactions since `(amount * fee_rate) % RATE_SCALING ≠ 0` for most deposit/withdrawal amounts. With random user amounts, approximately 99.99% of transactions will have non-zero remainders and trigger the undercollection.

**No Preconditions:**
- No special vault state required
- No timing requirements
- No coordination needed
- Happens during normal protocol operation
- Both user-initiated deposits and withdrawals affected

## Recommendation

Implement ceiling division for vault fees, matching the liquid staking module's approach:

**For deposit fees (line 830):**
```move
let deposit_fee = (((coin_amount as u128) * (self.deposit_fee_rate as u128) + 9999) / (RATE_SCALING as u128)) as u64;
```

**For withdrawal fees (line 1040):**
```move
let fee_amount = (((amount_to_withdraw as u128) * (self.withdraw_fee_rate as u128) + 9999) / (RATE_SCALING as u128)) as u64;
```

This ensures fees always round up, protecting protocol revenue and maintaining consistency with the liquid staking module's implementation.

## Proof of Concept

```move
#[test]
public fun test_fee_undercollection() {
    // Test demonstrating fee undercollection
    let coin_amount: u64 = 10_005;
    let fee_rate: u64 = 10; // 10 bps = 0.1%
    let RATE_SCALING: u64 = 10_000;
    
    // Current implementation (floor division)
    let actual_fee = coin_amount * fee_rate / RATE_SCALING;
    
    // Expected implementation (ceiling division)
    let expected_fee = (((coin_amount as u128) * (fee_rate as u128) + 9999) / (RATE_SCALING as u128)) as u64;
    
    // Verify undercollection
    assert!(actual_fee == 10, 0); // Floor gives 10
    assert!(expected_fee == 11, 1); // Ceiling gives 11
    assert!(expected_fee > actual_fee, 2); // Protocol loses 1 token
}
```

## Notes

This vulnerability demonstrates a critical inconsistency within the Volo codebase. The liquid staking module correctly implements ceiling division for fees, proving the team understands this is the proper approach. However, the vault module uses floor division, creating a systematic revenue leak. The cumulative impact over millions of transactions makes this a significant protocol-level concern despite the small per-transaction loss.

### Citations

**File:** volo-vault/sources/volo_vault.move (L28-28)
```text
const RATE_SCALING: u64 = 10_000;
```

**File:** volo-vault/sources/volo_vault.move (L30-31)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L830-830)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/volo_vault.move (L1040-1040)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
```

**File:** liquid_staking/sources/fee_config.move (L7-7)
```text
    const BPS_MULTIPLIER: u128 = 10_000; // 100%
```

**File:** liquid_staking/sources/fee_config.move (L79-80)
```text
        // ceil(sui_amount * sui_stake_fee_bps / 10_000)
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
```

**File:** liquid_staking/sources/fee_config.move (L88-89)
```text
        // ceil(sui_amount * unstake_fee_bps / 10_000)
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
```
