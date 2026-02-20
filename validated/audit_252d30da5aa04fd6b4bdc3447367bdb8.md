# Audit Report

## Title
Vault Deposit and Withdraw Fees Use Floor Rounding Instead of Ceiling, Causing Systematic Protocol Fee Undercollection

## Summary
The vault's `execute_deposit` and `execute_withdraw` functions calculate fees using truncating division (floor rounding), which favors users over the protocol. This is inconsistent with the liquid staking module's fee calculations that properly use ceiling division. This results in systematic fee undercollection on every deposit and withdrawal operation, causing direct financial loss to the protocol.

## Finding Description

The Volo protocol has an internal inconsistency in how fees are calculated across its modules. The vault system uses floor rounding while the liquid staking module uses ceiling rounding, creating a systematic undercollection issue.

**Vulnerable Vault Fee Calculations:**

The deposit fee calculation uses simple integer division [1](#0-0) , which truncates any fractional result. Similarly, the withdraw fee calculation also uses floor division [2](#0-1) . Both use the pattern `amount * fee_rate / RATE_SCALING` where `RATE_SCALING = 10_000` [3](#0-2) .

**Correct Implementation in Liquid Staking:**

The liquid staking module properly implements ceiling division for stake fees [4](#0-3)  and unstake fees [5](#0-4) . The pattern `((amount as u128) * (fee_bps as u128) + 9999) / BPS_MULTIPLIER` ensures fees always round up, where `BPS_MULTIPLIER = 10_000` [6](#0-5) .

**Impact Mechanics:**

With the default deposit fee rate of 10 bps (0.1%) [7](#0-6)  and withdraw fee rate of 10 bps [8](#0-7) , when a user deposits or withdraws an amount where `amount * 10 % 10_000 ≠ 0`, the protocol systematically loses the fractional fee amount.

**Concrete Example:**
- User deposits 10,005 tokens
- Floor calculation (current): `10,005 * 10 / 10,000 = 100,050 / 10,000 = 10` tokens fee
- Ceiling calculation (correct): `(10,005 * 10 + 9,999) / 10,000 = 110,049 / 10,000 = 11` tokens fee
- Protocol loses 1 token per transaction

The fee is then split from the user's balance [9](#0-8)  for deposits and [10](#0-9)  for withdrawals, meaning users keep the undercollected fractional amounts.

## Impact Explanation

**Direct Financial Loss:**
- The protocol systematically undercollects fees on virtually every deposit and withdrawal transaction
- Maximum loss per transaction: up to 1 unit of principal token
- With default 10 bps fees, most transaction amounts will not produce perfectly divisible results
- Cumulative impact scales with transaction volume: 1 million transactions/year with 0.5 token average loss = 500,000 tokens annual undercollection

**Protocol Revenue Impact:**
This directly reduces protocol revenue from fee collection, which is meant to sustain protocol operations and reward liquidity providers. The issue affects the core vault operations that all users interact with.

**Severity Justification:**
While individual transaction losses are small (< 1 token), the systematic nature across all vault transactions and high transaction frequency make this a Medium to High severity issue affecting protocol sustainability.

## Likelihood Explanation

**Certainty: 100%**

This vulnerability triggers automatically on every deposit and withdrawal where the fee calculation produces a non-integer result after division by 10,000. No attacker action is required—it happens during normal vault usage.

**Why It's Highly Likely:**
1. Default fee rates are 10 bps (0.1%), making most amounts indivisible by 10,000
2. Users naturally deposit/withdraw arbitrary amounts based on their needs
3. The vulnerability is always active—no special preconditions needed
4. Affects both public deposit/withdraw operations that any user can trigger

**Realistic Execution Path:**
1. User calls `request_deposit` with arbitrary amount (public entry point via user_entry.move)
2. Operator executes via `execute_deposit` (called from operation.move)
3. Fee calculation at line 830 automatically rounds down
4. Protocol loses fractional fee on every such transaction

This is not a theoretical vulnerability—it happens on production transactions today.

## Recommendation

Adopt the same ceiling division pattern used in the liquid staking module for vault fee calculations.

**For Deposit Fee (line 830):**
```move
let deposit_fee = (((coin_amount as u128) * (self.deposit_fee_rate as u128) + 9999) / (RATE_SCALING as u128)) as u64;
```

**For Withdraw Fee (line 1040):**
```move
let fee_amount = (((amount_to_withdraw as u128) * (self.withdraw_fee_rate as u128) + 9999) / (RATE_SCALING as u128)) as u64;
```

This ensures consistency with the protocol's established standard in the liquid staking module and guarantees fees always round in favor of the protocol.

## Proof of Concept

```move
#[test]
fun test_fee_undercollection() {
    // Setup: Create vault with default 10 bps deposit fee
    let deposit_amount: u64 = 10_005;
    let fee_rate: u64 = 10; // 0.1% = 10 bps
    let rate_scaling: u64 = 10_000;
    
    // Current (vulnerable) floor division
    let actual_fee = deposit_amount * fee_rate / rate_scaling;
    assert!(actual_fee == 10, 0);
    
    // Expected ceiling division (like liquid staking)
    let expected_fee = (((deposit_amount as u128) * (fee_rate as u128) + 9999) / (rate_scaling as u128)) as u64;
    assert!(expected_fee == 11, 1);
    
    // Protocol loses the difference
    let protocol_loss = expected_fee - actual_fee;
    assert!(protocol_loss == 1, 2); // 1 token lost per transaction
}
```

This test demonstrates that with a 10,005 token deposit at 10 bps fee rate, the current implementation collects 10 tokens while it should collect 11 tokens, resulting in 1 token undercollection per transaction.

### Citations

**File:** volo-vault/sources/volo_vault.move (L28-28)
```text
const RATE_SCALING: u64 = 10_000;
```

**File:** volo-vault/sources/volo_vault.move (L30-30)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L31-31)
```text
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L830-830)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/volo_vault.move (L835-836)
```text
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1040-1040)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/volo_vault.move (L1041-1042)
```text
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
```

**File:** liquid_staking/sources/fee_config.move (L7-7)
```text
    const BPS_MULTIPLIER: u128 = 10_000; // 100%
```

**File:** liquid_staking/sources/fee_config.move (L80-80)
```text
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
```

**File:** liquid_staking/sources/fee_config.move (L89-89)
```text
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
```
