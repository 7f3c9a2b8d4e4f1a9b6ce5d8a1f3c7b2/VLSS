### Title
Unchecked U256 to U64 Conversion in Withdraw Execution Causes Permanent Fund Lockup

### Summary
The `execute_withdraw()` function performs an unchecked cast from u256 to u64 when calculating withdrawal amounts, causing transaction aborts when the result exceeds u64::MAX. This permanently locks user funds for any vault with large share balances and low-priced principal tokens, as the withdrawal transaction will always fail.

### Finding Description

The vulnerability exists in the withdrawal execution flow where u256 share values are converted to u64 token amounts without overflow validation. [1](#0-0) 

The calculation computes: `amount_to_withdraw = (shares * ratio * 1e9) / price` as a u256, then directly casts to u64 without checking if the result fits within u64::MAX (18,446,744,073,709,551,615).

The withdrawal flow begins when users request withdrawals with u256 share amounts: [2](#0-1) 

The `WithdrawRequest` struct stores shares as u256 but expected_amount as u64: [3](#0-2) 

The protocol's own codebase demonstrates the CORRECT pattern for safe u256 to u64 conversions with explicit overflow checks: [4](#0-3) [5](#0-4) 

Another example of proper overflow handling: [6](#0-5) 

**Why Existing Protections Fail:**

The slippage checks on lines 1029-1030 occur AFTER the cast, so they cannot prevent the abort. The calculation uses: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Concrete Harm:**
- Users with large share balances cannot withdraw their funds
- Funds become permanently locked as every withdrawal attempt aborts
- No recovery mechanism exists once shares exceed the problematic threshold

**Quantified Scenario:**
For a vault with:
- User shares: 1e18 (1 billion shares with 9 decimal places)
- Share ratio: 2e9 (each share worth $2)
- Token price: 5e16 (0.05 USD per token in 1e18 decimals)

Calculation: `amount = (1e18 * 2e9 * 1e9) / 5e16 = 4e19`

This exceeds u64::MAX (1.844e19), causing immediate transaction abort.

**Affected Users:**
- Any user accumulating shares over time in a vault
- Vaults using low-priced principal tokens (meme coins, high-decimal tokens)
- Early depositors in successful vaults with significant growth

**Severity:** HIGH - Permanent fund lockup with realistic preconditions.

### Likelihood Explanation

**Attacker Capabilities:** None required - this affects legitimate users through normal protocol operation.

**Feasibility Conditions:**
1. User accumulates large u256 share balance (inevitable over time for active vaults)
2. Vault uses principal token with low USD price (common for meme coins, tokens with 18 decimals)
3. User attempts withdrawal

**Execution Path:**
1. User calls `withdraw()` or `withdraw_with_auto_transfer()`
2. Creates withdrawal request with u256 shares
3. Operator calls `execute_withdraw()` 
4. Calculation produces u256 value > u64::MAX
5. Cast to u64 causes transaction abort
6. Withdrawal permanently fails

**Probability:** HIGH - The conditions naturally occur as vaults mature and accumulate value. Low-priced tokens are common in DeFi ecosystems.

### Recommendation

Add explicit overflow check before the u64 cast in `execute_withdraw()`:

```move
let amount_u256 = vault_utils::div_with_oracle_price(
    usd_value_to_withdraw,
    vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    ),
);

// Add this check:
const U64_MAX: u256 = 18_446_744_073_709_551_615;
assert!(amount_u256 <= U64_MAX, ERR_AMOUNT_OVERFLOW);

let amount_to_withdraw = amount_u256 as u64;
```

**Invariant Check:** Ensure all u256 to u64 conversions include explicit bounds checking.

**Test Cases:**
1. Test withdrawal with shares that produce amount > u64::MAX
2. Test with various token price ranges (especially < $0.01)
3. Test with maximum realistic share balances (1e20+)

### Proof of Concept

**Initial State:**
- Vault with principal token priced at $0.05 (5e16 in 1e18 decimals)
- User has 1e18 shares (1 billion shares with 9 decimals)
- Share ratio is 2e9 (each share worth $2)

**Transaction Steps:**
1. User calls `withdraw(vault, shares=1e18, expected_amount=1e10, receipt, clock)`
2. Withdrawal request created successfully
3. Operator calls `execute_withdraw(vault, clock, config, request_id, max_amount=1e19)`
4. Calculation executes:
   - `usd_value_to_withdraw = 1e18 * 2e9 / 1e9 = 2e18`
   - `amount_to_withdraw = 2e18 * 1e18 / 5e16 = 4e19` (as u256)
5. Cast `4e19 as u64` exceeds u64::MAX (1.844e19)

**Expected Result:** Transaction should complete or fail gracefully with proper error

**Actual Result:** Transaction aborts at line 1022 due to overflow in u256→u64 cast

**Success Condition for Exploit:** User's withdrawal transaction consistently aborts, proving funds are permanently locked.

### Citations

**File:** volo-vault/sources/volo_vault.move (L896-903)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
```

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/requests/withdraw_request.move (L5-17)
```text
public struct WithdrawRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Withdraw Info ---- //
    shares: u256, // Shares to withdraw
    expected_amount: u64, // Expected amount to get after withdraw
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** liquid_staking/sources/volo_v1/math.move (L34-41)
```text
    public fun to_shares(ratio: u256, amount: u64): u64 {
        let mut shares = (amount as u256) * ratio / RATIO_MAX;
        assert!(shares <= (U64_MAX as u256), E_U64_OVERFLOW);
        if (amount > 0 && shares == 0) {
            shares = 1;
        };
        (shares as u64)
    }
```

**File:** liquid_staking/sources/volo_v1/math.move (L44-49)
```text
    public fun from_shares(ratio: u256, shares: u64): u64 {
        assert!(ratio != 0, E_DIVIDE_BY_ZERO);
        let amount = (shares as u256) * RATIO_MAX / ratio;
        assert!(amount <= (U64_MAX as u256), E_U64_OVERFLOW);
        (amount as u64)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move (L40-57)
```text
    public fun calculate_amplitude(a: u256, b: u256): u64 {
        if (a == 0 || b == 0) {
            return U64MAX
        };
        let ab_diff = abs_sub(a, b);

        // prevent overflow 
        if (ab_diff > sui::address::max() / (constants::multiple() as u256)) {
            return U64MAX
        };

        let amplitude = (ab_diff * (constants::multiple() as u256) / a);
        if (amplitude > (U64MAX as u256)) {
            return U64MAX
        };

        (amplitude as u64)
    }
```

**File:** volo-vault/sources/utils.move (L23-25)
```text
public fun mul_d(v1: u256, v2: u256): u256 {
    v1 * v2 / DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```
