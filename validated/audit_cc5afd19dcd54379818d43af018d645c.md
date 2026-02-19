### Title
Zero-Amount Withdrawal Due to Precision Loss in Vault Share Redemption

### Summary
The vault's `execute_withdraw` function lacks explicit validation to prevent zero-amount withdrawals when share-to-token conversion rounds down to zero. Users can burn shares but receive no tokens if they withdraw very small amounts with `expected_amount = 0`, directly analogous to the external "Minting of Zero LST" vulnerability where users provide assets but receive nothing in return.

### Finding Description

**Root Cause in Volo:**

The vulnerability exists in the vault withdrawal flow where share-to-token conversion can round down to zero without explicit prevention. [1](#0-0) 

The calculation performs:
1. `usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio)` which divides by 1e9 [2](#0-1) 
2. `amount_to_withdraw = vault_utils::div_with_oracle_price(usd_value_to_withdraw, price)` which divides by oracle price [3](#0-2) 

When shares are very small (e.g., 1 share with ratio=1e9 and price=2e18), the result rounds to zero: `(1 * 1e9 / 1e9) * 1e18 / 2e18 = 0.5 → 0`.

**Why Protections Fail:**

The only validations are slippage checks that compare against user's `expected_amount`. [4](#0-3)  If the user sets `expected_amount = 0`, the check `assert!(0 >= 0)` passes, allowing zero withdrawals.

User entry validation only checks shares are non-zero, not the resulting amount. [5](#0-4) 

**Inconsistency with Deposits:**

The deposit flow explicitly prevents zero-share minting with `assert!(user_shares > 0, ERR_ZERO_SHARE)`. [6](#0-5)  No equivalent check exists for withdrawals.

**Exploit Path:**
1. User calls `user_entry::withdraw(shares=1, expected_amount=0, ...)` - passes `shares > 0` check
2. Withdrawal request created with these parameters
3. Operator executes via `execute_withdraw(request_id, max_amount_received)`
4. Calculation produces `amount_to_withdraw = 0` due to precision loss
5. Slippage checks pass: `0 >= 0` and `0 <= max_amount_received`
6. Shares burned from vault total [7](#0-6) 
7. User receives zero tokens [8](#0-7) 

### Impact Explanation

**Severity: Medium-High**

- **Direct User Loss**: Users permanently lose vault share ownership without receiving any principal tokens in return
- **Value Transfer**: Burned shares mean remaining shareholders proportionally gain value, as their shares now represent a larger fraction of total vault assets
- **Protocol Integrity**: While vault accounting remains mathematically consistent, users suffer economic loss through unfair exchange
- **Analog Classification**: The external vulnerability showed users staking assets and receiving 0 tokens—here users burn shares (representing asset ownership) and receive 0 tokens, yielding the same economic outcome of providing value for nothing

The external report classified this as requiring remediation ("Prevent the minting of an invalid amount"), confirming this precision-loss-to-zero class is a valid vulnerability requiring fixes.

### Likelihood Explanation

**Likelihood: Medium**

**Triggering Conditions:**
- User must withdraw very small number of shares (typically 1-1,000 shares depending on token price)
- User must set `expected_amount = 0` or low enough that zero satisfies the check

**Realistic Scenarios:**
- Users withdrawing "dust" amounts (small leftover shares) without realizing the calculation rounds to zero
- Frontend UI bugs that incorrectly calculate or allow `expected_amount = 0`
- Manual parameter setting without proper validation
- High-value principal tokens (e.g., wrapped BTC) make the vulnerability range wider—up to ~1,000 shares could round to zero with $50,000/token prices

**Not Blocked By Existing Checks:**
- User entry validates only `shares > 0`, not final amount [5](#0-4) 
- Slippage validation only compares to user's `expected_amount`, doesn't enforce minimum > 0 [4](#0-3) 
- Operator's `max_amount_received` also doesn't enforce non-zero minimum

The combination of realistic precision loss with small amounts and lack of explicit zero-amount validation makes this exploitable under normal protocol operations.

### Recommendation

**Primary Fix - Add explicit zero-amount validation:**

In `volo-vault/sources/volo_vault.move`, add after line 1022:
```move
assert!(amount_to_withdraw > 0, ERR_ZERO_AMOUNT);
```

Define new error constant near line 52:
```move
const ERR_ZERO_AMOUNT: u64 = 5_029;
```

**Alternative/Additional Protections:**

1. **Minimum share withdrawal**: Enforce minimum shares in `user_entry::withdraw` (similar to liquid_staking's `MIN_STAKE_AMOUNT` pattern [9](#0-8) )

2. **Minimum expected_amount**: Require `expected_amount > 0` in user_entry validation

3. **Round-up protection**: Modify conversion to return at least 1 if input > 0, similar to the liquid staking v1 pattern [10](#0-9) 

**Consistency Note**: Apply same protection pattern used for deposits [6](#0-5)  to maintain consistent safety guarantees across deposit/withdraw flows.

### Proof of Concept

**Setup State:**
- Vault initialized with principal token (SUI)
- Share ratio = 1e9 (initial state from `to_decimals(1)`) [11](#0-10) 
- Oracle price = 2e18 (2 USD per SUI)
- User has receipt with ≥1 share

**Execution Steps:**

1. User requests withdrawal of 1 share with expected_amount=0:
   - Calls `user_entry::withdraw(vault, 1, 0, receipt, clock, ctx)`
   - Passes validation: `assert!(1 > 0)` [5](#0-4) 
   - Request stored with shares=1, expected_amount=0

2. Operator executes withdrawal:
   - Calls `operation::execute_withdraw(vault, cap, config, clock, request_id, 100)`
   
3. Calculation in `execute_withdraw`: [12](#0-11) 
   - `usd_value = mul_d(1, 1e9) = 1 * 1e9 / 1e9 = 1`
   - `amount_to_withdraw = div_with_oracle_price(1, 2e18) = 1 * 1e18 / 2e18 = 0` (rounds from 0.5)

4. Validations pass:
   - `assert!(0 >= 0, ERR_UNEXPECTED_SLIPPAGE)` ✓
   - `assert!(0 <= 100, ERR_UNEXPECTED_SLIPPAGE)` ✓

5. Shares burned: [7](#0-6) 
   - `self.total_shares = self.total_shares - 1`

6. User receives zero: [8](#0-7) 
   - `withdraw_balance = self.free_principal.split(0)`

**Result:** User's share count decreased by 1, but received Balance with value=0.

**Generalization:** For `amount_to_withdraw = 0`, need `shares * ratio * 1e18 < price * 1e9`. With ratio=1e9: shares < price/1e9. At price=$2, shares<2; at price=$1000, shares<1000.

### Citations

**File:** volo-vault/sources/volo_vault.move (L848-848)
```text
    assert!(user_shares > 0, ERR_ZERO_SHARE);
```

**File:** volo-vault/sources/volo_vault.move (L1011-1022)
```text
    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
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

**File:** volo-vault/sources/volo_vault.move (L1029-1030)
```text
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1033-1033)
```text
    self.total_shares = self.total_shares - shares_to_withdraw;
```

**File:** volo-vault/sources/volo_vault.move (L1037-1037)
```text
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);
```

**File:** volo-vault/sources/volo_vault.move (L1305-1305)
```text
        return vault_utils::to_decimals(1)
```

**File:** volo-vault/sources/utils.move (L23-25)
```text
public fun mul_d(v1: u256, v2: u256): u256 {
    v1 * v2 / DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L74-75)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
```

**File:** volo-vault/sources/user_entry.move (L137-137)
```text
    assert!(shares > 0, ERR_INVALID_AMOUNT);
```

**File:** liquid_staking/sources/stake_pool.move (L230-230)
```text
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** liquid_staking/sources/volo_v1/math.move (L37-39)
```text
        if (amount > 0 && shares == 0) {
            shares = 1;
        };
```
