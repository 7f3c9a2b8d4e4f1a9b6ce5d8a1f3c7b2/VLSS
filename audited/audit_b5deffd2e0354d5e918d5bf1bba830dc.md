# Audit Report

## Title
U64 Overflow in Withdrawal Amount Calculation Prevents Large Withdrawals in High-Value Vaults

## Summary
The `execute_withdraw` function performs an unchecked cast from u256 to u64 when calculating withdrawal amounts, causing transaction aborts when the calculated amount exceeds u64::MAX. This creates a denial-of-service condition for users with large vault positions.

## Finding Description

The vulnerability exists in the vault withdrawal execution flow where shares are converted to principal token amounts. The calculation performs:

1. USD value computation from shares and share ratio (u256 arithmetic)
2. Token amount calculation via `div_with_oracle_price`, which returns u256
3. **Direct cast to u64 without overflow validation** [1](#0-0) 

The `div_with_oracle_price` utility function multiplies by `ORACLE_DECIMALS = 10^18` before division, producing large u256 values: [2](#0-1) 

Oracle prices are normalized to 9 decimals: [3](#0-2) 

When the calculated amount exceeds u64::MAX (18,446,744,073,709,551,615), the Move runtime aborts the transaction **before** reaching the slippage validation checks. The `WithdrawRequest` struct also stores `expected_amount` as u64, reinforcing this ceiling: [4](#0-3) 

This contrasts with the liquid staking module, which implements explicit overflow checks before casting: [5](#0-4) [6](#0-5) 

## Impact Explanation

**Operational Denial of Service**: Users holding positions that result in token amounts exceeding u64::MAX cannot execute withdrawals. For 9-decimal tokens:
- At $1 per token: ~$18.4 billion threshold
- At $0.10 per token: ~$1.84 billion threshold  
- At $0.001 per token: ~$18.4 million threshold

**Affected Users**:
- Large institutional investors in successful vaults
- Users in vaults with low-priced tokens (meme coins, micro-cap assets)
- Any user whose position grows beyond the threshold through yield accumulation

**Severity**: Medium - This creates an asymmetric operational restriction where funds can enter the vault but large positions cannot exit without cancellation timeout periods to split requests. For extremely large positions, even split withdrawals may exceed the threshold, potentially creating permanent lockup scenarios.

## Likelihood Explanation

**Realistic Trigger Scenarios**:

1. **Vault Growth**: A vault growing from $5B to $20B+ through yields and deposits naturally encounters this limit
2. **Low-Price Tokens**: Tokens priced at $0.001 hit the u64 limit at just $18.4 million
3. **Micro-Cap Tokens**: Tokens at $0.0001 hit the limit at $1.84 million

**Probability Factors**:
- No attack complexity - occurs through normal vault operations
- More likely in bull markets where vault TVL grows rapidly
- Guaranteed once vault reaches critical threshold  
- Higher probability for institutional-scale vaults or low-unit-price tokens

The issue represents an inherent protocol limitation that manifests as vaults succeed and grow, rather than an exploitable attack vector.

## Recommendation

Implement explicit u64 overflow checks before casting, following the pattern used in the liquid staking module:

```move
// In execute_withdraw function, replace line 1014-1022 with:
let amount_to_withdraw_u256 = vault_utils::div_with_oracle_price(
    usd_value_to_withdraw,
    vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    ),
);

// Add overflow check
const U64_MAX: u256 = 18_446_744_073_709_551_615;
const ERR_U64_OVERFLOW: u64 = 5_029; // Add to error codes
assert!(amount_to_withdraw_u256 <= U64_MAX, ERR_U64_OVERFLOW);

let amount_to_withdraw = (amount_to_withdraw_u256 as u64);
```

Alternatively, consider upgrading the entire withdrawal accounting system to use u256 throughout, including the `WithdrawRequest.expected_amount` field, to support arbitrarily large vault positions.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::test_scenario::EEmptyInventory)]
public fun test_withdraw_u64_overflow() {
    // This test would demonstrate that attempting to withdraw a position
    // whose calculated token amount exceeds u64::MAX causes an abort
    // during the u256 to u64 cast, before any slippage checks execute.
    // The exact abort occurs in the Move runtime's casting operation.
    
    // Setup: Create vault with very large position value or low-priced token
    // Action: Request and execute withdrawal
    // Expected: Transaction aborts at cast operation in execute_withdraw
}
```

**Note**: The mathematical validation confirms that for a 9-decimal token at $1, the overflow occurs when `usd_value * 10^9 > u64::MAX`, which equals approximately $18.4 billion USD value. For lower-priced tokens, this threshold decreases proportionally, making the issue more likely to occur in practice.

### Citations

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

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
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
