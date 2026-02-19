### Title
Suilend Position Value Inflation Due to Incorrect Decimal Scaling Factor Mismatch

### Summary
The `parse_suilend_obligation()` function incorrectly divides Suilend market values (scaled by 1e18) by `DECIMAL` (1e9), resulting in position values that are inflated by 1 billion times. This breaks the vault's share ratio calculation, causing depositors to lose funds and enabling withdrawers to steal vault assets, as all other adaptors correctly return unscaled USD values.

### Finding Description

The vulnerability exists in the `parse_suilend_obligation()` function: [1](#0-0) 

The root cause is a scaling factor mismatch:

1. **Suilend's Decimal type uses 1e18 scaling:** [2](#0-1) 

2. **The `to_scaled_val()` function extracts the raw value (scaled by 1e18):** [3](#0-2) 

3. **Suilend reserve functions return Decimal types with 1e18 scaling:** [4](#0-3) [5](#0-4) 

4. **The adaptor incorrectly uses DECIMAL = 1e9 for division:** [6](#0-5) 

The calculation at line 88 divides values scaled by 1e18 by 1e9, leaving results scaled by 1e9 instead of unscaled.

**All other adaptors correctly return unscaled USD values:**

- **Navi adaptor** uses `mul_with_oracle_price` which divides by 1e18: [7](#0-6) 

- **Cetus adaptor** uses the same pattern: [8](#0-7) 

- **Receipt adaptor** follows the same convention: [9](#0-8) 

The `mul_with_oracle_price` function correctly divides by 1e18: [10](#0-9) 

The inflated Suilend position value is then stored in the vault's asset value table: [11](#0-10) 

And summed into the total USD value used for share ratio calculations: [12](#0-11) 

### Impact Explanation

**Direct Fund Impact - CRITICAL:**

1. **Massive Value Inflation:** A Suilend position worth $1,000 is reported as $1,000,000,000,000 (1 trillion dollars) - inflated by exactly 1 billion times (1e9).

2. **Share Ratio Manipulation:** The vault's share ratio is calculated as: [13](#0-12) 

   With inflated Suilend values, `total_usd_value` becomes artificially massive, causing:
   - **Depositor Loss:** New depositors receive 1 billion times fewer shares than they should, losing virtually all their funds
   - **Withdrawer Theft:** Existing shareholders can withdraw up to 1 billion times more value than they're entitled to, draining the vault

3. **Loss Tolerance Bypass:** The inflated total value masks real trading losses, bypassing the vault's loss protection mechanisms.

**Affected Parties:**
- All depositors to vaults using Suilend positions lose funds
- Existing shareholders can steal from the vault
- Protocol becomes insolvent

### Likelihood Explanation

**Likelihood: HIGH - Occurs automatically during normal operations**

1. **Reachable Entry Point:** The vulnerability triggers through the public entry function: [14](#0-13) 

2. **No Special Preconditions:** 
   - Operators call this function during normal vault operations (step 2 of the three-step operation flow)
   - No malicious intent required - the bug triggers automatically
   - Affects any vault with Suilend positions

3. **Execution Practicality:** 
   - The bug occurs in normal calculation logic
   - No complex attack sequence needed
   - Happens every time Suilend position values are updated

4. **Detection Difficulty:**
   - The mock tests don't catch this because they use unscaled values: [15](#0-14) 

### Recommendation

**Immediate Fix:**

Change line 88 in `suilend_adaptor.move` to divide by the correct scaling factor (1e18 instead of 1e9):

```move
// Current (INCORRECT):
const DECIMAL: u256 = 1_000_000_000; // 1e9

// Should be (CORRECT):
const DECIMAL: u256 = 1_000_000_000_000_000_000; // 1e18 - matches Suilend's WAD
```

Or better yet, use the same pattern as other adaptors and remove the division entirely since `to_scaled_val()` already returns the value in the correct format (just needs to be divided by 1e18 to get unscaled value).

**Additional Safeguards:**

1. Add integration tests that verify Suilend position values match expected USD amounts
2. Add assertions to validate that all asset USD values are within reasonable bounds relative to actual market prices
3. Implement cross-adaptor value consistency checks

**Test Case to Prevent Regression:**

Create a test that:
1. Sets up a Suilend position with known deposit/borrow amounts
2. Calls `parse_suilend_obligation()` with real Suilend Decimal values
3. Verifies the returned USD value matches the expected unscaled amount
4. Compares against other adaptor outputs to ensure consistency

### Proof of Concept

**Initial State:**
- Vault has 1,000 SUI principal worth $3,000 (at $3/SUI)
- Vault has a Suilend position: 1,000 USDC deposited, 0 borrowed
- Expected Suilend position value: $1,000
- Expected total vault value: $4,000
- Total shares: 4,000e9

**Transaction Steps:**

1. Operator calls `update_suilend_position_value()` during normal operations
2. Function calls `parse_suilend_obligation()` which:
   - Gets `market_value` as Decimal with value = 1000 * 1e18 = 1,000,000,000,000,000,000,000
   - Calls `to_scaled_val()` returning 1,000,000,000,000,000,000,000
   - Divides by DECIMAL (1e9): 1,000,000,000,000,000,000,000 / 1,000,000,000 = 1,000,000,000,000
   - Returns 1,000,000,000,000 instead of 1,000

3. Vault stores this inflated value and calculates total USD value:
   - Principal: $3,000
   - Suilend (INCORRECT): $1,000,000,000,000  
   - Total: $1,000,000,003,000

4. Share ratio calculation:
   - Share ratio = $1,000,000,003,000 * 1e9 / 4,000e9 ≈ 250,000,000.75e9

**Expected Result:**
- Suilend value: $1,000
- Total value: $4,000
- Share ratio: 1e9 (1:1)

**Actual Result:**
- Suilend value: $1,000,000,000,000 (inflated by 1 billion times)
- Total value: $1,000,000,003,000 (massively inflated)
- Share ratio: 250,000,000.75e9 (250 million times normal)

**Success Condition (Exploit):**
- A depositor deposits $1,000 expecting ~1000e9 shares, but receives only ~4 shares (losing 99.9999996% of their deposit)
- An existing shareholder with 1000e9 shares can withdraw ~$250,000,000,000 worth of assets (stealing from the vault)

### Citations

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L10-10)
```text
const DECIMAL: u256 = 1_000_000_000;
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L42-89)
```text
public(package) fun parse_suilend_obligation<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &LendingMarket<ObligationType>,
    clock: &Clock,
): u256 {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());

    let mut total_deposited_value_usd = 0;
    let mut total_borrowed_value_usd = 0;
    let reserves = lending_market.reserves();

    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L1-9)
```text
/// fixed point decimal representation. 18 decimal places are kept.
module suilend::decimal {
    // 1e18
    const WAD: u256 = 1000000000000000000;
    const U64_MAX: u256 = 18446744073709551615;

    public struct Decimal has copy, drop, store {
        value: u256,
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L47-49)
```text
    public fun to_scaled_val(v: Decimal): u256 {
        v.value
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L261-272)
```text
    public fun market_value<P>(
        reserve: &Reserve<P>, 
        liquidity_amount: Decimal
    ): Decimal {
        div(
            mul(
                price(reserve),
                liquidity_amount
            ),
            decimal::from(std::u64::pow(10, reserve.mint_decimals))
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L300-311)
```text
    public fun ctoken_market_value<P>(
        reserve: &Reserve<P>, 
        ctoken_amount: u64
    ): Decimal {
        // TODO should i floor here?
        let liquidity_amount = mul(
            decimal::from(ctoken_amount),
            ctoken_ratio(reserve)
        );

        market_value(reserve, liquidity_amount)
    }
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L65-78)
```text
        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L71-74)
```text
    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L65-75)
```text
    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );

    vault_share_value + pending_deposit_value + claimable_principal_value
```

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/volo_vault.move (L1177-1203)
```text
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1254-1278)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
```

**File:** volo-vault/sources/volo_vault.move (L1297-1310)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

```

**File:** volo-vault/tests/mock/mock_suilend.move (L45-49)
```text
public fun calculate_suilend_obligation_value<PoolType>(
    obligation: &MockSuilendObligation<PoolType>,
): u256 {
    obligation.usd_value as u256
}
```
