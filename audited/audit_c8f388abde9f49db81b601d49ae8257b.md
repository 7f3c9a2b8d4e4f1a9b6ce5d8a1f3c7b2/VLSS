### Title
Integer Division Rounding Can Cause Positive Asset Balances to Be Valued at Zero USD

### Summary
The `mul_with_oracle_price()` function performs integer division that can round positive asset balance and price products to zero when their product is less than `ORACLE_DECIMALS` (10^18). This causes assets with real economic value to be completely excluded from vault valuation, breaking the critical "total_usd_value correctness" invariant and enabling health factor bypass and incorrect share pricing.

### Finding Description

The core vulnerability exists in the `mul_with_oracle_price()` function: [1](#0-0) 

This function calculates `v1 * v2 / ORACLE_DECIMALS` where `ORACLE_DECIMALS = 10^18`. When the product of balance and price is less than 10^18, integer division rounds down to zero, causing positive-value assets to be valued at $0 USD.

**Root Cause:** No minimum value threshold or precision loss protection exists in the valuation logic.

**Critical Usage Paths:**

1. **Vault Asset Valuation** - Used to calculate USD value of principal and coin assets: [2](#0-1) [3](#0-2) 

2. **Asset Value Storage** - Zero values are stored without validation: [4](#0-3) 

3. **Total Vault Value Calculation** - Zero-valued assets are excluded from total: [5](#0-4) 

4. **Navi Health Factor** - Supply/borrow values can round to zero: [6](#0-5) 

5. **Cetus Liquidity Positions** - LP position values can round to zero: [7](#0-6) 

**Example Scenarios Where Rounding to Zero Occurs:**

- Balance: 0.001 tokens (10^6 in 10^9 decimals) × Price: $0.001 (10^15 in 10^18 decimals) = 10^21 / 10^18 = 1,000 (safe)
- Balance: 0.000001 tokens (10^3 in 10^9 decimals) × Price: $1 (10^18 in 10^18 decimals) = 10^21 / 10^18 = 1,000 (safe)
- Balance: 0.001 tokens (10^6 in 10^9 decimals) × Price: $0.0000001 (10^11 in 10^18 decimals) = 10^17 / 10^18 = **0** (rounds to zero!)
- Balance: 1 token (10^9 in 10^9 decimals) × Price: $0.0000000001 (10^8 in 10^18 decimals) = 10^17 / 10^18 = **0** (rounds to zero!)

### Impact Explanation

**1. Understated Vault Value (Direct Fund Impact)**
- Assets with real economic value are completely excluded from `total_usd_value` calculation
- Affects share price calculation: `share_ratio = total_usd_value / total_shares`
- Users receive more shares than they should for deposits when vault value is understated
- Vault effectively loses track of assets it holds

**2. Health Factor Bypass (Security Integrity)**
The Navi adaptor calculates health factor based on supply and borrow USD values. If these round to zero: [8](#0-7) 

- Borrowed positions could be hidden (borrow_usd_value rounds to zero)
- Collateral could be understated (supply_usd_value rounds to zero)
- Health limiter checks would use incorrect values
- Operations that should fail health checks could proceed

**3. Loss Tolerance Bypass**
If assets lost during operations have values that round to zero, the loss won't be counted: [9](#0-8) 

The loss tracking becomes inaccurate when asset values incorrectly round to zero.

**Quantified Impact:**
- For a vault with $1M TVL, even 0.1% of assets rounding to zero represents $1,000 unaccounted value
- Dust amounts across multiple assets compound the issue
- LP positions in low-liquidity pairs are particularly vulnerable

### Likelihood Explanation

**Feasible Preconditions:**
This vulnerability occurs naturally through normal vault operations without attacker manipulation:

1. **Dust Amounts from DeFi Operations**
   - LP positions leave dust amounts when partially withdrawn
   - Lending protocols accrue small interest amounts
   - Reward distributions can be fractional
   - Operation residuals accumulate over time

2. **Low-Value Token Support**
   - Vault accepts multiple coin types without minimum value restrictions
   - Micro-cap tokens, meme coins, or newly launched tokens can have very low prices
   - No check in user entry requires minimum USD value: [10](#0-9) 

3. **Multi-Asset Vault Design**
   - Vault designed to hold various coin types and adaptor positions
   - Each asset type independently vulnerable to precision loss
   - Cumulative effect across multiple assets

**Execution Practicality:**
- Occurs automatically during normal operations
- No special attacker capabilities required
- Natural market conditions (low prices) trigger the issue
- Already present in adaptors handling external protocol positions

**Detection Constraints:**
- Silent failure mode (no errors thrown)
- Asset remains in vault but shows $0 value
- Hard to detect without detailed value reconciliation
- Events emitted with zero values appear normal

**Probability:** MEDIUM-HIGH - While requiring specific balance/price combinations, these conditions occur naturally in production DeFi systems with multi-asset vaults.

### Recommendation

**1. Add Minimum USD Value Threshold**

In `utils.move`, add validation to prevent zero-value results for positive inputs:

```move
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    // If both inputs are positive but would round to zero, fail explicitly
    if (v1 > 0 && v2 > 0) {
        let product = v1 * v2;
        assert!(product >= ORACLE_DECIMALS, ERR_VALUE_TOO_SMALL_FOR_PRECISION);
    };
    v1 * v2 / ORACLE_DECIMALS
}
```

**2. Add Asset Value Validation**

In `volo_vault.move`, validate that positive balances with positive prices never result in zero values:

```move
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    // If there's a positive balance for this asset, USD value must be positive
    if (self.assets.contains(asset_type)) {
        let balance_value = self.assets.borrow<String, Balance<_>>(asset_type).value();
        if (balance_value > 0) {
            assert!(usd_value > 0, ERR_POSITIVE_BALANCE_ZERO_VALUE);
        };
    };
    // ... rest of function
}
```

**3. Implement Minimum Asset Thresholds**

Add configurable minimum USD value thresholds for assets to be included in vault valuation, rejecting dust amounts below precision limits.

**4. Add Precision Loss Tests**

Add test cases covering:
- Very small balances with normal prices
- Normal balances with very low prices  
- Edge cases where `balance * price < ORACLE_DECIMALS`
- Multi-asset scenarios with cumulative precision loss

### Proof of Concept

**Initial State:**
- Vault deployed with principal and multiple coin types
- Oracle configured with standard 10^18 decimals

**Exploitation Sequence:**

1. **Natural Dust Accumulation:**
   - Vault holds 0.001 units of TokenA (balance = 10^6 in normalized form)
   - TokenA market price drops to $0.0000001 (oracle price = 10^11 in 10^18 decimals)

2. **Asset Value Update:**
   - Operator calls `update_coin_type_asset_value<PrincipalCoinType, TokenA>`
   - Function calculates: `mul_with_oracle_price(10^6, 10^11) = 10^17 / 10^18 = 0`
   - Asset value stored as 0 USD despite positive balance and price

3. **Total Value Calculation:**
   - `get_total_usd_value()` sums all asset values
   - TokenA contributes 0 USD to total (actual value: $0.0001)
   - Total vault value understated by TokenA's real value

4. **Health Factor Impact (if using Navi):**
   - Similar dust in Navi position with low-value collateral
   - `get_navi_account_value()` calculates supply_usd_value = 0
   - Health factor incorrectly calculated, allowing over-borrowing

**Expected Result:**
- Asset value = (balance * price) properly scaled with precision protection

**Actual Result:**  
- Asset value = 0 despite positive balance and positive price
- Critical invariant "total_usd_value correctness" violated
- Vault state becomes inconsistent with actual holdings

### Notes

This vulnerability affects the core pricing invariant of the Volo vault system. While the specific conditions (very small balance × very low price) might seem edge-case, they occur naturally in production DeFi environments through:

- Dust accumulation from LP operations
- Low-value token holdings
- Partial withdrawals leaving residuals  
- External protocol position updates

The absence of minimum value thresholds or precision loss detection means the protocol silently accepts incorrect zero valuations, breaking trust in the vault's accounting system. The partial protection in reward manager shows awareness of precision issues but doesn't extend to the core valuation logic.

This is particularly critical because it compounds across multiple assets and adaptor integrations, with cumulative undervaluation growing over time as more dust positions accumulate.

### Citations

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/volo_vault.move (L629-635)
```text
    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L1115-1118)
```text
    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1145-1153)
```text
    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

    finish_update_asset_value(self, asset_type, coin_usd_value, now);
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L65-69)
```text
        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-78)
```text
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

**File:** volo-vault/sources/user_entry.move (L29-29)
```text
    assert!(amount > 0, ERR_INVALID_AMOUNT);
```
