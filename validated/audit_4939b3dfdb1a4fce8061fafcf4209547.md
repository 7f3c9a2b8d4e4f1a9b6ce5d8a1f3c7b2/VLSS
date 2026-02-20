# Audit Report

## Title
Stale Oracle Price Vulnerability in Navi Position Valuation Due to Two-Layer Caching

## Summary
The vault's oracle system implements a two-layer price caching mechanism where the `OracleConfig` caches Switchboard prices for up to 60 seconds, while the vault requires asset values to be updated in the same transaction. This architectural mismatch allows operators to perform vault operations using oracle prices that are up to 1 minute stale, enabling exploitation of favorable stale prices to understate losses and potentially bypass loss tolerance protections.

## Finding Description

The vulnerability stems from a critical disconnect between two different staleness validation mechanisms operating at different protocol layers:

**Layer 1 - OracleConfig Cache:** The `OracleConfig` stores cached prices with a default `update_interval` of 60 seconds (1 minute). [1](#0-0)  This cache is initialized with this interval by default. [2](#0-1) 

**Layer 2 - Vault Asset Values:** The vault enforces that asset VALUES must be updated within `MAX_UPDATE_INTERVAL = 0`, meaning they must be updated in the same transaction. [3](#0-2)  This is enforced when calculating total USD value. [4](#0-3) 

**The Critical Flaw:** When `calculate_navi_position_value()` is called to value Navi positions, it uses `vault_oracle::get_asset_price()` to fetch prices. [5](#0-4) 

The `get_asset_price()` function only validates that the CACHED price was updated within the oracle's `update_interval` (60 seconds), not the actual Switchboard aggregator's current timestamp. [6](#0-5) 

While `get_current_price()` properly validates Switchboard's timestamp when fetching fresh prices, [7](#0-6)  this validation only occurs when `update_price()` is explicitly called to refresh the cache. [8](#0-7) 

**Exploitation Scenario:**
1. At time T=0: Someone calls `update_price()` to cache Switchboard price P1=$2000
2. At time T=30s: Market crashes, Switchboard shows P2=$1900
3. At time T=45s: Operator begins operation and calls `update_navi_position_value()` which uses cached P1=$2000 (still valid, within 60s window)
4. Operator's Navi position is overvalued by ~5% due to stale price
5. After performing operations that lose value, operator updates again at T=55s, still using stale P1
6. Loss calculation compares before/after values both using inflated prices, understating actual losses

This allows operators to bypass the loss tolerance check implemented in `end_op_value_update_with_bag()`. [9](#0-8) 

## Impact Explanation

**High Severity - Protocol Integrity Compromise**

1. **Loss Tolerance Bypass:** The vault implements per-epoch loss tolerance to protect depositors from excessive losses. By using stale prices that don't reflect current market conditions, operators can understate losses in USD terms, allowing operations that exceed the intended risk limits to pass validation checks. [10](#0-9) 

2. **Share Ratio Manipulation:** When users deposit or withdraw, share ratios are calculated based on total vault USD value. [11](#0-10)  Stale prices lead to incorrect valuations, causing unfair share distributions that can extract value from existing depositors.

3. **Accounting Corruption:** In volatile crypto markets, prices can move 1-5% within 60 seconds. For a vault with $1M in Navi positions, this represents $10K-$50K of potential mispricing, directly affecting all vault participants.

4. **Systemic Risk:** The vulnerability affects all vault operations that rely on oracle prices, not just Navi positions, as the same `get_asset_price()` mechanism is used throughout the vault system for all asset valuations. [12](#0-11) 

## Likelihood Explanation

**High Likelihood - Readily Exploitable**

1. **Standard Operation Flow:** The vulnerable code path is triggered during normal vault operations. Any operator performing routine operations can exploit this vulnerability without special setup. [13](#0-12) 

2. **Operator Control:** While `update_price()` is a public function that anyone can call [14](#0-13) , operators control the TIMING of their operations. They can strategically execute operations when cached prices are favorable relative to current market prices.

3. **Market Conditions:** Cryptocurrency markets are inherently volatile. 60-second price movements of 1-5% occur regularly, especially during high volatility periods, providing frequent exploitation opportunities.

4. **No Detection:** The exploitation is difficult to detect as all protocol checks pass - the cached price is within its configured staleness limit, making the operation appear legitimate from an on-chain perspective.

5. **Economic Incentive:** For operators managing large positions, the ability to understate losses or manipulate share ratios provides clear financial incentives with minimal cost (only gas fees).

## Recommendation

Implement one of the following solutions:

**Solution 1 (Recommended): Eliminate the cache layer for critical operations**
- Modify `update_navi_position_value()` and similar adaptor functions to call `update_price()` first, then use the freshly validated price
- This ensures Switchboard's timestamp validation always occurs before using prices for loss tolerance calculations

**Solution 2: Synchronize staleness windows**
- Reduce `OracleConfig.update_interval` to match the vault's `MAX_UPDATE_INTERVAL = 0`
- This eliminates the semantic gap but may increase gas costs due to more frequent Switchboard validations

**Solution 3: Add direct Switchboard validation in critical paths**
- Modify `get_asset_price()` to optionally perform direct Switchboard timestamp validation when called during operations
- Add a parameter to indicate if strict freshness is required

## Proof of Concept

The vulnerability can be demonstrated through the following transaction sequence:

```
1. Call update_price(oracle_config, switchboard_aggregator, clock, "SUI")
   - Caches current Switchboard price at T=0
   
2. Wait 45 seconds (market moves but cache still valid)
   
3. Operator calls start_op_with_bag()
   - Records total_usd_value using get_total_usd_value()
   - All asset values use get_asset_price() which returns 45s-old cached price
   
4. Operator performs operations that lose value
   
5. Operator calls update_navi_position_value()
   - Still uses cached price from T=0 (now 55s old, but < 60s limit)
   - Asset value appears "updated" (same transaction) but uses stale price
   
6. Operator calls end_op_value_update_with_bag()
   - Calculates loss using before/after values both based on stale prices
   - Loss appears smaller than actual market loss
   - Passes loss tolerance check that should have failed
```

The test would demonstrate that:
- `get_asset_price()` returns cached prices up to 60 seconds old
- `get_total_usd_value()` accepts these values as "fresh" if updated in same transaction
- Loss tolerance calculations use these potentially stale valuations
- Actual market losses can be understated by the price staleness percentage

## Notes

This vulnerability is a **design flaw** in the oracle architecture where two well-intentioned safety mechanisms (cached prices for gas efficiency + same-transaction value updates for freshness) interact to create an exploitable window. The issue is exacerbated by:

1. The public nature of `update_price()` means operators cannot be prevented from letting the cache age
2. The 60-second window is long enough for significant market movements in crypto assets
3. The vault's `MAX_UPDATE_INTERVAL = 0` creates false confidence that values are always current

The fix requires careful consideration of the trade-off between gas efficiency (caching) and security (freshness guarantees).

### Citations

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
```

**File:** volo-vault/sources/oracle.move (L89-89)
```text
        update_interval: MAX_UPDATE_INTERVAL,
```

**File:** volo-vault/sources/oracle.move (L135-135)
```text
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L259-259)
```text
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1109-1113)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );
```

**File:** volo-vault/sources/volo_vault.move (L1266-1266)
```text
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
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

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/operation.move (L94-207)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);

    let mut defi_assets = bag::new(ctx);

    let defi_assets_length = defi_asset_ids.length();
    assert!(defi_assets_length == defi_asset_types.length(), ERR_ASSETS_LENGTH_MISMATCH);

    let mut i = 0;
    while (i < defi_assets_length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = vault.borrow_defi_asset<T, CetusPosition>(cetus_asset_type);
            defi_assets.add<String, CetusPosition>(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let obligation_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = vault.borrow_defi_asset<T, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
            );
            defi_assets.add<String, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
                obligation,
            );
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = vault.borrow_defi_asset<T, Receipt>(receipt_asset_type);
            defi_assets.add<String, Receipt>(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    let principal_balance = if (principal_amount > 0) {
        vault.borrow_free_principal(principal_amount)
    } else {
        balance::zero<T>()
    };

    let coin_type_asset_balance = if (coin_type_asset_amount > 0) {
        vault.borrow_coin_type_asset<T, CoinType>(
            coin_type_asset_amount,
        )
    } else {
        balance::zero<CoinType>()
    };

    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };

    emit(OperationStarted {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount,
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount,
        total_usd_value,
    });

    (defi_assets, tx, tx_for_check_value_update, principal_balance, coin_type_asset_balance)
}
```

**File:** volo-vault/sources/operation.move (L361-364)
```text
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
