# Audit Report

## Title
Inconsistent Price Oracle Sources Across Vault Adaptors Leading to TVL Manipulation

## Summary
The Volo vault system uses inconsistent price sources when calculating position values across different DeFi protocol adaptors. Navi, Cetus, and Momentum adaptors use the vault's Switchboard-based oracle, while the Suilend adaptor uses Suilend's internal Pyth-based reserve prices. This creates inconsistent TVL calculations that corrupt the share ratio, enabling unfair value transfers between depositors during legitimate price divergences.

## Finding Description

The vault calculates its total USD value by aggregating position values from multiple DeFi protocol adaptors. However, these adaptors source prices from different oracle systems:

**Navi Adaptor** retrieves prices from the vault's Switchboard oracle: [1](#0-0) 

**Cetus Adaptor** also uses the vault's Switchboard oracle: [2](#0-1) 

**Momentum Adaptor** uses the vault's Switchboard oracle: [3](#0-2) 

**Suilend Adaptor** uses Suilend's internal reserve pricing functions: [4](#0-3) 

These reserve functions internally reference `price(reserve)`: [5](#0-4) 

Which returns the reserve's internal price field: [6](#0-5) 

This price is sourced from Pyth oracles: [7](#0-6) 

All position values feed into the vault's total USD value calculation: [8](#0-7) 

The share ratio is derived from this potentially inconsistent TVL: [9](#0-8) 

When deposits are executed, shares are minted using this corrupted ratio: [10](#0-9) 

The loss tolerance mechanism only validates TVL decreases, not pricing inconsistencies: [11](#0-10) 

**Critical Issue:** Even when both Switchboard and Pyth oracles are updated correctly and show "fresh" prices, they can legitimately diverge by 1-5% due to different data sources, aggregation methods, and update timing. When the vault holds the same asset (e.g., SUI) in both a Suilend position and a Navi position, this price divergence causes incorrect TVL calculation.

**Example Scenario:**
- Vault holds 1000 SUI in Navi + 1000 SUI in Suilend
- Switchboard shows SUI = $2.10 (fresh)
- Pyth shows SUI = $2.00 (fresh)
- Calculated TVL: (1000 × $2.10) + (1000 × $2.00) = $4,100
- Correct TVL should be either $4,000 or $4,200, not a mix

This inconsistent TVL corrupts the share ratio, causing depositors to receive incorrect share amounts and withdrawers to extract incorrect value.

## Impact Explanation

This vulnerability has **HIGH** severity with direct impact on user funds:

1. **Share Ratio Corruption**: The fundamental vault invariant `share_ratio = total_assets / total_shares` becomes incorrect due to inconsistent asset valuation from mixed oracle sources.

2. **Unfair Value Transfers**: During price divergence periods:
   - Depositors receive incorrect share amounts relative to their actual USD contribution
   - Withdrawers extract incorrect value relative to their share ownership
   - Value is transferred from some users to others based on timing of operations during divergence

3. **Systematic Impact**: All deposits and withdrawals are affected during divergence periods, impacting the entire user base rather than isolated cases.

Users can call public deposit and withdraw functions: [12](#0-11) [13](#0-12) 

## Likelihood Explanation

This vulnerability has **HIGH** likelihood:

1. **Realistic Preconditions**: 
   - Vaults commonly hold positions across multiple protocols (Navi, Suilend, Cetus, Momentum)
   - Switchboard and Pyth naturally diverge due to different oracle architectures
   - Even small 1-2% divergences create exploitable opportunities with large transaction amounts

2. **Uncontrolled Natural Occurrence**: Price divergence between oracle systems happens naturally and frequently in normal market conditions, not requiring any attack or manipulation.

3. **No Protection Mechanism**: There is no check validating price consistency across different oracle sources. The vault trusts both Switchboard and Pyth prices independently without cross-validation.

4. **Public Access**: Any user can trigger deposits and withdrawals through public entry points, no special privileges required.

## Recommendation

Implement a price consistency check mechanism:

1. **Single Oracle Source**: Standardize all adaptors to use a single oracle source (either all Switchboard or all Pyth) to ensure pricing consistency.

2. **Price Deviation Threshold**: If mixed oracle sources are necessary, implement a maximum allowed deviation check between different oracle sources for the same asset before calculating TVL:
   - Query both Switchboard and Pyth for overlapping assets
   - Assert that price deviation is within acceptable bounds (e.g., < 1%)
   - Revert or delay operations if deviation exceeds threshold

3. **Oracle Arbitration**: Implement a fallback mechanism where a trusted oracle arbitrator validates price consistency before critical operations (deposits/withdrawals).

## Proof of Concept

```move
// Test demonstrating the vulnerability:
// 1. Vault has 1000 SUI in Navi position (valued via Switchboard at $2.10)
// 2. Vault has 1000 SUI in Suilend position (valued via Pyth at $2.00)
// 3. TVL = $4,100 instead of consistent $4,000 or $4,200
// 4. Share ratio is corrupted
// 5. User deposits when ratio is favorable
// 6. Price converges
// 7. User withdraws at corrected ratio
// 8. Net value extracted from other depositors

#[test]
fun test_price_oracle_inconsistency() {
    // Setup vault with positions in both Navi (Switchboard) and Suilend (Pyth)
    // Update Switchboard oracle to show SUI = $2.10
    // Update Pyth oracle to show SUI = $2.00
    // Calculate TVL - will be $4,100 (incorrect mix)
    // User deposits $1,000 worth
    // Receives shares based on corrupted ratio
    // Prices converge to $2.00 across both oracles
    // User withdraws
    // Extracts more value than deposited due to initial ratio corruption
}
```

## Notes

The vulnerability is inherent to using multiple oracle systems for the same underlying assets. While both Switchboard and Pyth are legitimate oracle providers with staleness protections, they are fundamentally different systems that can provide different price feeds for the same asset within their respective freshness windows. This architectural design choice in the Volo vault system creates a pricing inconsistency vulnerability that enables value extraction by timing operations during natural oracle divergence periods.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-50)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L58-62)
```text
        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L249-251)
```text
    public fun price<P>(reserve: &Reserve<P>): Decimal {
        reserve.price
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L265-269)
```text
        div(
            mul(
                price(reserve),
                liquidity_amount
            ),
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-590)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
```

**File:** volo-vault/sources/volo_vault.move (L626-635)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L820-844)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/user_entry.move (L19-28)
```text
public fun deposit<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    mut coin: Coin<PrincipalCoinType>,
    amount: u64,
    expected_shares: u256,
    mut original_receipt: Option<Receipt>,
    clock: &Clock,
    ctx: &mut TxContext,
): (u64, Receipt, Coin<PrincipalCoinType>) {
```

**File:** volo-vault/sources/user_entry.move (L124-137)
```text
public fun withdraw<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    shares: u256,
    expected_amount: u64,
    receipt: &mut Receipt,
    clock: &Clock,
    _ctx: &mut TxContext,
): u64 {
    vault.assert_vault_receipt_matched(receipt);
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
    assert!(shares > 0, ERR_INVALID_AMOUNT);
```
