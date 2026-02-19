### Title
Inconsistent Price Oracle Sources Across Vault Adaptors Leading to TVL Manipulation

### Summary
The Volo vault system uses inconsistent price sources when calculating position values across different DeFi protocol adaptors. While Navi, Cetus, and Momentum adaptors use the vault's Switchboard-based oracle, the Suilend adaptor uses Suilend's internal Pyth-based reserve prices. This discrepancy creates inconsistent TVL calculations, enabling unfair value transfers between depositors during price divergences.

### Finding Description

The external vulnerability involves different functions accessing attributes from different storage locations (CapyLabsApp vs Mint objects), causing inconsistent behavior. Volo exhibits an analogous vulnerability where functionally similar operations (calculating DeFi position values) access price data from different oracle sources.

**Price Source Discrepancies:**

1. **Navi Adaptor** uses the vault's Switchboard oracle: [1](#0-0) 

2. **Cetus Adaptor** uses the vault's Switchboard oracle: [2](#0-1) 

3. **Momentum Adaptor** uses the vault's Switchboard oracle: [3](#0-2) 

4. **Suilend Adaptor** uses Suilend's internal Pyth-based prices: [4](#0-3) [5](#0-4) 

The Suilend reserve's `market_value` functions internally reference `reserve.price`: [6](#0-5) [7](#0-6) 

**TVL Calculation Impact:**

All position values feed into the vault's total USD value calculation: [8](#0-7) 

The share ratio is derived from this TVL: [9](#0-8) 

**Exploit Path:**

When deposits are executed, the share calculation uses this potentially manipulated share ratio: [10](#0-9) 

When withdrawals are executed, users receive value based on the inconsistent share ratio: [11](#0-10) 

**Why Protections Fail:**

While both oracle systems enforce staleness checks: [12](#0-11) 

There is **no check enforcing price consistency across different oracle sources** for the same underlying asset. Switchboard and Pyth prices can legitimately diverge within their freshness windows (< 1 minute) due to different update times, aggregation methods, and data sources.

### Impact Explanation

**Concrete Protocol Impact:**

1. **TVL Manipulation**: When the vault holds the same asset (e.g., SUI) in both Navi and Suilend positions, inconsistent pricing causes incorrect TVL. If Switchboard shows SUI=$2.10 while Suilend's Pyth shows SUI=$2.00, a vault with 1000 SUI in each protocol would report $4,100 TVL instead of the correct $4,000 or $4,200.

2. **Unfair Value Transfer**: The inflated/deflated share ratio causes:
   - Depositors receive incorrect share amounts relative to their actual contribution
   - Withdrawers extract incorrect value relative to their share ownership
   - Early participants profit at the expense of later participants (or vice versa)

3. **Share Ratio Corruption**: The fundamental vault invariant "share_ratio = total_assets / total_shares" becomes incorrect due to inconsistent asset valuation.

**Severity Justification:** High severity due to direct impact on user funds through incorrect share pricing affecting all deposits and withdrawals during price divergence periods.

### Likelihood Explanation

**Realistic Exploit Feasibility:**

1. **Reachable by Untrusted Actors**: Any user can call deposit/withdraw functions through public entry points: [13](#0-12) [14](#0-13) 

2. **Feasible Preconditions**: 
   - Vault must have positions in both Suilend and at least one other protocol (Navi/Cetus/Momentum)
   - Price divergence between Switchboard and Pyth (realistic due to different update mechanisms)
   - Even 1-2% divergence creates exploitable value transfer with large deposit/withdrawal amounts

3. **Executable Sequence**:
   - Step 1: Monitor for price divergence between Switchboard and Pyth oracles
   - Step 2: Request deposit when share ratio is favorable (prices diverged in user's favor)
   - Step 3: Operator executes deposit, minting shares at incorrect ratio
   - Step 4: Wait for price convergence
   - Step 5: Request and execute withdrawal at corrected share ratio
   - Result: Value extracted from other depositors

4. **Not Blocked**: No existing check validates price consistency across oracle sources. The loss tolerance mechanism only checks TVL decreases during operations, not pricing inconsistencies: [15](#0-14) 

### Recommendation

**Code-Level Mitigation:**

1. **Unified Oracle Source**: Migrate all adaptors to use a single, consistent price oracle source (vault's OracleConfig) for all position valuations. Modify the Suilend adaptor to:
   - Query asset prices from `vault_oracle::get_normalized_asset_price()` instead of `reserve::market_value()`
   - Calculate position values using vault oracle prices consistently with other adaptors

2. **Price Consistency Validation**: Add a validation check in `get_total_usd_value()` that compares prices from different sources for overlapping assets and aborts if divergence exceeds a threshold (e.g., 0.5%).

3. **Oracle Source Documentation**: Clearly document which oracle source should be used for each adaptor and enforce this through code reviews and testing.

### Proof of Concept

**Initial State:**
- Vault holds 1000 SUI in Navi position (uses Switchboard oracle)
- Vault holds 1000 SUI in Suilend position (uses Suilend's Pyth oracle)
- User A has 100 shares representing 100% of vault
- Actual vault value: 2000 SUI

**Step 1 - Price Divergence Occurs:**
- Switchboard oracle: SUI = $2.10
- Suilend Pyth oracle: SUI = $2.00
- Both within 1-minute freshness window

**Step 2 - TVL Calculation:**
- `update_navi_position_value()` called: 1000 SUI × $2.10 = $2,100
- `update_suilend_position_value()` called: 1000 SUI × $2.00 = $2,000
- Total TVL = $4,100 (inflated by $100)
- Share ratio = $4,100 / 100 shares = $41/share

**Step 3 - User B Deposits:**
- User B deposits 1000 SUI
- Free principal updated: 1000 SUI × $2.10 = $2,100 (using Switchboard)
- New shares = $2,100 / $41 = 51.22 shares
- Total shares = 151.22 shares

**Step 4 - Prices Converge:**
- Both oracles updated to SUI = $2.00
- Actual TVL = 3000 SUI × $2.00 = $6,000
- Corrected share ratio = $6,000 / 151.22 = $39.68/share

**Step 5 - Value Transfer:**
- User A's value: 100 × $39.68 = $3,968 (lost $32 from original $4,000)
- User B's value: 51.22 × $39.68 = $2,032 (gained $32 from deposited $2,000)

**Result:** The inconsistent oracle sources enabled a $32 value transfer from User A to User B (0.8% loss to existing depositors) due to temporarily inflated TVL during the price divergence window.

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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L77-80)
```text
        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L249-250)
```text
    public fun price<P>(reserve: &Reserve<P>): Decimal {
        reserve.price
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

**File:** volo-vault/sources/volo_vault.move (L806-812)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
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

**File:** volo-vault/sources/volo_vault.move (L994-1002)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1006-1022)
```text
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

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

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
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
}
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

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```
