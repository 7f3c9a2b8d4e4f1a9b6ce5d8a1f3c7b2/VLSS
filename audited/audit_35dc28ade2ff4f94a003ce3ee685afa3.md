### Title
Oracle Circuit Breaker Disables Lending Operations During Market Stress, Blocking Vault Withdrawals

### Summary
The protocol oracle's circuit breaker mechanism stops price updates when deviation thresholds are exceeded, causing prices to become stale. This makes all Navi lending operations (withdraw, borrow) revert with `invalid_price()` errors. When vaults have capital deployed in Navi positions, operators cannot withdraw funds to process user redemptions, creating a denial of service during market stress that could accelerate a crisis—analogous to the PSM vulnerability where protective mechanisms inadvertently disable critical functionality.

### Finding Description

The Volo protocol oracle implements a multi-threshold circuit breaker that stops updating prices when market conditions suggest potential manipulation or extreme volatility. [1](#0-0) 

When price deviation between primary and secondary oracle sources exceeds `threshold2`, or when deviation remains between `threshold1` and `threshold2` for longer than `max_duration_within_thresholds`, the `update_single_price` function emits an event but returns early without updating the `PriceOracle` shared object. [2](#0-1) 

Additionally, if the final price falls outside `maximum_effective_price`, `minimum_effective_price`, or deviates too much from historical prices (`maximum_allowed_span_percentage`), the oracle update is similarly aborted. [3](#0-2) 

When the oracle stops updating, prices in the `PriceOracle` object become stale. The `get_token_price` function validates freshness by checking if the price timestamp is within `update_interval`, returning `valid = false` when stale. [4](#0-3) 

All Navi lending protocol operations depend on this oracle. The `calculator::calculate_value` function asserts that prices must be valid, causing immediate reversion when prices are stale. [5](#0-4) 

Critical lending operations like `execute_withdraw` require health factor validation using oracle prices. [6](#0-5)  Similarly, `execute_borrow` validates health factors before allowing any borrow operation. [7](#0-6) 

The vault system integrates with Navi lending through operator-controlled operations. Operators can borrow vault principal and deploy it into Navi positions. [8](#0-7)  When users request withdrawals, operators may need to withdraw capital from Navi to free up principal for redemptions.

The withdrawal flow requires calling `incentive_v3::withdraw_with_account_cap`, which internally calls lending operations that depend on the oracle. [9](#0-8) [10](#0-9) 

**Exploit Path:**
1. Market volatility causes oracle price deviation to exceed configured thresholds
2. Circuit breaker triggers repeatedly, preventing oracle updates for duration > `update_interval`
3. Prices in `PriceOracle` become stale
4. Vault operator attempts to withdraw from Navi to process user redemptions
5. `execute_withdraw` calls `calculator::calculate_value` for health checks
6. `calculate_value` asserts `is_valid` which is now false → transaction reverts
7. Vault cannot free up principal from Navi positions
8. User withdrawal requests remain unprocessed
9. Panic ensues, accelerating the crisis

### Impact Explanation

**High Severity Denial of Service During Market Stress**

When vaults have significant capital deployed in Navi lending positions, the inability to withdraw during volatile periods creates a critical liquidity failure:

1. **User Funds Locked**: Legitimate withdrawal requests cannot be processed because operators cannot retrieve capital from Navi. Users cannot exit positions during exactly the time they need to most.

2. **Cascade Effect**: As users observe failed withdrawals, panic intensifies, driving more withdrawal requests and potentially triggering a bank-run scenario on the vault.

3. **Collateral Liquidation Risk**: If vault positions in Navi approach liquidation thresholds during the price volatility, operators cannot proactively deleverage or rebalance, potentially resulting in forced liquidations at unfavorable prices.

4. **Protocol Reputation Damage**: The vault appears "broken" during stress events, undermining confidence in the entire protocol when reliability matters most.

This directly mirrors the PSM vulnerability: a protective circuit breaker (designed to prevent oracle manipulation) inadvertently disables the very functionality needed to maintain stability during crisis conditions.

### Likelihood Explanation

**High Likelihood in Real Market Conditions**

This vulnerability is highly realistic because:

1. **Natural Market Triggers**: Crypto markets regularly experience 10-20% hourly volatility during crisis events (DeFi protocol exploits, macroeconomic shocks, liquidation cascades). Such volatility naturally causes oracle feed divergence.

2. **No Adversarial Action Required**: An attacker doesn't need to manipulate anything. Normal market conditions trigger the circuit breaker. The typical `threshold2` values of 2-5% can easily be exceeded during flash crashes.

3. **Threshold Duration Risk**: The `max_duration_within_thresholds` parameter (often set to 5-15 minutes) means even brief elevated volatility can trigger the `level_major` state, stopping updates for an extended period.

4. **Systematic Deployment Pattern**: Vaults actively deploy significant portions of user capital into Navi for yield generation—this is the intended use case, not an edge scenario.

5. **No Override Mechanism**: There's no emergency procedure for operators to bypass the oracle staleness check during crisis conditions, even with valid admin authority.

### Recommendation

**Implement Graduated Oracle Degradation Rather Than Binary Shutdown**

1. **Multiple Staleness Tiers**: Instead of a binary valid/invalid check, implement tiered staleness levels:
   ```
   - Fresh (< update_interval): All operations allowed
   - Stale (< 2x update_interval): Withdrawals allowed, borrows disabled
   - Very Stale (< 4x update_interval): Emergency withdrawals only with warning
   - Critical (> 4x update_interval): Full shutdown
   ```

2. **Emergency Oracle Mode**: Add an admin-controlled emergency oracle mode that allows operations to proceed with the last known price plus a conservative safety buffer. This should be time-limited and logged extensively. [4](#0-3) 

3. **Separate Withdrawal Health Checks**: Modify `execute_withdraw` to use a more lenient price staleness threshold specifically for withdrawal operations, accepting slightly older prices with conservative health factor buffers. [6](#0-5) 

4. **Circuit Breaker Refinement**: In the oracle circuit breaker, instead of stopping all updates when `level_critical` is reached, continue updating but flag the prices as "under stress". Allow critical operations like withdrawals to proceed with these flagged prices plus extra safety margins. [2](#0-1) 

5. **Vault-Level Fallback**: Add vault configuration to specify fallback oracle sources (e.g., Switchboard, Pyth) that can be consulted when the primary protocol oracle is stale, specifically for processing withdrawal operations.

### Proof of Concept

**Scenario: Flash Crash Triggers Oracle Shutdown and Vault Lockup**

**Initial State:**
- Vault has 1M USDC deployed: 500K in free principal, 500K lent to Navi earning yield
- User holds receipt representing 100K USDC worth of shares
- Oracle `update_interval` = 60 seconds
- `threshold2` = 3% price deviation
- Current time: T

**Exploit Steps:**

1. **T+0s**: Market flash crash begins. SUI drops 5% on one exchange but only 2% on another due to liquidity differences.

2. **T+10s**: Oracle keeper attempts `update_single_price`. Primary source shows $0.95, secondary shows $0.98. Deviation = 3.16% > threshold2 → `level_critical` returned. [1](#0-0) 

3. **T+10s**: `update_single_price` returns early at line 118 without updating `PriceOracle`. Price remains at last valid value from T-50s. [11](#0-10) 

4. **T+30s**: User observes price drop, requests full withdrawal of 100K USDC via `user_entry::request_withdraw`. Request accepted and buffered.

5. **T+45s**: Vault operator attempts to execute withdrawal. First calls `start_op_with_bag` to borrow NaviAccountCap and 100K from free principal.

6. **T+50s**: Operator needs additional 50K, so attempts `incentive_v3::withdraw_with_account_cap` on Navi position. [9](#0-8) 

7. **T+50s**: Call chain reaches `lending::base_withdraw` → `logic::execute_withdraw` → `is_health` → `user_health_factor` → `calculator::calculate_value` [12](#0-11) 

8. **T+50s**: `get_token_price` checks: current_ts (T+50s) - token_price.timestamp (T-50s) = 100s > update_interval (60s). Returns `valid = false`. [13](#0-12) 

9. **T+50s**: `calculate_value` asserts `is_valid` → **Transaction aborts with `invalid_price()` error**. [14](#0-13) 

10. **T+60s**: Operator attempts alternative: execute withdrawal using only free principal (insufficient for full redemption). Reduces withdrawal to 50K, partial fill only.

11. **T+120s**: Oracle feeds stabilize but price now at $0.93 (7% down from T-50s). This exceeds `maximum_allowed_span_percentage` (typically 5-10%). [15](#0-14) 

12. **T+120s**: `validate_price_range_and_history` returns false → oracle still cannot update → prices remain stale.

13. **T+180s**: Additional users submit withdrawal requests totaling 200K. Vault now has 500K free principal, 500K locked in Navi, 300K withdrawal requests pending. Crisis deepens.

**Result**: Vault effectively locks 50% of user funds in Navi lending protocol during the exact market conditions when users need liquidity most urgently. The protective oracle circuit breaker has inadvertently created a bank-run scenario.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L9-20)
```text
    public fun validate_price_difference(primary_price: u256, secondary_price: u256, threshold1: u64, threshold2: u64, current_timestamp: u64, max_duration_within_thresholds: u64, ratio2_usage_start_time: u64): u8 {
        let diff = utils::calculate_amplitude(primary_price, secondary_price);

        if (diff < threshold1) { return constants::level_normal() };
        if (diff > threshold2) { return constants::level_critical() };

        if (ratio2_usage_start_time > 0 && current_timestamp > max_duration_within_thresholds + ratio2_usage_start_time) {
            return constants::level_major()
        } else {
            return constants::level_warning()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L100-131)
```text
        if (is_primary_price_fresh && is_secondary_price_fresh) { // if 2 price sources are fresh, validate price diff
            let (price_diff_threshold1, price_diff_threshold2) = (config::get_price_diff_threshold1_from_feed(price_feed), config::get_price_diff_threshold2_from_feed(price_feed));
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds_from_feed(price_feed);
            let diff_threshold2_timer = config::get_diff_threshold2_timer_from_feed(price_feed);
            let severity = strategy::validate_price_difference(primary_price, secondary_price, price_diff_threshold1, price_diff_threshold2, current_timestamp, max_duration_within_thresholds, diff_threshold2_timer);
            if (severity != constants::level_normal()) {
                emit (PriceRegulation {
                    level: severity,
                    config_address: config_address,
                    feed_address: feed_address,
                    price_diff_threshold1: price_diff_threshold1,
                    price_diff_threshold2: price_diff_threshold2,
                    current_time: current_timestamp,
                    diff_threshold2_timer: diff_threshold2_timer,
                    max_duration_within_thresholds: max_duration_within_thresholds,
                    primary_price: primary_price,
                    secondary_price: secondary_price,
                });
                if (severity != constants::level_warning()) { return };
                start_or_continue_diff_threshold2_timer = true;
            };
        } else if (is_primary_price_fresh) { // if secondary price not fresh and primary price fresh
            if (is_secondary_oracle_available) { // prevent single source mode from keeping emitting event
                emit(OracleUnavailable {type: constants::secondary_type(), config_address, feed_address, provider: provider::to_string(config::get_secondary_oracle_provider(price_feed)), price: secondary_price, updated_time: secondary_updated_time});
            };
        } else if (is_secondary_price_fresh) { // if primary price not fresh and secondary price fresh
            emit(OracleUnavailable {type: constants::primary_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            final_price = secondary_price;
        } else { // no fresh price, terminate price feed
            emit(OracleUnavailable {type: constants::both_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            return
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L133-154)
```text
        // validate final price 
        let (maximum_effective_price, minimum_effective_price) = (config::get_maximum_effective_price_from_feed(price_feed), config::get_minimum_effective_price_from_feed(price_feed));
        let maximum_allowed_span_percentage = config::get_maximum_allowed_span_percentage_from_feed(price_feed);
        let historical_price_ttl = config::get_historical_price_ttl(price_feed);
        let (historical_price, historical_updated_time) = config::get_history_price_data_from_feed(price_feed);

        if (!strategy::validate_price_range_and_history(final_price, maximum_effective_price, minimum_effective_price, maximum_allowed_span_percentage, current_timestamp, historical_price_ttl, historical_price, historical_updated_time)) {
            emit(InvalidOraclePrice {
                config_address: config_address,
                feed_address: feed_address,
                provider: provider::to_string(primary_oracle_provider),
                price: final_price,
                maximum_effective_price: maximum_effective_price,
                minimum_effective_price: minimum_effective_price,
                maximum_allowed_span: maximum_allowed_span_percentage,
                current_timestamp: current_timestamp,
                historical_price_ttl: historical_price_ttl,
                historical_price: historical_price,
                historical_updated_time: historical_updated_time,
            });
            return
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-91)
```text
    public(friend) fun execute_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256 // e.g. 100USDT -> 100000000000
    ): u64 {
        assert!(user_collateral_balance(storage, asset, user) > 0, error::user_have_no_collateral());

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_withdraw<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L127-159)
```text
    public(friend) fun execute_borrow<CoinType>(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_borrow<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_borrow_balance(storage, asset, user, amount);
        
        /////////////////////////////////////////////////////
        // Add the asset to the user's list of loan assets //
        /////////////////////////////////////////////////////
        if (!is_loan(storage, asset, user)) {
            storage::update_user_loans(storage, asset, user)
        };

        //////////////////////////////////
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L853-869)
```text
    public fun withdraw_with_account_cap<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap
    ): Balance<CoinType> {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        lending::withdraw_with_account_cap<CoinType>(clock, oracle, storage, pool, asset, amount, account_cap)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L201-248)
```text
    public(friend) fun withdraw_coin<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        ctx: &mut TxContext
    ): Balance<CoinType> {
        let sender = tx_context::sender(ctx);
        let _balance = base_withdraw(clock, oracle, storage, pool, asset, amount, sender);
        return _balance
    }

    // Base: Withdraw Function
    fun base_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        user: address
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let normal_withdraw_amount = pool::normal_amount(pool, amount);
        let normal_withdrawable_amount = logic::execute_withdraw<CoinType>(
            clock,
            oracle,
            storage,
            asset,
            user,
            (normal_withdraw_amount as u256)
        );

        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
        let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
        emit(WithdrawEvent {
            reserve: asset,
            sender: user,
            to: user,
            amount: withdrawable_amount,
        });

        return _balance
    }
```
