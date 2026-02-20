# Audit Report

## Title
Zero Oracle Price Causes Division by Zero in Vault Share Calculations Leading to Complete DoS

## Summary
The Volo vault accepts zero prices from Switchboard oracles without validation, which causes the share ratio calculation to return zero when asset prices are zero. This zero share ratio triggers division by zero errors in `execute_deposit()` and `execute_withdraw()`, completely disabling all vault deposit and withdrawal operations until oracle prices are restored.

## Finding Description

The vulnerability exists across three interconnected components in the vault system:

**1. Oracle System Accepts Zero Prices Without Validation**

The vault's `update_price()` function accepts prices from Switchboard aggregators without any validation that the price must be greater than zero. [1](#0-0)  The `get_current_price()` function simply extracts the value from the Switchboard aggregator and casts it to u256 with no zero check. [2](#0-1) 

Switchboard's Decimal type can represent zero values through its `zero()` constructor, confirming zero prices are possible. [3](#0-2) 

**2. Zero Prices Propagate to Zero Share Ratio**

When oracle prices are zero, `update_free_principal_value()` calculates USD value by multiplying the principal balance by the zero price, resulting in `principal_usd_value = 0`. [4](#0-3) 

The `get_total_usd_value()` function sums all asset USD values. When all prices are zero, it returns `total_usd_value = 0`. [5](#0-4) 

When `total_usd_value = 0` and `total_shares > 0` (normal operational state with existing depositors), `get_share_ratio()` calculates `div_d(0, total_shares)` which equals zero. [6](#0-5) 

**3. Division by Zero in Critical Operations**

The `div_d()` utility function performs division as `v1 * DECIMALS / v2` without any zero check on the denominator. [7](#0-6) 

In `execute_deposit()`, when `share_ratio_before = 0`, line 844 performs `div_d(new_usd_value_deposited, 0)` to calculate user shares, causing division by zero. [8](#0-7) 

Similarly, `div_with_oracle_price()` has no zero check on the denominator. [9](#0-8) 

In `execute_withdraw()`, when the principal coin price is zero (obtained via `get_normalized_asset_price()`), line 1015 performs `div_with_oracle_price(usd_value_to_withdraw, 0)` to calculate withdrawal amount, causing division by zero. [10](#0-9) 

## Impact Explanation

This vulnerability has **HIGH severity** due to complete operational failure:

- **Complete DoS**: All `execute_deposit()` and `execute_withdraw()` transactions abort with arithmetic errors (division by zero), making the vault completely non-functional
- **Capital Lock**: Users with pending deposit/withdrawal requests cannot execute them, effectively locking their funds indefinitely until oracle prices are restored
- **No User Recovery**: Users cannot bypass this issue through any transaction parameter adjustments or alternative paths
- **Protocol Revenue Loss**: No deposit/withdrawal fees can be collected during the outage period
- **Operational Disruption**: The vault remains stuck until external oracle prices are fixed, which may take time depending on the oracle provider's response

While funds are not directly stolen, the complete inability for users to access their capital during oracle failures represents a critical availability failure that violates core protocol guarantees of fund accessibility.

## Likelihood Explanation

This vulnerability has **MODERATE likelihood** based on:

**Preconditions:**
1. Vault has existing depositors (`total_shares > 0`) - this is the normal operational state
2. Switchboard oracle returns zero price due to misconfiguration, oracle provider outage, or edge cases
3. Any user attempts to execute a pending deposit or withdrawal request

**Feasibility:**
- Oracle failures and zero price reports are realistic edge cases documented in oracle provider incidents
- The vulnerability requires no attacker action - it's a passive failure mode triggered by external oracle behavior
- Standard user operations (`execute_deposit`, `execute_withdraw`) trigger the bug through normal protocol flows
- No code enforcement prevents zero prices from being accepted and propagated

**No Mitigations Present:**
- No defensive zero-price validation in oracle update functions
- No zero-denominator checks in division utility functions
- No graceful degradation or circuit breaker mechanisms for oracle failures

## Recommendation

Implement comprehensive zero-price validation at multiple layers:

1. **Oracle Layer**: Add validation in `update_price()` to reject zero prices:
```move
public fun update_price(...) {
    let current_price = get_current_price(config, clock, aggregator);
    assert!(current_price > 0, ERR_INVALID_ZERO_PRICE);
    // ... rest of function
}
```

2. **Division Utility Layer**: Add zero checks in division functions:
```move
public fun div_d(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * DECIMALS / v2
}

public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * ORACLE_DECIMALS / v2
}
```

3. **Share Ratio Layer**: Add defensive check in `get_share_ratio()`:
```move
let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
assert!(share_ratio > 0, ERR_INVALID_SHARE_RATIO);
```

## Proof of Concept

```move
#[test]
#[expected_failure(arithmetic_error, location = vault_utils)]
public fun test_zero_oracle_price_causes_division_by_zero() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    let sui_asset_type = type_name::get<SUI_TEST_COIN>().into_string();
    
    // Set initial valid price and execute a deposit to establish total_shares > 0
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        vault_oracle::set_aggregator(&mut oracle_config, &clock, sui_asset_type, 9, MOCK_AGGREGATOR_SUI);
        vault_oracle::set_current_price(&mut oracle_config, &clock, sui_asset_type, 2 * ORACLE_DECIMALS);
        test_scenario::return_shared(oracle_config);
    };
    
    // Initial deposit to create shares
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let (_request_id, receipt, coin) = user_entry::deposit(&mut vault, &mut reward_manager, coin, 1_000_000_000, 1_000_000_000, option::none(), &clock, s.ctx());
        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Execute first deposit
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        vault::update_free_principal_value(&mut vault, &config, &clock);
        operation::execute_deposit(&operation, &cap, &mut vault, &mut reward_manager, &clock, &config, 0, 2_000_000_000);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(reward_manager);
    };
    
    // Set oracle price to ZERO (oracle failure)
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        clock::increment_for_testing(&mut clock, 2000);
        vault_oracle::set_current_price(&mut oracle_config, &clock, sui_asset_type, 0); // ZERO PRICE
        test_scenario::return_shared(oracle_config);
    };
    
    // Request another deposit
    s.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let (_request_id, receipt, coin) = user_entry::deposit(&mut vault, &mut reward_manager, coin, 1_000_000_000, 1_000_000_000, option::none(), &clock, s.ctx());
        transfer::public_transfer(coin, ALICE);
        transfer::public_transfer(receipt, ALICE);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Attempt to execute deposit with zero oracle price -> DIVISION BY ZERO
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        vault::update_free_principal_value(&mut vault, &config, &clock); // Updates to zero USD value
        operation::execute_deposit(&operation, &cap, &mut vault, &mut reward_manager, &clock, &config, 1, 2_000_000_000); // FAILS: division by zero
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(reward_manager);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

The vulnerability is rooted in the assumption that oracle prices will always be positive, which is not guaranteed in practice. External oracle providers can experience outages, misconfigurations, or edge cases that result in zero or invalid prices being reported. The protocol should implement defensive validation to handle such scenarios gracefully rather than allowing complete DoS of critical operations.

### Citations

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
}
```

**File:** volo-vault/sources/volo_vault.move (L818-851)
```text
    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
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
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);

```

**File:** volo-vault/sources/volo_vault.move (L1005-1023)
```text
    // Get the current share ratio
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

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
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

**File:** volo-vault/sources/volo_vault.move (L1304-1318)
```text
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

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```
