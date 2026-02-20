# Audit Report

## Title
Oracle Aggregator Can Be Changed Mid-Operation Causing Inconsistent Price Sources for Loss Tolerance Validation

## Summary
The `change_switchboard_aggregator()` function lacks vault status validation, allowing the oracle price source to be changed while the vault is in `VAULT_DURING_OPERATION_STATUS`. This causes loss tolerance validation to compare total USD values computed from different price sources, breaking a critical security invariant that protects vault shareholders from excessive operational losses.

## Finding Description

The `change_switchboard_aggregator()` function in the vault management module only requires `AdminCap` and performs no vault status validation [1](#0-0) . This function delegates to the oracle implementation which immediately updates both the aggregator address and the stored price [2](#0-1) .

During vault operations, the loss tolerance mechanism relies on price consistency. When an operation starts via `start_op_with_bag()`, the vault status is set to `VAULT_DURING_OPERATION_STATUS` [3](#0-2)  and the initial total USD value is captured in `TxBagForCheckValueUpdate` [4](#0-3) .

An admin can call `change_switchboard_aggregator()` during the operation, which immediately updates the oracle's stored price without any vault status check. When the operation completes via `end_op_value_update_with_bag()`, it recalculates the total USD value and compares it to the initial value to detect losses [5](#0-4) .

The USD value calculation reads from the vault's `assets_value` table which is populated by calling oracle functions [6](#0-5) . Asset value updates use `get_normalized_asset_price()` [7](#0-6)  which reads the stored price from the oracle config [8](#0-7)  and [9](#0-8) .

**Root Cause:** The absence of vault status validation creates an inconsistent security model. Other critical admin functions like `set_enabled()` explicitly prevent modifications during operations [10](#0-9) . This protection is tested and enforced [11](#0-10) .

## Impact Explanation

This vulnerability directly compromises the loss_tolerance mechanism, which is a critical safety feature protecting vault shareholders from excessive operational losses.

**Concrete Harm Scenarios:**

1. **Loss Tolerance Bypass:** If the new aggregator reports higher prices than the old one, real operational losses can be masked. For example, if the vault loses 100,000 SUI tokens in a failed strategy, but the new aggregator values SUI 20% higher, the loss calculation will underestimate or completely hide the actual loss, allowing it to bypass the loss_tolerance check enforced at [12](#0-11) .

2. **Loss Tolerance Exhaustion:** If the new aggregator reports lower prices, artificial losses are created. A vault with no actual loss could show a significant USD value decrease purely from the price source change, consuming the epoch's loss_tolerance budget and potentially causing legitimate future operations to fail.

3. **Protocol Invariant Violation:** The loss_tolerance per epoch is designed to limit operator risk by ensuring that vault value changes stay within acceptable bounds. This mechanism is rendered ineffective when before/after comparisons use inconsistent price sources.

**Severity Justification:** This is a HIGH severity issue because it:
- Directly impacts a critical security mechanism protecting user funds
- Can lead to either fund loss (scenario 1) or denial of service (scenario 2)
- Requires no complex exploit - just a single admin function call
- Impact scales with vault TVL and price divergence between aggregators

## Likelihood Explanation

This vulnerability has HIGH likelihood of occurrence due to multiple factors:

**Feasibility:**
- Only requires a single function call with AdminCap
- No complex transaction ordering or timing precision needed
- Operations can run for extended periods during complex DeFi interactions
- Multiple potential oracle aggregators exist for common assets

**Realistic Scenarios:**

1. **Unintentional Trigger:** Administrators may legitimately need to switch oracle aggregators for operational reasons (e.g., provider reliability issues, better data quality, cost optimization). Without any vault status check or warning, an admin could unknowingly make this change while an operation is in progress, especially since operations can be long-running.

2. **Design Oversight:** The inconsistency with `set_enabled()` which has explicit protection suggests this was simply overlooked rather than intentionally omitted, making unintentional triggering more likely.

**Contributing Factors:**
- The function is part of normal admin operations (not an exotic edge case)
- There's no on-chain prevention mechanism
- Event emission (`SwitchboardAggregatorChanged`) requires off-chain monitoring to detect
- Operations can span multiple transactions and extended time periods

## Recommendation

Add vault status validation to `change_switchboard_aggregator()` to prevent modifications during operations, matching the pattern used by `set_enabled()`:

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    vault: &Vault<T>,  // Add vault parameter
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    vault.assert_not_during_operation();  // Add this check
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    // ... rest of implementation
}
```

Alternatively, if vault-specific checks are not feasible in the oracle module, add the check in the manage module wrapper before delegating to the oracle implementation.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Starting an operation with `start_op_with_bag()` (sets vault to `VAULT_DURING_OPERATION_STATUS`)
2. Calling `change_switchboard_aggregator()` with a different aggregator that reports different prices
3. Completing the operation with `end_op_value_update_with_bag()`
4. Observing that the loss calculation compares values from different price sources

The test at [11](#0-10)  demonstrates that `set_enabled()` correctly aborts with `ERR_VAULT_DURING_OPERATION` when called during operations. No equivalent test or protection exists for `change_switchboard_aggregator()`.

## Notes

This is a design flaw rather than a malicious exploit scenario. The vulnerability arises from the legitimate admin capability being able to perform an action at an inappropriate time, breaking the protocol's loss tolerance invariant. The issue is particularly concerning because:

1. The protection pattern already exists in the codebase (`set_enabled()` has this check)
2. The function immediately updates stored prices, not just configuration
3. Loss tolerance is a critical safety mechanism for protecting user funds
4. The inconsistency suggests an oversight rather than intentional design

### Citations

**File:** volo-vault/sources/manage.move (L118-126)
```text
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
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

**File:** volo-vault/sources/oracle.move (L198-220)
```text
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L178-193)
```text
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
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
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

**File:** volo-vault/sources/volo_vault.move (L1146-1151)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);
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

**File:** volo-vault/tests/operation/operation.test.move (L3797-3894)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION, location = vault)]
// [TEST-CASE: Should set vault disabled fail if vault is during operation.] @test-case OPERATION-022
public fun test_start_op_and_set_vault_enabled_fail_vault_during_operation() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(
            0,
            navi_account_cap,
        );
        test_scenario::return_shared(vault);
    };

    // Set mock aggregator and price
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);

        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);

        test_scenario::return_shared(oracle_config);
    };

    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();

        vault.return_free_principal(coin.into_balance());

        vault::update_free_principal_value(&mut vault, &config, &clock);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let coin = coin::mint_for_testing<USDC_TEST_COIN>(100_000_000_000, s.ctx());
        // Add 100 USDC to the vault
        vault.add_new_coin_type_asset<SUI_TEST_COIN, USDC_TEST_COIN>();
        vault.return_coin_type_asset(coin.into_balance());

        let config = s.take_shared<OracleConfig>();
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        test_scenario::return_shared(config);
        test_scenario::return_shared(vault);
    };

    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();

        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];

        let (
            asset_bag,
            tx_bag,
            tx_bag_for_check_value_update,
            principal_balance,
            coin_type_asset_balance,
        ) = operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            defi_asset_ids,
            defi_asset_types,
            1_000_000_000,
            0,
            s.ctx(),
        );

        let admin_cap = s.take_from_sender<AdminCap>();
        vault_manage::set_vault_enabled(&admin_cap, &mut vault, false);
```
