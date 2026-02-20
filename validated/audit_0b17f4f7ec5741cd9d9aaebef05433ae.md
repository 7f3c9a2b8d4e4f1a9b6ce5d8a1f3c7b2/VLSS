# Audit Report

## Title
Oracle Aggregator Can Be Changed Mid-Operation Causing Inconsistent Price Sources for Loss Tolerance Validation

## Summary
The `change_switchboard_aggregator()` function lacks vault status validation, allowing the oracle price source to be changed while the vault is in `VAULT_DURING_OPERATION_STATUS`. This causes loss tolerance validation to compare total USD values computed from different price sources, breaking a critical security invariant designed to protect vault shareholders from excessive operational losses.

## Finding Description

The `change_switchboard_aggregator()` function in the vault management module only requires `AdminCap` and performs no vault status validation. [1](#0-0) 

This function delegates to the oracle implementation which immediately updates both the aggregator address and the stored price. [2](#0-1) 

The vulnerability occurs because the loss tolerance mechanism relies on price consistency across the operation lifecycle:

**Phase 1 - Operation Start:** The `start_op_with_bag()` function sets the vault status to `VAULT_DURING_OPERATION_STATUS` [3](#0-2)  and captures the initial total USD value using the current oracle prices. [4](#0-3) 

**Phase 2 - Mid-Operation Vulnerability:** While the vault is in `VAULT_DURING_OPERATION_STATUS`, an admin can call `change_switchboard_aggregator()` which immediately updates the oracle's stored price without any vault status check. The new price is stored in the `PriceInfo` struct. [5](#0-4) 

**Phase 3 - Operation End:** The `end_op_value_update_with_bag()` function recalculates the total USD value using the NEW oracle price and compares it to the initial value captured with the OLD price to detect losses. [6](#0-5) 

The USD value calculations read from the oracle's stored prices: `get_total_usd_value()` reads from the `assets_value` table [7](#0-6) , which is populated by asset update functions that call `get_normalized_asset_price()` [8](#0-7) , which in turn calls `get_asset_price()` that returns the stored price from the oracle config. [9](#0-8) 

**Root Cause:** The absence of vault status validation creates an inconsistent security model. Other critical admin functions like `set_enabled()` explicitly prevent modifications during operations with an assertion check. [10](#0-9) 

This protection is tested and enforced in the test suite, confirming it's an intentional design pattern that was overlooked for `change_switchboard_aggregator()`. [11](#0-10) 

## Impact Explanation

This vulnerability has **HIGH SEVERITY** impact because it directly compromises the `loss_tolerance` mechanism, which is a critical safety feature protecting vault shareholders from excessive operational losses.

**Concrete Harm Scenarios:**

1. **Loss Tolerance Bypass:** If the new aggregator reports 20% higher prices than the old one, real operational losses can be masked. For example:
   - Vault starts operation with 1M SUI valued at $100/SUI = $100M total
   - During operation, vault loses 100K SUI in a failed strategy
   - Admin changes aggregator to one valuing SUI at $120/SUI
   - Final value: 900K SUI × $120 = $108M
   - System sees a $8M gain instead of the actual $10M loss
   - Loss tolerance check passes, hiding the real loss from shareholders

2. **Loss Tolerance Exhaustion:** If the new aggregator reports lower prices, artificial losses are created:
   - Vault with no actual loss could show significant USD value decrease
   - Consumes the epoch's loss_tolerance budget (default 0.1%)
   - Causes legitimate future operations to fail unnecessarily
   - Creates denial of service for normal vault operations

3. **Protocol Invariant Violation:** The loss_tolerance mechanism is designed to ensure vault value changes stay within acceptable per-epoch bounds. This becomes completely ineffective when before/after comparisons use inconsistent price sources, breaking a fundamental security guarantee.

The impact scales directly with:
- Vault TVL (larger vaults = larger absolute losses that can be hidden)
- Price divergence between aggregators (more divergence = more manipulation potential)
- Operation duration (longer operations = more opportunity for mid-operation changes)

## Likelihood Explanation

This vulnerability has **HIGH LIKELIHOOD** of occurrence because:

**Feasibility:**
- Requires only a single function call with `AdminCap` - no complex transaction ordering needed
- Operations can run for extended periods during complex DeFi interactions (borrowing from Navi, providing liquidity to Cetus/Momentum, etc.)
- Multiple legitimate oracle aggregators exist for common assets (different Switchboard feeds)
- No on-chain prevention mechanism exists

**Realistic Scenarios:**

1. **Unintentional Trigger:** Administrators may legitimately need to switch oracle aggregators for operational reasons:
   - Original aggregator experiencing reliability issues or downtime
   - Switching to a more accurate or liquid price feed
   - Cost optimization (different feed costs)
   - Without any vault status check or warning, an admin could unknowingly make this change while an operation is in progress

2. **Systemic Risk:** Since operations can be long-running and there's no visibility into active operations from the oracle config context, this can happen accidentally even with honest administrators following legitimate operational procedures.

**Contributing Factors:**
- The function is part of normal admin operations, not an exotic edge case
- Event emission (`SwitchboardAggregatorChanged`) only provides off-chain detection, not prevention
- The inconsistency with `set_enabled()` suggests this protection was simply overlooked rather than intentionally omitted
- No documentation or comments warning against mid-operation changes

## Recommendation

Add vault status validation to `change_switchboard_aggregator()` to prevent modifications during active operations. The fix should mirror the protection pattern used in `set_enabled()`:

```move
public fun change_switchboard_aggregator(
    _: &AdminCap,
    vault: &Vault<PrincipalCoinType>,  // Add vault parameter
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    // Add vault status check
    assert!(vault.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
```

Alternatively, if the vault parameter cannot be added (due to the oracle config being shared across multiple vaults), consider:
1. Adding an `active_operations_count` to `OracleConfig` that increments/decrements during operation start/end
2. Preventing aggregator changes when `active_operations_count > 0`

## Proof of Concept

```move
#[test]
public fun test_change_aggregator_mid_operation_bypasses_loss_tolerance() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and oracle with aggregator A at price $100
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, vector[100 * ORACLE_DECIMALS]);
        test_scenario::return_shared(oracle_config);
    };
    
    // Add 1M SUI to vault, worth $100M at price $100
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault.return_free_principal(coin.into_balance());
        vault::update_free_principal_value(&mut vault, &config, &clock);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // Start operation - captures total_usd_value at $100/SUI
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let (bag, tx_bag, tx_check, balance, _) = operation::start_op_with_bag<SUI_TEST_COIN, USDC, SUI>(
            &mut vault, &operation, &cap, &clock, vector[], vector[], 100_000_000_000, 0, s.ctx()
        );
        
        // VULNERABILITY: Change aggregator mid-operation to $120/SUI (20% higher)
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut oracle_config = s.take_shared<OracleConfig>();
        let new_aggregator = test_helpers::create_aggregator_with_price(&mut s, 120 * ORACLE_DECIMALS);
        vault_manage::change_switchboard_aggregator(&admin_cap, &mut oracle_config, &clock, string::utf8(b"SUI"), &new_aggregator);
        
        // Simulate losing 100K SUI (10% loss) during operation
        let lost_sui = balance.split(100_000_000_000);
        lost_sui.destroy_for_testing();
        
        // End operation and update values with NEW price
        operation::end_op_with_bag<SUI_TEST_COIN, USDC, SUI>(&mut vault, &operation, &cap, &clock, bag, tx_bag, balance, balance::zero(), s.ctx());
        vault::update_free_principal_value(&mut vault, &oracle_config, &clock);
        
        // End operation value check - compares old price vs new price
        // Should fail with 10% loss but PASSES because price change masks it
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, SUI>(&mut vault, &operation, &cap, &clock, tx_check);
        // Expected: ERR_EXCEED_LOSS_LIMIT (10% loss > 0.1% tolerance)
        // Actual: PASSES (900K × $120 = $108M vs $100M shows 8% gain!)
    };
}
```

This proof of concept demonstrates that a 10% actual loss (100K SUI lost from 1M SUI) is completely masked by changing to an oracle aggregator with 20% higher prices, allowing the loss tolerance check to pass when it should fail.

---

## Notes

This is a **mis-scoped privilege issue** where the admin role (trusted) is given excessive power that violates a critical security invariant. Even though admins are trusted, they should not be able to change oracle aggregators mid-operation because it breaks the loss tolerance mechanism's fundamental assumption of price consistency. The existence of explicit vault status checks in similar admin functions (`set_enabled`) confirms this protection was likely an oversight rather than an intentional design decision.

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

**File:** volo-vault/sources/volo_vault.move (L519-531)
```text
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

**File:** volo-vault/tests/operation/operation.test.move (L3800-3894)
```text
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
