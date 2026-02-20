# Audit Report

## Title
Loss Tolerance Bypass via Stale Asset Value Baseline

## Summary
The vault's loss tolerance mechanism uses cached asset values without freshness verification when setting the epoch baseline, allowing operators to bypass loss tolerance limits by up to the staleness differential. This violates the protocol's risk management invariant that losses per epoch should not exceed the configured `loss_tolerance` percentage.

## Finding Description

The Volo Vault implements an epoch-based loss tolerance system to limit operational losses. However, the baseline used for this protection is set using stale cached values instead of verified fresh values.

**Root Cause:**

When a new epoch begins, `try_reset_tolerance` sets the loss tolerance baseline using `get_total_usd_value_without_update()` [1](#0-0) , which returns cached asset values without enforcing the `MAX_UPDATE_INTERVAL` freshness requirement [2](#0-1) .

In contrast, the correct function `get_total_usd_value()` enforces freshness by asserting that all asset values were updated within `MAX_UPDATE_INTERVAL` (set to 0, meaning same transaction) [3](#0-2) .

**Exploit Path:**

1. Operator initiates any vault operation via `start_op_with_bag` [4](#0-3) 
2. This calls `pre_vault_check` which invokes `try_reset_tolerance` if a new epoch has begun [5](#0-4) 
3. The baseline is set using stale cached values, not fresh verified values
4. Later, when the operation completes, loss is checked against this stale baseline [6](#0-5) 

**Why Protections Fail:**

While the protocol correctly uses fresh values for calculating actual losses (before/after values within operations) [7](#0-6) , it incorrectly uses stale values for the baseline that determines the loss limit. This creates a mismatch where `loss_limit = cur_epoch_loss_base_usd_value * tolerance_rate` uses a potentially inflated baseline.

## Impact Explanation

**Primary Impact - Loss Tolerance Bypass:**

When cached asset values are higher than actual current values (due to market declines or delayed updates between operations), the `cur_epoch_loss_base_usd_value` will be inflated. This directly increases the calculated `loss_limit`, allowing operators to cause losses beyond the configured percentage.

**Concrete Example:**
- Configured `loss_tolerance`: 10 basis points (0.1%)
- Vault value at end of Epoch N: 1,000,000 USD (fresh)
- Epoch N+1 begins, 12 hours pass with market decline
- Actual vault value: 900,000 USD
- Cached/stale value: 1,000,000 USD
- **Intended loss limit:** 900,000 × 0.001 = 900 USD
- **Actual loss limit used:** 1,000,000 × 0.001 = 1,000 USD
- **Bypass amount:** 100 USD (11% more loss allowed)

This violates the protocol's risk management invariant. The differential scales with vault size and degree of staleness. In volatile markets with large vaults, this could permit significant unauthorized losses.

**Secondary Impact:**
If cached values are lower than actual (less common), valid operations may be incorrectly rejected with `ERR_EXCEED_LOSS_LIMIT`, causing operational denial of service.

## Likelihood Explanation

**HIGH Likelihood:**

1. **Automatic Triggering:** The vulnerability triggers automatically when Sui epochs change and any operator initiates an operation. No special manipulation required.

2. **Natural Staleness:** Asset values naturally become stale between operations. The protocol requires updates only during operations [8](#0-7) , not between them.

3. **Operator Access:** Regular operators (not admins) have sufficient privileges to trigger this through normal operations.

4. **Routine Preconditions:** All conditions are routine:
   - Vault has assets (normal state)
   - Epoch changes (automatic, happens ~24 hours on Sui)
   - Operator initiates operation (standard activity)

5. **Protocol Evidence:** The protocol explicitly sets `MAX_UPDATE_INTERVAL = 0` [9](#0-8)  and documents `get_total_usd_value_without_update()` as returning "not correct & latest value" [10](#0-9) , indicating the developers intended freshness enforcement but failed to apply it consistently.

## Recommendation

Replace the stale value lookup with fresh value verification in `try_reset_tolerance`:

```move
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    clock: &Clock,  // Add Clock parameter
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        // FIXED: Use fresh values instead of cached
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value(clock);
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
}
```

Update all call sites to pass the `Clock` parameter:
- `pre_vault_check` in operation.move
- `reset_loss_tolerance` in manage.move

## Proof of Concept

```move
#[test]
fun test_loss_tolerance_bypass_via_stale_baseline() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Initialize vault with 1M USD worth of assets
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    setup_oracle_and_deposit(&mut scenario, &mut clock, 1_000_000);
    
    // Update all asset values - vault now worth 1M USD (fresh)
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let oracle = scenario.take_shared<OracleConfig>();
        vault.update_free_principal_value(&oracle, &clock);
        // Cached value = 1,000,000 USD
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle);
    };
    
    // Move to next epoch - market declines 10%
    scenario.next_epoch(ADMIN);
    scenario.next_tx(OPERATOR);
    {
        let mut oracle = scenario.take_shared<OracleConfig>();
        // Simulate market decline: update oracle to 90% of previous price
        set_oracle_price(&mut oracle, &mut clock, 900_000);
        test_scenario::return_shared(oracle);
    };
    
    // Operator starts operation - try_reset_tolerance uses STALE cached value
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let oracle = scenario.take_shared<OracleConfig>();
        
        // Baseline set to 1,000,000 (stale) instead of 900,000 (actual)
        vault.try_reset_tolerance(false, scenario.ctx());
        assert!(vault.cur_epoch_loss_base_usd_value() == 1_000_000, 0);
        
        // Loss limit = 1,000,000 * 0.001 = 1,000 USD
        // But should be: 900,000 * 0.001 = 900 USD
        // Operator can now cause 1,000 USD loss instead of 900 USD
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

This test demonstrates that `try_reset_tolerance` uses the cached value of 1,000,000 USD even when the actual vault value has declined to 900,000 USD, allowing 11% more loss than intended by the loss tolerance percentage.

### Citations

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L608-624)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
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

**File:** volo-vault/sources/volo_vault.move (L1281-1281)
```text
// * @dev Just get the total usd value without checking the update time (not correct & latest value)
```

**File:** volo-vault/sources/volo_vault.move (L1282-1295)
```text
public fun get_total_usd_value_without_update<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
): u256 {
    self.check_version();

    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    total_usd_value
}
```

**File:** volo-vault/sources/operation.move (L94-104)
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
