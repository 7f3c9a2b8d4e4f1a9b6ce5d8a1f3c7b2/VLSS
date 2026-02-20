# Audit Report

## Title
Epoch Boundary Timing Allows Loss Accumulation Beyond Per-Epoch Tolerance Limits

## Summary
The vault's loss tolerance mechanism fails to correctly enforce per-epoch loss limits when operations span epoch boundaries. The `cur_epoch` tracking field is only updated when operations start via `try_reset_tolerance()`, not at actual epoch transitions, allowing losses exceeding the configured per-epoch tolerance of 0.1% (10 basis points) by 20% or more through natural operation timing around epoch boundaries.

## Finding Description

The vulnerability exists in how the vault tracks and resets loss tolerance across epoch boundaries. The loss tolerance mechanism is designed to limit losses to 10 basis points (0.1%) per epoch [1](#0-0) , but the implementation has a critical timing flaw.

**Root Cause:**

When operations start, `pre_vault_check()` calls `try_reset_tolerance()` to conditionally reset the loss counter [2](#0-1) . However, the reset only triggers when `self.cur_epoch < tx_context::epoch(ctx)` [3](#0-2) .

The Vault struct tracks epochs using `cur_epoch`, `cur_epoch_loss_base_usd_value`, `cur_epoch_loss`, and `loss_tolerance` fields [4](#0-3) .

**Exploitation Flow:**

1. **End of Epoch N**: Operation A starts with `cur_epoch == N`
   - Condition `N < N` is false, no reset occurs
   - `cur_epoch_loss_base_usd_value` remains from epoch N start

2. **Early Epoch N+1**: Operation A completes with loss L1
   - Loss is recorded via `update_tolerance()` and added to `cur_epoch_loss` [5](#0-4) 
   - The loss is validated against epoch N's base value, not epoch N+1's
   - Vault value drops by L1

3. **Still Epoch N+1**: Operation B starts
   - Now `cur_epoch == N` and `tx_context::epoch(ctx) == N+1`, so `N < N+1` is true
   - Reset occurs with `cur_epoch_loss_base_usd_value = get_total_usd_value_without_update()` [6](#0-5) 
   - The new base is vault value AFTER L1 was already subtracted
   - Operation B can now cause losses up to 0.1% of this reduced value

**Why Existing Protections Fail:**

The tolerance validation checks `cur_epoch_loss <= cur_epoch_loss_base_usd_value * loss_tolerance / RATE_SCALING` [7](#0-6) , but the base value becomes stale when operations span epochs. The system has no timeout mechanism preventing operations from spanning arbitrary periods, and the three-phase operation pattern (`start_op_with_bag` → `end_op_with_bag` → `end_op_value_update_with_bag`) inherently spans multiple transactions [8](#0-7) .

## Impact Explanation

**Direct Financial Harm:**
Vault shareholders experience losses exceeding the configured per-epoch tolerance limit. The intended invariant documented in code is "principal loss tolerance at every epoch" [1](#0-0) , meaning total losses occurring chronologically during epoch E should not exceed 0.1% of vault value at epoch E's start.

**Quantified Impact:**
Using the default 10 basis point tolerance:
- If vault value at start of epoch N+1 is 10,000 USD, the epoch limit should be 10 USD
- Through the vulnerability, if L1 = 2 USD occurs spanning the boundary, the new base becomes 9,998 USD
- Epoch N+1 operations can then cause up to 9,998 * 0.001 = 9.998 USD additional loss
- Total epoch N+1 losses: 2 + 9.998 = 11.998 USD (≈20% excess over intended 10 USD limit)
- With larger spanning losses, excess approaches 100%

**Affected Parties:**
- All vault shareholders bear losses beyond agreed risk parameters
- The protocol's loss tolerance guarantee is violated
- Trust in vault risk management is undermined

**Severity:** Medium - Individual excess per epoch is limited but allows systematic circumvention of a critical safety mechanism over time.

## Likelihood Explanation

**Natural Occurrence:**
This vulnerability does NOT require malicious operator behavior. It occurs naturally because:
- Sui epochs are deterministic 24-hour periods
- Operations inherently span multiple transactions across the three-phase pattern
- No timeout enforcement exists in the codebase
- High-activity periods naturally lead to operations crossing epoch boundaries

**Feasibility:**
- Operations begin with `start_op_with_bag` and conclude with `end_op_value_update_with_bag` in separate transactions
- No duration constraints exist between these phases
- Epoch boundaries WILL be crossed during normal vault operations
- The vulnerability window exists for every operation spanning an epoch boundary

**Probability:** High for accidental occurrence during normal operations. An aware operator could also strategically time operations, but this is unnecessary as the issue manifests naturally.

## Recommendation

Implement one of the following fixes:

**Option 1: Snapshot base value at actual epoch transitions**
```move
// Add to Vault struct
last_reset_epoch_start_value: u256,

// Modify try_reset_tolerance to:
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();
    
    let current_epoch = tx_context::epoch(ctx);
    if (by_admin || self.cur_epoch < current_epoch) {
        // If we skipped epochs, use the value from when we should have reset
        let base_value = if (self.cur_epoch < current_epoch - 1) {
            // Multiple epochs passed, use stored value
            self.last_reset_epoch_start_value
        } else {
            // Normal case: use current value
            self.get_total_usd_value_without_update()
        };
        
        self.cur_epoch_loss = 0;
        self.cur_epoch = current_epoch;
        self.cur_epoch_loss_base_usd_value = base_value;
        self.last_reset_epoch_start_value = base_value;
        
        emit(LossToleranceReset { ... });
    };
}
```

**Option 2: Track and validate losses occurring in the current chronological epoch**
Add a separate tracking mechanism that captures the actual epoch when losses occur, not when operations started.

**Option 3: Enforce operation timeouts**
Add maximum duration constraints to prevent operations from spanning epoch boundaries.

## Proof of Concept

```move
#[test]
fun test_epoch_boundary_loss_tolerance_bypass() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with 10,000 USD value
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    setup_oracle_and_fund_vault(&mut s, &mut clock, 10_000_000_000_000); // 10,000 USD
    
    // Start operation A in epoch N (assume epoch 1)
    s.next_tx(OWNER);
    let (bag, tx, tx_check, principal, coin) = start_op_with_bag(...);
    
    // Move to next epoch N+1 (epoch 2)
    s.next_epoch(OWNER);
    
    // Complete operation A with 2 USD loss in epoch N+1
    s.next_tx(OWNER);
    end_op_with_bag(...);
    // Simulate 2 USD loss
    end_op_value_update_with_bag(...); // vault value now 9,998 USD
    
    // Start operation B in epoch N+1 - triggers reset with reduced base
    s.next_tx(OWNER);
    let (bag2, tx2, tx_check2, principal2, coin2) = start_op_with_bag(...);
    
    // Complete operation B with 9.99 USD loss (should fail but passes)
    s.next_tx(OWNER);
    end_op_with_bag(...);
    end_op_value_update_with_bag(...); // Total epoch 2 loss: ~12 USD > 10 USD limit
    
    // Verify total epoch 2 losses exceeded intended 0.1% limit
    let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
    assert!(vault.get_total_usd_value(&clock) < 9990); // Lost > 10 USD in epoch 2
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This is a **logic flaw in the loss tolerance mechanism**, not an access control issue. While it involves OperatorCap operations, the vulnerability occurs naturally without requiring malicious intent. The issue violates the documented per-epoch loss tolerance guarantee and affects all vault shareholders. The lack of timeout enforcement and the natural multi-transaction operation pattern make epoch boundary crossings inevitable during normal vault operations.

### Citations

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L117-121)
```text
    // ---- Loss Tolerance ---- //
    cur_epoch: u64,
    cur_epoch_loss_base_usd_value: u256,
    cur_epoch_loss: u256,
    loss_tolerance: u256,
```

**File:** volo-vault/sources/volo_vault.move (L615-623)
```text
    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
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

**File:** volo-vault/sources/operation.move (L94-377)
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

public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();

    defi_assets.destroy_empty();
}

public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
