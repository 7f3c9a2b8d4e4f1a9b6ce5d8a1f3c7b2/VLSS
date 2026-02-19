### Title
Loss Tolerance Denial of Service When Vault Base Value is Zero

### Summary
The Volo vault's loss tolerance mechanism calculates a loss limit based on the epoch's base USD value. When a vault is empty or newly created (base value = 0), any operation resulting in loss will fail the tolerance check, permanently blocking vault operations. This mirrors the external vulnerability where a zero-collateral check blocks valid position closures, but in Volo it blocks valid operations on empty vaults.

### Finding Description

The external vulnerability shows a pattern where a validation function returns a "bad" state when a value is zero, without considering whether that zero represents a valid terminal/initial state. The analog vulnerability exists in Volo's loss tolerance mechanism.

**Root Cause in Volo:**

In `volo_vault.move`, the `try_reset_tolerance` function sets the epoch's base USD value to the current vault total: [1](#0-0) 

When `update_tolerance` is called to check losses, it calculates the loss limit as:
`loss_limit = cur_epoch_loss_base_usd_value * loss_tolerance / RATE_SCALING` [2](#0-1) 

**The Vulnerability:**
When `cur_epoch_loss_base_usd_value = 0` (empty vault), `loss_limit = 0 * loss_tolerance / RATE_SCALING = 0`. The assertion `assert!(loss_limit >= cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT)` will fail for ANY loss > 0, blocking the operation.

**Exploit Path:**

1. Vault is newly created or fully withdrawn (total USD value = 0)
2. Operator initiates operation via `start_op_with_bag` in operation.move
3. `pre_vault_check` calls `try_reset_tolerance(false, ctx)`: [3](#0-2) 

4. This sets `cur_epoch_loss_base_usd_value = 0`
5. Operation executes with any loss (rounding, fees, market movement)
6. `end_op_value_update_with_bag` calculates loss and calls `vault.update_tolerance(loss)`: [4](#0-3) 

7. Assertion fails because `0 >= loss` is false when loss > 0
8. Transaction aborts with `ERR_EXCEED_LOSS_LIMIT` (error code 5_008)

**Why Protections Fail:**
The test suite only tests tolerance with funded vaults, never testing the empty vault edge case: [5](#0-4) 

### Impact Explanation

**High Severity - Protocol Denial of Service:**
- Newly created vaults cannot perform ANY operations that result in loss, preventing vault initialization
- Fully withdrawn vaults cannot restart operations
- Any vault that experiences complete withdrawal becomes permanently unusable for loss-generating operations
- This affects core vault functionality including DeFi strategy execution, rebalancing, and yield generation
- Loss is unavoidable in real DeFi operations due to fees, slippage, and market conditions

The constants show default tolerance is only 0.1% (10 basis points): [6](#0-5) 

### Likelihood Explanation

**High Likelihood:**
- Occurs naturally when vaults are newly deployed (common during protocol launch)
- Occurs after full withdrawals (legitimate user behavior)
- No special attacker privileges required
- The precondition (vault base value = 0) is a normal operational state
- Any loss-generating operation triggers it (not an edge case)
- The operation flow is the standard three-phase pattern used by all vault operations: [7](#0-6) 

### Recommendation

**Code-level Mitigation:**

Modify the `update_tolerance` function in `volo_vault.move` to handle the zero base value case:

```move
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();
    
    self.cur_epoch_loss = self.cur_epoch_loss + loss;
    
    // Special case: if base value is zero, allow operations without loss limit
    if (self.cur_epoch_loss_base_usd_value == 0) {
        return
    };
    
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

Alternatively, set a minimum base value threshold (e.g., 1 USD) below which tolerance checks are skipped.

### Proof of Concept

**Reproducible Exploit Steps:**

1. **Initial State:** Deploy a new vault with 0 total USD value
2. **Action:** Operator calls `start_op_with_bag` to begin operation
   - Precondition: `vault.get_total_usd_value() = 0`
   - `try_reset_tolerance` sets `cur_epoch_loss_base_usd_value = 0`
3. **Operation:** Borrow assets from Navi/Suilend, perform swap on Cetus
   - Any fee/slippage causes `total_usd_value_after < total_usd_value_before`
   - Example: 1 unit loss due to swap fee
4. **Completion:** Operator calls `end_op_value_update_with_bag`
   - `loss = total_usd_value_before - total_usd_value_after = 1`
   - `vault.update_tolerance(1)` is called
5. **Failure:** Inside `update_tolerance`:
   - `loss_limit = 0 * 10 / 10_000 = 0`
   - `assert!(0 >= 1)` → **FAILS**
6. **Result:** Transaction aborts with `ERR_EXCEED_LOSS_LIMIT` (5_008)
7. **Impact:** Vault permanently cannot perform operations until admin manually resets tolerance with non-zero base value

**Realistic Inputs:**
- Vault: Fresh deployment or post-withdrawal
- Operation: Any standard DeFi strategy (lending, swapping, LP provision)
- Loss: Even 0.0001 USD loss triggers the bug
- No special permissions needed beyond normal operator role

### Citations

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/tests/tolerance.test.move (L94-104)
```text
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let oracle_config = s.take_shared<OracleConfig>();

        vault.return_free_principal(coin.into_balance());
        vault.update_free_principal_value(&oracle_config, &clock);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
    };
```
