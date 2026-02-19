# Audit Report

## Title
Unrestricted Public Access to Asset Value Update Functions During Vault Operations Enables Loss Tolerance Bypass

## Summary
All adaptor value update functions (`update_cetus_position_value`, `update_navi_position_value`, `update_suilend_position_value`, `update_momentum_position_value`, `update_receipt_value`) are declared as `public fun`, allowing any external caller to update asset valuations via Programmable Transaction Blocks (PTBs) during vault operations. These functions only enforce `assert_enabled()` rather than `assert_normal()`, permitting calls while the vault is in `VAULT_DURING_OPERATION_STATUS`. This allows attackers to manipulate asset values used in loss tolerance calculations, bypassing critical security controls designed to protect vault participants.

## Finding Description

**Root Cause - Public Function Visibility:**
All adaptor update functions are declared as `public fun` without capability requirements: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

In Sui Move, `public fun` functions are directly callable via PTBs by any external address without requiring special permissions or capability objects.

**Insufficient Access Control:**
These functions call `finish_update_asset_value()` which only enforces `assert_enabled()`: [6](#0-5) 

The critical flaw is in the `assert_enabled()` check: [7](#0-6) 

This check only prevents calls when status is `VAULT_DISABLED_STATUS` (value 2), but **allows both** `VAULT_NORMAL_STATUS` (0) **and** `VAULT_DURING_OPERATION_STATUS` (1): [8](#0-7) 

Compare this to `assert_normal()` which properly restricts to only normal status: [9](#0-8) 

**Operation Flow and Vulnerability Window:**
During vault operations, the status is set to `VAULT_DURING_OPERATION_STATUS`: [10](#0-9) 

The operator captures `total_usd_value_before` for later loss verification: [11](#0-10) 

**Direct State Modification:**
The vulnerability lies in `finish_update_asset_value` directly modifying the vault's `assets_value` table regardless of operation status: [12](#0-11) 

**Impact on Loss Calculation:**
When the operation completes, `end_op_value_update_with_bag` calculates `total_usd_value_after` using these manipulated values: [13](#0-12) 

The `get_total_usd_value` function sums all asset values from the `assets_value` table: [14](#0-13) 

The loss tolerance check then validates using these potentially manipulated values: [15](#0-14) 

## Impact Explanation

**Critical Loss Tolerance Bypass:**
By inflating asset values between operation start and loss verification, an attacker can make actual losses appear smaller than they are. For example:
- Vault starts operation with `total_usd_value_before = 1,000,000 USD`
- Operator executes strategy that results in actual loss to 900,000 USD
- Attacker calls update functions to inflate values to 950,000 USD
- Loss calculation shows only 50,000 USD loss instead of actual 100,000 USD
- The per-epoch loss tolerance check passes when it should have aborted

This completely undermines the loss tolerance mechanism designed to protect vault participants from excessive operator losses.

**Protocol Integrity Impact:**
- Loss tolerance enforcement becomes bypassable, removing a critical safety mechanism
- Vault's recorded asset values become unreliable during operations
- Operators' actions cannot be properly audited since external actors can modify state
- The vault's accounting system loses integrity during the most critical operation windows

## Likelihood Explanation

**Trivial Execution via PTB:**
The attack requires only:
1. Monitoring on-chain state for vault status changes (publicly observable)
2. Access to shared objects (Vault, OracleConfig, Clock, Pool objects - all shared)
3. Submitting a single PTB transaction calling any public update function
4. No special capabilities, operator privileges, or complex setup required

**Attack Window:**
The vulnerability window exists during any vault operation, which occurs regularly as operators rebalance positions, execute strategies, or manage DeFi integrations. The window persists from `start_op_with_bag` until `end_op_value_update_with_bag` completes.

**Economic Rationality:**
- Attack cost: Single transaction gas fee (~0.01-0.1 SUI)
- Potential benefit: Can hide losses worth significant vault value
- Can be executed repeatedly on every operation
- No risk to attacker (worst case: transaction reverts)

## Recommendation

Change all adaptor update functions from `public fun` to `public(package) fun` to restrict access to package-internal calls only:

```move
// In cetus_adaptor.move
public(package) fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    // ... existing implementation
}
```

Apply this change to:
- `update_navi_position_value` in navi_adaptor.move
- `update_suilend_position_value` in suilend_adaptor.move  
- `update_momentum_position_value` in momentum.adaptor.move
- `update_receipt_value` in receipt_adaptor.move
- `update_coin_type_asset_value` in volo_vault.move

Additionally, consider adding operator capability checks if these functions need to be called from operation module entry points.

## Proof of Concept

```move
#[test]
fun test_external_manipulation_during_operation() {
    // Setup: Create vault, add cetus position asset
    let mut scenario = test_scenario::begin(ADMIN);
    let (vault, clock, config, pool) = setup_vault_with_cetus_position(&mut scenario);
    
    // Step 1: Operator starts operation
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    let total_value_before = vault.get_total_usd_value(&clock);
    
    // Step 2: External attacker calls public update function
    // This should FAIL but currently SUCCEEDS
    let attacker_ctx = test_scenario::ctx(&mut scenario);
    volo_vault::cetus_adaptor::update_cetus_position_value(
        &mut vault,
        &config, 
        &clock,
        b"cetus_position_1".to_string(),
        &mut pool
    ); // No capability required - this executes successfully!
    
    let total_value_after = vault.get_total_usd_value(&clock);
    
    // Attacker successfully modified asset values during operation
    assert!(total_value_after != total_value_before, 0);
}
```

The test demonstrates that external callers can invoke update functions during `VAULT_DURING_OPERATION_STATUS` without any operator capabilities, directly modifying vault state that should only be controlled by trusted operators during sensitive operation windows.

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-36)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
    receipt_vault.assert_normal();

    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);

    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1181)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
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

**File:** volo-vault/sources/operation.move (L178-179)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();
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
