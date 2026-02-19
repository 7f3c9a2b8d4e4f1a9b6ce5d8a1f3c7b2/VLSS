### Title
Momentum Adaptor Upgrade Lacks State Migration Mechanism Causing Incorrect Mixed-Formula Vault Valuations

### Summary
The momentum adaptor module has no version tracking or migration mechanism to recalculate existing position values when the adaptor logic is upgraded. After an upgrade with modified valuation formulas, only positions explicitly updated during subsequent operations receive new calculations, while other positions retain values computed with the old formula. This creates a critical state inconsistency where the vault's total USD value becomes incorrect due to mixing old and new formula results, leading to wrong share ratios, unfair deposits/withdrawals, and loss tolerance bypasses.

### Finding Description

**Storage Architecture:**
Position USD values are stored separately from the Position objects themselves in the vault's `assets_value` table, which maps asset type strings to u256 USD values. [1](#0-0) 

**Value Update Mechanism:**
The `update_momentum_position_value` function calculates the USD value by reading the Position object, calling `get_position_value` to compute token amounts via `liquidity_math::get_amounts_for_liquidity`, fetching oracle prices, and then calling `finish_update_asset_value` to overwrite the stored value. [2](#0-1) [3](#0-2) 

The `finish_update_asset_value` function directly overwrites the old USD value in the `assets_value` table without any versioning or migration logic. [4](#0-3) 

**Upgrade Mechanism:**
The vault upgrade function only updates a version field in the Vault struct itself, with no mechanism to trigger recalculation of all stored position values. [5](#0-4) [6](#0-5) 

The momentum adaptor module itself has no version field or migration logic. [7](#0-6) 

**Root Cause:**
Position values are only recalculated when explicitly borrowed during operations. The three-step operation flow shows that assets are borrowed, used, returned, and then their values must be updated. [8](#0-7) [9](#0-8) 

However, there is no mechanism forcing ALL positions to be updated after an adaptor upgrade. Positions not borrowed in subsequent operations retain their old formula values indefinitely.

**Critical Flaw in Total Value Calculation:**
The `get_total_usd_value` function simply sums all values from the `assets_value` table without checking which formula version was used to compute each value. [10](#0-9) 

### Impact Explanation

**Direct Financial Impact:**

1. **Incorrect Share Ratios**: The share ratio calculation divides total USD value by total shares. When the total USD value is incorrect due to mixed formulas, all share-based operations become unfair. [11](#0-10) 

2. **Unfair Deposit Executions**: Deposits calculate user shares based on the incorrect share ratio, either over-allocating shares (diluting existing holders) or under-allocating shares (harming new depositors). [12](#0-11) 

3. **Unfair Withdrawal Executions**: Withdrawals calculate the principal amount to return based on shares and the incorrect share ratio, causing fund redistribution errors. [13](#0-12) 

4. **Loss Tolerance Bypass**: The loss tolerance mechanism uses the total USD value to set the base value at the start of each epoch. An incorrect base value allows losses to bypass tolerance checks. [14](#0-13) [15](#0-14) 

**Concrete Scenario:**
- Vault has MomentumPosition A valued at $100,000 and Position B valued at $50,000 under old formula
- Adaptor upgraded with new formula that should value Position A at $120,000 and Position B at $60,000
- Only Position A borrowed in next operation → updated to $120,000
- Position B never borrowed → remains $50,000
- Total vault value = $120,000 + $50,000 = $170,000 (actual should be $180,000)
- Share ratio incorrectly calculated as lower, causing systematic value leakage in subsequent deposits/withdrawals

### Likelihood Explanation

**High Likelihood:**

1. **Realistic Upgrade Scenarios**: Formula changes in adaptors are expected during:
   - Bug fixes in liquidity calculations
   - Decimal precision improvements
   - Oracle price handling modifications
   - AMM math library upgrades
   - Slippage validation changes

2. **No Operational Controls**: The protocol has no mechanism to:
   - Force updating all positions before upgrade takes effect
   - Detect mixed-formula states
   - Prevent operations when values are inconsistent
   - Alert operators to stale position values

3. **Practical Exploitation**: An attacker doesn't need to trigger the upgrade—they simply need to:
   - Monitor for adaptor upgrades on-chain
   - Identify which positions were/weren't updated post-upgrade
   - Calculate the valuation discrepancy
   - Execute deposits/withdrawals to extract value from the mispriced vault

4. **Economic Feasibility**: The attack becomes profitable when the valuation discrepancy exceeds gas costs, which is likely for any material formula change affecting large positions.

### Recommendation

**Immediate Mitigations:**

1. **Add Version Tracking to Adaptor:**
```
module volo_vault::momentum_adaptor {
    const VERSION: u64 = 1;
    
    public fun get_adaptor_version(): u64 {
        VERSION
    }
}
```

2. **Add Version Field to Position Value Storage:**
Extend the Vault struct to track which adaptor version was used to calculate each position value:
```
position_value_versions: Table<String, u64>
```

3. **Add Version Check in finish_update_asset_value:**
```
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    adaptor_version: u64,
    now: u64,
) {
    // Store version alongside value
    self.position_value_versions[asset_type] = adaptor_version;
    // ... existing logic
}
```

4. **Add Migration Function:**
Create a mandatory migration function that operators must call after adaptor upgrades:
```
public fun migrate_all_momentum_positions<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    position_asset_types: vector<String>,
    pools: vector<&mut MomentumPool<CoinA, CoinB>>,
) {
    // Force recalculation of all momentum positions
    // Only allow normal operations after all positions migrated
}
```

5. **Add Pre-Operation Version Validation:**
Before any operation that uses `get_total_usd_value`, validate all position values are calculated with current adaptor versions:
```
public fun validate_position_value_versions<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.asset_types.do_ref!(|asset_type| {
        if (is_momentum_position(*asset_type)) {
            let stored_version = self.position_value_versions[*asset_type];
            assert!(stored_version == momentum_adaptor::get_adaptor_version(), ERR_STALE_POSITION_VALUE);
        }
    });
}
```

**Long-term Solution:**

Implement a comprehensive version management system across all adaptors with atomic migration requirements: no operations permitted until all affected positions are updated post-upgrade.

### Proof of Concept

**Initial State:**
1. Vault created with total_shares = 1,000,000
2. Two MomentumPositions added:
   - Position A: stored value = 100,000 USD (old formula)
   - Position B: stored value = 50,000 USD (old formula)
3. Total vault value = 150,000 USD
4. Share ratio = 150,000 / 1,000,000 = 0.15 USD per share

**Upgrade Execution:**
5. Momentum adaptor upgraded with new `get_position_value` formula
6. New formula would calculate: Position A = 120,000 USD, Position B = 60,000 USD
7. Operation executed borrowing only Position A
8. Position A updated via `update_momentum_position_value` → stored value = 120,000 USD
9. Position B NOT borrowed → stored value remains 50,000 USD (old formula)

**Post-Upgrade State:**
10. Total vault value = 120,000 + 50,000 = 170,000 USD (INCORRECT, should be 180,000)
11. Share ratio = 170,000 / 1,000,000 = 0.17 USD per share (INCORRECT, should be 0.18)

**Exploitation:**
12. User deposits 17,000 USD expecting shares = 17,000 / 0.18 = 94,444 shares
13. Actually receives shares = 17,000 / 0.17 = 100,000 shares (5.88% over-allocation)
14. Total shares diluted to 1,100,000, user owns 9.09% instead of 8.57%
15. Existing holders lose proportional value to the over-allocated shares

**Success Condition:**
The vault's `assets_value` table contains Position A with value 120,000 (new formula) and Position B with value 50,000 (old formula), causing a 10,000 USD undervaluation that persists until Position B is explicitly updated.

### Citations

**File:** volo-vault/sources/volo_vault.move (L96-130)
```text
public struct Vault<phantom T> has key, store {
    id: UID,
    version: u64,
    // ---- Pool Info ---- //
    status: u8,
    total_shares: u256,
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
    // ---- Fee ---- //
    deposit_withdraw_fee_collected: Balance<T>,
    // ---- Principal Info ---- //
    free_principal: Balance<T>,
    claimable_principal: Balance<T>,
    // ---- Config ---- //
    deposit_fee_rate: u64,
    withdraw_fee_rate: u64,
    // ---- Assets ---- //
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
    // ---- Loss Tolerance ---- //
    cur_epoch: u64,
    cur_epoch_loss_base_usd_value: u256,
    cur_epoch_loss: u256,
    loss_tolerance: u256,
    // ---- Request Buffer ---- //
    request_buffer: RequestBuffer<T>,
    // ---- Reward Info ---- //
    reward_manager: address,
    // ---- Receipt Info ---- //
    receipts: Table<address, VaultReceiptInfo>,
    // ---- Operation Value Update Record ---- //
    op_value_update_record: OperationValueUpdateRecord,
}
```

**File:** volo-vault/sources/volo_vault.move (L464-469)
```text
public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
```

**File:** volo-vault/sources/volo_vault.move (L608-641)
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

**File:** volo-vault/sources/volo_vault.move (L806-872)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

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

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
```

**File:** volo-vault/sources/volo_vault.move (L994-1052)
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
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

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

    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

    // Decrease the share in vault and receipt
    self.total_shares = self.total_shares - shares_to_withdraw;

    // Split balances from the vault
    assert!(amount_to_withdraw <= self.free_principal.value(), ERR_NO_FREE_PRINCIPAL);
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);

    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);

    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
    });

```

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L1-14)
```text
module volo_vault::momentum_adaptor;

use mmt_v3::liquidity_math;
use mmt_v3::pool::Pool as MomentumPool;
use mmt_v3::position::Position as MomentumPosition;
use mmt_v3::tick_math;
use std::ascii::String;
use std::type_name::{get, into_string};
use std::u256::pow;
use sui::clock::Clock;
use volo_vault::vault::Vault;
use volo_vault::vault_oracle::{Self, OracleConfig};
use volo_vault::vault_utils;

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L34-67)
```text
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);

    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );

    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
}
```

**File:** volo-vault/sources/manage.move (L22-24)
```text
public fun upgrade_vault<PrincipalCoinType>(_: &AdminCap, vault: &mut Vault<PrincipalCoinType>) {
    vault.upgrade_vault();
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

**File:** volo-vault/sources/operation.move (L259-265)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };
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
