# Audit Report

## Title
Race Condition Between Oracle Aggregator Changes and Multi-Transaction Vault Operations

## Summary
The `change_switchboard_aggregator()` function can execute concurrently with ongoing multi-transaction vault operations, creating a race condition where assets are valued using prices from different aggregators within the same operation. This results in incorrect loss calculations that can bypass the protocol's loss tolerance limits or falsely reject valid operations.

## Finding Description

The vulnerability stems from the lack of coordination between the oracle module and vault operation state. The protocol implements a three-step operation flow where vault operations span multiple transactions:

**Step 1 - Operation Start**: The operator calls `start_op_with_bag()` which captures an initial `total_usd_value` snapshot by summing all asset values from the vault's `assets_value` table [1](#0-0) . This snapshot represents the vault's total USD value at operation start.

**Step 2 - Asset Updates Between Transactions**: After assets are returned via `end_op_with_bag()`, operators must update all borrowed asset values in separate transactions. Functions like `update_free_principal_value()` read prices from the oracle by calling `get_normalized_asset_price()` [2](#0-1) . Similarly, `update_coin_type_asset_value()` reads prices from the oracle [3](#0-2) .

**Step 3 - Operation End**: The operator calls `end_op_value_update_with_bag()` which computes a final `total_usd_value_after` by summing all asset values again [4](#0-3) . The loss is calculated as the difference between these snapshots [5](#0-4) .

**The Race Condition**: Between Step 2 asset updates, the admin can call `change_switchboard_aggregator()` which immediately updates the aggregator address and price without any check for ongoing vault operations [6](#0-5) . This causes some assets to be valued with the old aggregator and others with the new aggregator, producing an inconsistent total USD value.

**Why Protections Fail**:

1. The vault tracks its operation status using `VAULT_DURING_OPERATION_STATUS` [7](#0-6)  and sets this status during operations [8](#0-7) .

2. However, `change_switchboard_aggregator()` performs NO vault status checks and only validates version and asset existence [9](#0-8) .

3. The OracleConfig is a shared object that can be modified concurrently [10](#0-9)  and is exposed to admin via the manage module [11](#0-10) .

4. Asset update functions only check `assert_enabled()` which validates the vault is not disabled [12](#0-11) , but do NOT check if the vault is during an operation [13](#0-12) [14](#0-13) .

5. The oracle module is architecturally decoupled from vault modules and has no mechanism to query vault statuses.

## Impact Explanation

**Loss Tolerance Bypass**: The protocol enforces loss limits through `update_tolerance()` which checks that accumulated losses do not exceed `loss_tolerance` [15](#0-14) . The assertion at line 635 enforces this critical safety mechanism [16](#0-15) .

When aggregator prices differ and change mid-operation:
- If the new aggregator reports higher prices for some assets, the mixed-price total appears higher than reality, making real losses appear smaller or even showing artificial gains
- This allows operations that actually exceed `loss_tolerance` to complete successfully, bypassing the protocol's core safety mechanism
- Conversely, if the new aggregator reports lower prices, artificial losses are detected, causing valid operations to fail with `ERR_EXCEED_LOSS_LIMIT`

**Share Price Corruption**: The vault's share ratio is calculated using `total_usd_value` [17](#0-16) . Mixed aggregator prices corrupt this calculation, causing users to receive incorrect share amounts during deposits and withdrawals, directly affecting user funds.

**Severity: HIGH** - This vulnerability compromises a fundamental protocol invariant (loss tolerance enforcement) and has direct financial impact on user funds through incorrect valuation and share pricing.

## Likelihood Explanation

**High Probability During Normal Operations**: This vulnerability requires no malicious actors or deliberate coordination. It naturally arises when:
- An honest admin performs legitimate oracle maintenance (upgrading to improved price feeds)
- An honest operator executes normal vault operations with DeFi protocols

**Architectural Design Enables Race**: 
1. Operations span multiple transactions by design, with asset updates occurring in separate transactions between `end_op_with_bag()` and `end_op_value_update_with_bag()`
2. The OracleConfig is a shared object accessible concurrently
3. No coordination mechanism exists - the oracle module cannot check vault statuses, and vault operations cannot prevent oracle changes
4. Operations can take minutes to complete across multiple blocks, providing a large timing window

**Real-World Scenario**: With frequent vault operations (multiple daily) and periodic oracle maintenance (weekly/monthly aggregator upgrades for better price feeds or new protocols), this race condition will naturally occur during normal protocol usage. The timing window spans from when the first asset value is updated until the last asset value is updated - potentially several minutes across multiple transactions.

## Recommendation

Implement a coordination mechanism between oracle configuration changes and vault operations:

1. **Option A - Oracle-Level Status Check**: Add a registry in OracleConfig that tracks active vault operations. Vaults register when entering `VAULT_DURING_OPERATION_STATUS` and deregister when returning to `VAULT_NORMAL_STATUS`. The `change_switchboard_aggregator()` function checks this registry and reverts if any vault is mid-operation.

2. **Option B - Vault-Level Aggregator Lock**: Store the aggregator address used at operation start in the operation context. Asset update functions verify they're using the same aggregator. If the aggregator has changed, either revert or require re-capturing the initial snapshot with the new aggregator.

3. **Option C - Atomic Update Window**: Add a configurable "oracle update window" parameter. When an aggregator change is initiated, set a timestamp. Vault operations that started before this timestamp must complete with the old aggregator; new operations use the new aggregator. This provides a grace period for in-flight operations.

Recommended implementation is Option B as it's the least disruptive and maintains clear separation of concerns between modules.

## Proof of Concept

The vulnerability can be demonstrated with the following transaction sequence:

1. Vault has assets: PrincipalCoin (1000 units @ $1 = $1000) and AssetCoin (1000 units @ $1 = $1000), total = $2000
2. Operator calls `start_op_with_bag()` → captures initial snapshot: $2000
3. Operator calls `update_free_principal_value()` → reads price from Aggregator A ($1), records $1000
4. Admin calls `change_switchboard_aggregator()` for AssetCoin → changes to Aggregator B ($1.10)
5. Operator calls `update_coin_type_asset_value()` → reads price from Aggregator B ($1.10), records $1100
6. Operator calls `end_op_value_update_with_bag()` → final snapshot: $2100
7. Loss calculation: $2000 - $2100 = -$100 (apparent gain masking real loss)

If both assets actually lost 5% value (should be $1900 total, $100 real loss), the mixed aggregator prices show an artificial $100 gain instead, allowing the operation to complete when it should have triggered `ERR_EXCEED_LOSS_LIMIT` if the real loss exceeded the configured `loss_tolerance`.

### Citations

**File:** volo-vault/sources/operation.move (L24-24)
```text
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
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

**File:** volo-vault/sources/volo_vault.move (L1107-1107)
```text
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1109-1113)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );
```

**File:** volo-vault/sources/volo_vault.move (L1136-1136)
```text
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1146-1150)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
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

**File:** volo-vault/sources/oracle.move (L31-37)
```text
public struct OracleConfig has key, store {
    id: UID,
    version: u64,
    aggregators: Table<String, PriceInfo>,
    update_interval: u64,
    dex_slippage: u256, // Pool price and oracle price slippage parameter (used in adaptors related to DEX)
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
