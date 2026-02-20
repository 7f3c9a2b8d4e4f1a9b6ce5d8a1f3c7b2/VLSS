# Audit Report

## Title
Vault Operations DoS Due to Stub Implementation of MMT v3 Math Functions

## Summary
All MMT v3 mathematical functions are stub implementations that unconditionally abort. When an operator adds a MomentumPosition to a vault (a legitimately supported operation), the vault's strict 0ms update interval requirement causes all operations requiring total USD value calculation to fail until the position is removed, creating a temporary DoS condition.

## Finding Description

The protocol includes explicit support for MomentumPosition integration across multiple modules. However, the MMT v3 dependency contains only stub implementations that unconditionally abort. [1](#0-0) [2](#0-1) 

The momentum adaptor's value calculation depends on these aborting functions: [3](#0-2) 

The vault enforces a MAX_UPDATE_INTERVAL of 0 milliseconds: [4](#0-3) 

When calculating total USD value, the vault requires all assets to have been updated within this interval: [5](#0-4) 

When a new asset is added, its `assets_value_updated` timestamp is initialized to 0: [6](#0-5) 

Operators can add MomentumPositions through the public interface: [7](#0-6) 

Once a MomentumPosition is present, critical operations are affected:

**Deposit execution:** [8](#0-7) 

**Withdrawal execution:** [9](#0-8) 

**Operations start:** [10](#0-9) 

**Operations end:** [11](#0-10) 

The position can be removed via `remove_defi_asset_support` when `assets_value_updated` is still 0: [12](#0-11) 

## Impact Explanation

**Operational DoS**: While a MomentumPosition is present, all core vault operations are blocked:
- User deposits cannot be executed (funds stuck in request buffer)
- User withdrawals cannot be executed (shares locked)
- Rebalancing operations cannot proceed
- Protocol revenue generation halts

**Severity**: HIGH. While the DoS is real and affects all core functionality, it is recoverable through operator intervention. The operator can call `remove_defi_asset_support` to remove the position (which satisfies the removal condition since `assets_value_updated == 0`). However, this requires operator diagnosis and manual intervention, potentially taking hours to days, during which all vault operations remain blocked and user funds are temporarily inaccessible.

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

Operators would reasonably expect MomentumPosition integration to work based on:
- Dedicated `momentum_adaptor` module exists in production code
- `operation` module explicitly handles MomentumPosition borrowing/returning alongside other position types (Navi, Cetus, Suilend)
- Public `add_new_defi_asset` interface accepts MomentumPosition
- No code warnings or documentation indicating incomplete implementation
- Similar patterns working correctly for other position types

**Trigger Scenario**:
1. Operator adds MomentumPosition via `add_new_defi_asset` (legitimate action)
2. Any subsequent deposit execution, withdrawal execution, or operation start/end attempts
3. Transaction aborts with `ERR_USD_VALUE_NOT_UPDATED`
4. Vault operations blocked until operator identifies root cause and removes position

This represents an implementation gap rather than a malicious attack - honest operators using an advertised but incomplete feature.

## Recommendation

**Short-term fix:**
1. Remove MomentumPosition support from the codebase until MMT v3 is fully implemented
2. Add explicit checks in `add_new_defi_asset` to prevent adding MomentumPosition
3. Document that MomentumPosition integration is not yet ready

**Long-term fix:**
1. Complete the MMT v3 implementation with functional math functions
2. Add integration tests that verify MomentumPosition value updates work correctly
3. Consider adding a feature flag system to disable incomplete integrations at runtime

## Proof of Concept

```move
#[test]
fun test_momentum_position_dos() {
    // Setup: Create vault with operator
    let (vault, operation, operator_cap, clock) = setup_vault_and_operator();
    
    // Step 1: Operator adds MomentumPosition (legitimate action)
    let momentum_position = create_test_momentum_position();
    operation::add_new_defi_asset<SUI, MomentumPosition>(
        &operation,
        &operator_cap,
        &mut vault,
        0, // idx
        momentum_position
    );
    
    // Step 2: Any operation requiring get_total_usd_value now fails
    // This will abort with ERR_USD_VALUE_NOT_UPDATED because:
    // - assets_value_updated[momentum_asset] = 0
    // - MAX_UPDATE_INTERVAL = 0
    // - For any positive timestamp: now - 0 > 0, failing the check
    
    operation::execute_deposit<SUI>(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &oracle_config,
        request_id,
        max_shares
    ); // ABORTS HERE with ERR_USD_VALUE_NOT_UPDATED
}
```

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-9)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L19-27)
```text
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L69-91)
```text
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();

    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
    (amount_a, amount_b, sqrt_price)
}
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L806-821)
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
```

**File:** volo-vault/sources/volo_vault.move (L994-1006)
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

**File:** volo-vault/sources/volo_vault.move (L1353-1372)
```text
public(package) fun set_new_asset_type<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    // assert!(!self.assets.contains(asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);
    assert!(!self.asset_types.contains(&asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);

    self.asset_types.push_back(asset_type);
    self.assets_value.add(asset_type, 0);
    self.assets_value_updated.add(asset_type, 0);

    emit(NewAssetTypeAdded {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1390-1413)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();

    let asset_type = vault_utils::parse_key<AssetType>(idx);

    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    self.asset_types.remove(index);

    let asset_value = self.assets_value[asset_type];
    let asset_value_updated = self.assets_value_updated[asset_type];
    assert!(asset_value == 0 || asset_value_updated == 0, ERR_ASSET_TYPE_NOT_FOUND);

    emit(DefiAssetRemoved {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
}
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L565-574)
```text
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```
