# Audit Report

## Title
Momentum Position Accumulated Fees Excluded from Value Calculations Enable Undetected Fund Theft

## Summary
The momentum adaptor calculates position values based solely on liquidity-derived token amounts, completely ignoring accumulated trading fees stored in `owed_coin_x` and `owed_coin_y` fields. This allows operators to collect fees via the public `mmt_v3::collect::fee()` function during operations without triggering the vault's loss detection mechanism, bypassing security controls designed to constrain operator behavior.

## Finding Description

**Root Cause - Incomplete Value Calculation:**

The momentum adaptor's value calculation is fundamentally incomplete. The `get_position_value()` function calls `get_position_token_amounts()` which derives amounts purely from liquidity using `liquidity_math::get_amounts_for_liquidity()`, completely ignoring the `owed_coin_x` and `owed_coin_y` fields that represent accumulated trading fees. [1](#0-0) 

The MMT v3 Position struct clearly contains these fee fields: [2](#0-1) 

**Exploitation Mechanism:**

During operations, operators borrow momentum positions into a Bag they control through `start_op_with_bag()`: [3](#0-2) 

The MMT v3 protocol provides a public `fee()` function that allows anyone with a mutable position reference to collect accumulated fees: [4](#0-3) 

A malicious operator can:
1. Remove the MomentumPosition from the Bag they received
2. Call `mmt_v3::collect::fee()` to extract accumulated fees as Coin objects
3. Transfer these coins to their own address
4. Return the position (now with zero fees) to the Bag
5. Call `end_op_with_bag()` to return the position

The `return_defi_asset()` function performs no validation of the asset's state: [5](#0-4) 

**Why Loss Detection Fails:**

At operation start, `start_op_with_bag()` captures `total_usd_value` by calling `get_total_usd_value()`: [6](#0-5) 

The `get_total_usd_value()` function retrieves pre-stored USD values from the `assets_value` table without recalculation: [7](#0-6) 

These stored values are updated by `finish_update_asset_value()` which blindly stores whatever value adaptors calculate: [8](#0-7) 

Since the momentum adaptor never includes fees in its calculation, both the "before" and "after" total values exclude fees. When `end_op_value_update_with_bag()` compares these values for loss detection, it sees no loss despite the stolen fees: [9](#0-8) 

## Impact Explanation

**Direct Financial Loss:**
The vault loses accumulated trading fees that rightfully belong to depositors. In active liquidity pools, these fees can represent significant value accruing continuously from trading activity.

**Security Control Bypass:**
This vulnerability circumvents the vault's core loss detection mechanism. The vault system explicitly implements value update checks and loss tolerance limits to constrain operator behavior and prevent unauthorized fund extraction. The existence of operator freeze mechanisms and tolerance enforcement demonstrates that operators are not fully trusted.

**Systematic Exploitation:**
- Attack repeatable on every operation cycle
- Multiple momentum positions multiply attack surface
- Losses accumulate completely undetected
- Per-epoch loss_tolerance protection ineffective (no loss recorded)

**Impact Classification: HIGH**
While requiring OperatorCap (semi-trusted role), this explicitly bypasses security checks designed to constrain operators, enabling undetectable theft of vault funds belonging to depositors.

## Likelihood Explanation

**Attacker Capability:**
Requires OperatorCap. However, the vault's architecture explicitly does not fully trust operators, implementing value checks, loss tolerance limits, and freeze mechanisms as security boundaries against malicious operator behavior.

**Attack Complexity:**
Very low. Uses only standard function calls in normal sequence:
1. `start_op_with_bag()` - standard initialization
2. Extract position from Bag (standard Sui Move operation)
3. `mmt_v3::collect::fee()` - public MMT v3 function
4. Return position via `end_op_with_bag()`
5. Value update passes incorrectly

All operations can be executed in a single programmable transaction block.

**Preconditions:**
- Vault holds momentum position (common for DeFi vaults)
- Position has accumulated fees (natural in active pools)
- No special timing required

**Detection Capability:**
Zero. Theft completely invisible to all security checks because fee value never measured.

**Likelihood Assessment: HIGH (if operator is malicious)**
No technical barriers, guaranteed success, zero detection risk, repeatable at no cost.

## Recommendation

Modify `get_position_value()` in the momentum adaptor to include accumulated fees:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
    
    // Add accumulated fees
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    let total_amount_a = amount_a + owed_a;
    let total_amount_b = amount_b + owed_b;
    
    // Continue with existing price validation and value calculation
    // using total_amount_a and total_amount_b instead of amount_a and amount_b
    ...
}
```

Additionally, consider implementing validation in `return_defi_asset()` to verify that returned positions have not had fees collected without proper accounting.

## Proof of Concept

```move
#[test]
fun test_operator_steals_momentum_fees() {
    // Setup: Create vault with momentum position that has accumulated fees
    let mut scenario = test_scenario::begin(OPERATOR);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Initialize vault and add momentum position with fees
    // Position has: liquidity = 1000, owed_coin_x = 50, owed_coin_y = 30
    
    // Capture initial total value (excludes fees)
    let value_before = vault.get_total_usd_value(&clock);
    // value_before = only liquidity value, fees not included
    
    // Operator starts operation and gets Bag with position
    let (mut bag, tx, tx_check, ...) = operation::start_op_with_bag(
        &mut vault, &op, &cap, &clock, 
        vector[0], vector[momentum_type], 0, 0, scenario.ctx()
    );
    
    // Operator extracts position from Bag
    let mut position = bag.remove<String, MomentumPosition>(key);
    
    // Operator collects fees (THIS IS THE EXPLOIT)
    let (fee_x, fee_y) = mmt_v3::collect::fee(
        &mut pool, &mut position, &clock, &version, scenario.ctx()
    );
    // fee_x.value() == 50, fee_y.value() == 30
    
    // Operator transfers stolen fees to their address
    transfer::public_transfer(fee_x, OPERATOR);
    transfer::public_transfer(fee_y, OPERATOR);
    
    // Return position (now with zero fees) to Bag
    bag.add<String, MomentumPosition>(key, position);
    
    // End operation - position returned with no validation
    operation::end_op_with_bag(&mut vault, &op, &cap, bag, tx, ...);
    
    // Update position value (still excludes fees since they're now zero)
    momentum_adaptor::update_momentum_position_value(&mut vault, &config, &clock, ...);
    
    // End with value check
    operation::end_op_value_update_with_bag(&mut vault, &op, &cap, &clock, tx_check);
    
    // ASSERT: No loss detected despite stolen fees
    let value_after = vault.get_total_usd_value(&clock);
    assert!(value_after == value_before); // Loss detection FAILED
    
    // ASSERT: Operator received stolen funds
    assert!(test_scenario::has_most_recent_for_address<Coin<CoinX>>(OPERATOR));
    assert!(test_scenario::has_most_recent_for_address<Coin<CoinY>>(OPERATOR));
}
```

**Notes:**
- This vulnerability exploits the gap between what MMT v3 considers part of position value (liquidity + fees) and what the momentum adaptor measures (liquidity only)
- The attack is completely invisible because the loss detection mechanism compares two values that both exclude fees
- The vault's security model treats operators as constrained actors, making this bypass a genuine security violation
- All operations are valid Sui Move operations available to anyone holding OperatorCap

### Citations

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L10-24)
```text
    public struct Position has store, key {
        id: UID,
        pool_id: ID,
        fee_rate: u64,
        type_x: TypeName,
        type_y: TypeName,
        tick_lower_index: I32,
        tick_upper_index: I32,
        liquidity: u128,
        fee_growth_inside_x_last: u128,
        fee_growth_inside_y_last: u128,
        owed_coin_x: u64,
        owed_coin_y: u64,
        reward_infos: vector<PositionRewardInfo>,
    }
```

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/collect.move (L25-33)
```text
    public fun fee<X, Y>(
        pool: &mut Pool<X, Y>, 
        position: &mut Position, 
        clock: &Clock, 
        version: &Version,
        tx_context: &mut TxContext
    ) : (Coin<X>, Coin<Y>) {
        abort 0
    }
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1436-1449)
```text
public(package) fun return_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    asset: AssetType,
) {
    self.check_version();

    emit(DefiAssetReturned {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.add<String, AssetType>(asset_type, asset);
}
```
