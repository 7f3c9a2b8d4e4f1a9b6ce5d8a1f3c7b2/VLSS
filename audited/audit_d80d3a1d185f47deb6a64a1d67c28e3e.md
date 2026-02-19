Audit Report

## Title
Complete Vault DoS Due to Aborting MMT v3 Math Functions in Momentum Position Valuation

## Summary
All MMT v3 mathematical utility functions are stub implementations that unconditionally abort, making it impossible to update MomentumPosition asset values. Since the vault enforces a MAX_UPDATE_INTERVAL of 0 milliseconds for all asset value updates, any vault containing a MomentumPosition becomes permanently unusable, causing complete DoS for deposits, withdrawals, and rebalancing operations.

## Finding Description

**Root Cause:**

The MMT v3 library contains only stub implementations of critical mathematical functions that unconditionally abort: [1](#0-0) [2](#0-1) [3](#0-2) 

The momentum adaptor's valuation logic critically depends on these aborting functions: [4](#0-3) [5](#0-4) 

**Critical Constraint:**

The vault enforces that ALL asset values must be updated within MAX_UPDATE_INTERVAL (0 milliseconds) before calculating total USD value: [6](#0-5) [7](#0-6) 

When new DeFi assets are added, their `assets_value_updated` timestamp is initialized to 0: [8](#0-7) 

**Attack Vector:**

Operators can add MomentumPositions through the public interface: [9](#0-8) [10](#0-9) 

**Affected Operations:**

All critical vault operations call `get_total_usd_value`:

1. **Deposits** require total USD value calculation: [11](#0-10) 

2. **Withdrawals** call `get_share_ratio` which internally calls `get_total_usd_value`: [12](#0-11) [13](#0-12) 

3. **Operations** require total USD value at both start and completion: [14](#0-13) [15](#0-14) 

MomentumPosition is explicitly supported as a borrowable asset type: [16](#0-15) 

## Impact Explanation

This vulnerability causes **CRITICAL** impact:

1. **Complete Vault DoS**: Once a MomentumPosition is added with `assets_value_updated = 0`, any subsequent call to `get_total_usd_value` fails the staleness check (`now - 0 <= 0` is false for any positive timestamp).

2. **Permanent Fund Lockup**: All depositors cannot withdraw their funds because `execute_withdraw` requires `get_share_ratio`, which calls `get_total_usd_value`.

3. **Irrecoverable State**: 
   - Cannot update MomentumPosition value: The update function aborts due to MMT v3 stubs
   - Cannot complete any operations: All require `get_total_usd_value` 
   - Cannot process deposits: Requires total USD value calculation

4. **Protocol-Wide Impact**: Affects entire vault and all depositors, not just a single user.

## Likelihood Explanation

**HIGH Likelihood**:

1. **Low Attack Complexity**: A single operator transaction calling `add_new_defi_asset<PrincipalCoinType, MomentumPosition>` triggers permanent DoS.

2. **Legitimate Use Case**: The MMT v3 integration is clearly intended—a dedicated momentum adaptor exists and the operation module explicitly supports MomentumPosition borrowing. Operators may legitimately attempt to add MomentumPositions expecting them to work.

3. **No Preconditions**: Requires only operator privileges (a trusted role performing normal duties).

4. **Deterministic Effect**: Once added, the vault becomes immediately and permanently unusable.

5. **Implementation Gap**: This is not a theoretical vulnerability but a concrete implementation gap where stub functions were deployed without working implementations.

## Recommendation

**Immediate Actions:**
1. Remove or disable the ability to add MomentumPosition assets until MMT v3 math functions are properly implemented
2. Add validation in `add_new_defi_asset` to prevent adding asset types with non-functional adaptors
3. Consider implementing a grace period or different MAX_UPDATE_INTERVAL policy for newly added assets

**Long-term Fix:**
1. Implement actual mathematical logic in all MMT v3 utility functions (sqrt_price_math, tick_math, liquidity_math)
2. Add integration tests verifying MomentumPosition value updates work end-to-end before enabling this feature in production

**Code Fix Example:**
```move
// In operation.move, add validation before allowing MomentumPosition
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    // Temporarily block MomentumPosition until MMT v3 is implemented
    assert!(
        type_name::get<AssetType>() != type_name::get<MomentumPosition>(),
        ERR_MOMENTUM_NOT_SUPPORTED
    );
    
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```

## Proof of Concept

```move
#[test]
fun test_momentum_position_causes_vault_dos() {
    let mut scenario = test_scenario::begin(ADMIN);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with some deposits
    setup_vault_with_deposits(&mut scenario, &clock);
    
    // Operator adds MomentumPosition (timestamp initialized to 0)
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let operation = scenario.take_shared<Operation>();
        let operator_cap = scenario.take_from_sender<OperatorCap>();
        let momentum_pos = create_test_momentum_position(scenario.ctx());
        
        operation::add_new_defi_asset(
            &operation,
            &operator_cap,
            &mut vault,
            0,
            momentum_pos
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        scenario.return_to_sender(operator_cap);
    };
    
    // Advance clock to non-zero time
    clock.increment_for_testing(1000);
    
    // Try to execute deposit - WILL ABORT
    scenario.next_tx(USER);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let config = scenario.take_shared<OracleConfig>();
        
        // This call will fail with ERR_USD_VALUE_NOT_UPDATED
        // because: now (1000) - last_update_time (0) = 1000 > MAX_UPDATE_INTERVAL (0)
        vault.execute_deposit(&clock, &config, request_id, max_shares);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

## Notes

This vulnerability demonstrates a critical implementation gap where infrastructure code (MMT v3 math functions) was included as stubs but the Volo vault was designed to use it in production. The zero-millisecond MAX_UPDATE_INTERVAL requirement creates an impossible constraint: assets must be updated in the same transaction they are checked, but MomentumPosition updates abort immediately. This combination creates a permanent, unrecoverable DoS condition affecting all vault operations and locking all depositor funds.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/sqrt_price_math.move (L2-32)
```text
    public fun get_amount_x_delta(
        sqrt_price_start: u128, 
        sqrt_price_end: u128, 
        liquidity: u128, 
        round_up: bool
    ) : u64 {
        abort 0
    }
    
    public fun get_amount_y_delta(sqrt_price_start: u128, sqrt_price_end: u128, liquidity: u128, round_up: bool) : u64 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_amount_x_rouding_up(current_price: u128, liquidity: u128, amount: u64, round_up: bool) : u128 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_amount_y_rouding_down(current_price: u128, liquidity: u128, amount: u64, round_up: bool) : u128 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_input(current_price: u128, liquidity: u128, amount: u64, is_token0: bool) : u128 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_output(current_price: u128, liquidity: u128, amount: u64, is_token0: bool) : u128 {
        abort 0
    }
    
    
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L1-35)
```text
module mmt_v3::tick_math {
    use mmt_v3::i32::{I32};
    
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
        abort 0
    }
    
    public fun is_valid_index(arg0: I32, arg1: u32) : bool {
        abort 0
    }
    
    public fun max_sqrt_price() : u128 {
        abort 0
    }
    
    public fun max_tick() : I32 {
        abort 0
    }
    
    public fun min_sqrt_price() : u128 {
        abort 0
    }
    
    public fun min_tick() : I32 {
        abort 0
    }
    
    public fun tick_bound() : u32 {
        abort 0
    }
}
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

**File:** volo-vault/sources/volo_vault.move (L806-841)
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

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```

**File:** volo-vault/sources/operation.move (L94-178)
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
```

**File:** volo-vault/sources/operation.move (L340-377)
```text
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
