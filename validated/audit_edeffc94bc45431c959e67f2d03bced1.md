### Title
Timestamp Truncation in Navi Lending Protocol Causes Systematic Interest Underaccounting for Volo Vault Positions

### Summary
The Navi lending protocol (lending_core) integrated by Volo vault contains a timestamp truncation vulnerability identical to the external report. When converting milliseconds to seconds for interest calculations, fractional milliseconds are permanently lost, causing systematic underaccounting of interest across all reserves. This affects Volo vault positions whenever operators interact with Navi AccountCaps during vault operations.

### Finding Description
The vulnerability exists in the Navi lending protocol's state update mechanism that Volo depends on. [1](#0-0) 

**Root Cause:**
The `update_state` function calculates time elapsed by truncating milliseconds to seconds via integer division, but then updates `last_update_timestamp` to the full current timestamp including the truncated fractional milliseconds. [2](#0-1) 

The timestamp is then updated to the full `current_timestamp` value: [3](#0-2) 

And persisted to storage: [4](#0-3) 

**Exploit Path:**
1. Volo vault stores Navi `AccountCap` objects as DeFi assets [5](#0-4) 

2. Vault operators borrow AccountCaps during operations and interact with Navi lending through functions like `incentive_v3::deposit_with_account_cap` [6](#0-5) 

3. This calls `lending::deposit_with_account_cap` [7](#0-6) 

4. Which triggers `logic::execute_deposit` that calls `update_state_of_all` [8](#0-7) 

5. This updates all reserves' state with the vulnerable timestamp truncation logic [9](#0-8) 

**Why Protections Fail:**
No validation exists to prevent timestamp drift. The fractional milliseconds (<1000ms) are silently discarded on every state update, accumulating lost interest over time.

### Impact Explanation
**Severity: Medium to High**

The vulnerability causes systematic underaccounting of interest across ALL Navi lending protocol reserves:

- **Direct Financial Loss**: Interest accrual is reduced for all suppliers and increased borrowing costs are reduced for all borrowers
- **Volo Vault Impact**: When vault position values are calculated via `navi_adaptor::calculate_navi_position_value`, the undercounted interest reduces the vault's asset values [10](#0-9) 
- **Accumulating Effect**: Each interaction with Navi loses fractional time. With frequent vault operations, this compounds to significant interest loss
- **Protocol-Wide Impact**: Affects not just Volo users but all Navi protocol participants

### Likelihood Explanation
**Likelihood: High**

This vulnerability triggers automatically during normal protocol operations:

1. **Frequent Trigger**: Every vault operation that interacts with Navi (deposit, withdraw, borrow, repay via AccountCap) triggers `update_state_of_all`
2. **No Special Permissions Required**: Standard vault operator actions execute the vulnerable code path
3. **Guaranteed Occurrence**: The truncation happens on EVERY state update, not just edge cases
4. **Observable in Tests**: Vault operation tests demonstrate the exact call path [11](#0-10) 

### Recommendation
Apply the same fix as the external report to the Navi lending_core protocol:

**In `logic.move::update_state()`:**
```move
// Calculate truncated seconds for interest
let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;

// Calculate indices using truncated seconds
// ... (existing interest calculation logic)

// FIX: Update timestamp by the ACTUAL time used in calculations, not current time
let new_last_update_timestamp = last_update_timestamp + (timestamp_difference * 1000);
storage::update_state(storage, asset, new_borrow_index, new_supply_index, new_last_update_timestamp, scaled_treasury_amount);
```

This ensures that only the time period actually used for interest calculation is consumed from the timestamp, preserving fractional milliseconds for future updates.

### Proof of Concept
**Scenario:** Vault operator interacts with Navi multiple times in quick succession

**Setup:**
- Vault has Navi AccountCap with active supply/borrow positions
- Initial state: `last_update_timestamp = 1000ms`

**Execution:**
1. At T=2999ms, operator calls vault operation that deposits to Navi
   - `timestamp_difference = (2999 - 1000) / 1000 = 1 second`
   - Interest accrued for 1 second only (999ms lost)
   - `last_update_timestamp` updated to 2999ms

2. At T=3500ms, operator calls another operation
   - `timestamp_difference = (3500 - 2999) / 1000 = 0 seconds`
   - NO interest accrued (501ms lost)
   - `last_update_timestamp` updated to 3500ms

3. At T=4200ms, another operation
   - `timestamp_difference = (4200 - 3500) / 1000 = 0 seconds`
   - NO interest accrued (700ms lost)
   - `last_update_timestamp` updated to 4200ms

**Result:**
- Total real time elapsed: 3200ms = 3.2 seconds
- Interest accrued for: 1 second only
- Lost time: 2.2 seconds (68.75% of interest never accrues)

**Verification:**
The vulnerable code path is exercised in existing tests where vault operators interact with Navi lending through borrowed AccountCaps [12](#0-11)

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L37-62)
```text
    public(friend) fun execute_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256
    ) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_deposit<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_supply_balance(storage, asset, user, amount);

        if (!is_collateral(storage, asset, user)) {
            storage::update_user_collaterals(storage, asset, user)
        };

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L243-251)
```text
    public(friend) fun update_state_of_all(clock: &Clock, storage: &mut Storage) {
        let count = storage::get_reserves_count(storage);

        let i = 0;
        while (i < count) {
            update_state(clock, storage, i);
            i = i + 1;
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L256-288)
```text
    fun update_state(clock: &Clock, storage: &mut Storage, asset: u8) {
        // e.g. get the current timestamp in milliseconds
        let current_timestamp = clock::timestamp_ms(clock);

        // Calculate the time difference between now and the last update
        let last_update_timestamp = storage::get_last_update_timestamp(storage, asset);
        let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;

        // Get All required reserve configurations
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);
        let (current_supply_rate, current_borrow_rate) = storage::get_current_rate(storage, asset);
        let (_, _, _, reserve_factor, _) = storage::get_borrow_rate_factors(storage, asset);
        let (_, total_borrow) = storage::get_total_supply(storage, asset);

        // Calculate new supply index via linear interest
        let linear_interest = calculator::calculate_linear_interest(timestamp_difference, current_supply_rate);
        let new_supply_index = ray_math::ray_mul(linear_interest, current_supply_index);

        // Calculate new borrowing index via compound interest
        let compounded_interest = calculator::calculate_compounded_interest(timestamp_difference, current_borrow_rate);
        let new_borrow_index = ray_math::ray_mul(compounded_interest, current_borrow_index);

        // Calculate the treasury amount
        let treasury_amount = ray_math::ray_mul(
            ray_math::ray_mul(total_borrow, (new_borrow_index - current_borrow_index)),
            reserve_factor
        );
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);

        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_treasury_amount);
        // storage::increase_balance_for_pool(storage, asset, scaled_supply_amount, scaled_borrow_amount + scaled_reserve_amount) // **No need to double calculate interest
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L477-493)
```text
    public(friend) fun update_state(
        storage: &mut Storage,
        asset: u8,
        new_borrow_index: u256,
        new_supply_index: u256,
        last_update_timestamp: u64,
        scaled_treasury_amount: u256
    ) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);

        reserve.current_borrow_index = new_borrow_index;
        reserve.current_supply_index = new_supply_index;
        reserve.last_update_timestamp = last_update_timestamp;
        reserve.treasury_balance = reserve.treasury_balance + scaled_treasury_amount;
    }
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L1-29)
```text
module volo_vault::navi_adaptor;

use lending_core::account::AccountCap as NaviAccountCap;
use lending_core::dynamic_calculator;
use lending_core::storage::Storage;
use math::ray_math;
use std::ascii::String;
use sui::clock::Clock;
use volo_vault::vault::Vault;
use volo_vault::vault_oracle::{Self, OracleConfig};
use volo_vault::vault_utils;

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L798-813)
```text
    public fun deposit_with_account_cap<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap
    ) {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        lending::deposit_with_account_cap<CoinType>(clock, storage, pool, asset, deposit_coin, account_cap);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L483-492)
```text
    public(friend) fun deposit_with_account_cap<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        account_cap: &AccountCap
    ) {
        base_deposit(clock, storage, pool, asset, account::account_owner(account_cap), coin::into_balance(deposit_coin))
    }
```

**File:** volo-vault/tests/operation/operation.test.move (L3225-3265)
```text
            vault_utils::parse_key<NaviAccountCap>(0),
        );
        let split_to_deposit_balance = principal_balance.split(500_000_000);
        let mut sui_pool = s.take_shared<Pool<SUI_TEST_COIN>>();
        let mut incentive_v2 = s.take_shared<IncentiveV2>();
        let mut incentive_v3 = s.take_shared<IncentiveV3>();
        incentive_v3::deposit_with_account_cap<SUI_TEST_COIN>(
            &clock,
            &mut storage,
            &mut sui_pool,
            0,
            split_to_deposit_balance.into_coin(s.ctx()),
            &mut incentive_v2,
            &mut incentive_v3,
            navi_account_cap,
        );

        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            asset_bag,
            tx_bag,
            principal_balance,
            coin_type_asset_balance,
        );

        let navi_account_cap_type = vault_utils::parse_key<NaviAccountCap>(0);
        navi_adaptor::update_navi_position_value<SUI_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            navi_account_cap_type,
            &mut storage,
        );

        let mock_cetus_asset_type = vault_utils::parse_key<
            MockCetusPosition<SUI_TEST_COIN, USDC_TEST_COIN>,
        >(0);
        mock_cetus::update_mock_cetus_position_value<SUI_TEST_COIN, SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault,
```
