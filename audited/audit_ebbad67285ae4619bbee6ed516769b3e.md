### Title
Reserve Iteration Gas Exhaustion in Lending Core Operations

### Summary
The lending_core protocol iterates through ALL reserves (up to 255) on every user operation (deposit, withdraw, borrow, repay, liquidate), performing expensive state updates for each reserve. As the protocol grows and adds more reserves, this iteration will eventually exceed Sui's gas limits, causing complete protocol DoS and preventing users from withdrawing funds.

### Finding Description

The root cause is in the `update_state_of_all` function which unconditionally iterates through all reserves: [1](#0-0) 

This function is called at the beginning of EVERY user operation:
- In `execute_deposit`: [2](#0-1) 
- In `execute_withdraw`: [3](#0-2) 
- In `execute_borrow`: [4](#0-3) 
- In `execute_repay`: [5](#0-4) 
- In `execute_liquidate`: [6](#0-5) 

The protocol allows up to 255 reserves: [7](#0-6) 

Each iteration calls `update_state` which performs computationally expensive operations: [8](#0-7) 

The developers explicitly acknowledge this gas concern: [9](#0-8) 

Additionally, the Volo vault's Navi adaptor also iterates through all reserves when calculating position values: [10](#0-9) 

### Impact Explanation

**Operational Impact**: As reserves approach 255, every user operation becomes progressively more gas-intensive. At some threshold (likely well before 255 reserves), normal operations will exceed Sui's per-transaction gas limit, causing:

1. **Complete Protocol DoS**: Users cannot deposit, withdraw, borrow, repay, or liquidate
2. **Fund Locking**: Users with existing positions cannot withdraw their collateral or repay loans
3. **Liquidation Failure**: Unhealthy positions cannot be liquidated, exposing the protocol to bad debt
4. **Cascading Failure**: Both the lending_core AND the Volo vault (which depends on it via Navi adaptor) become unusable

**Affected Parties**: All protocol users and the Volo vault that integrates with lending_core.

**Severity**: HIGH - This creates a critical operational failure path that locks user funds and breaks core protocol functionality.

### Likelihood Explanation

**Realistic Scenario**: This vulnerability does not require any attack or compromise. It occurs through normal protocol growth:

1. Admins legitimately add new reserves as the protocol expands (supported assets)
2. Each reserve addition is a valid operation using StorageAdminCap: [11](#0-10) 

**Feasibility**: The protocol is designed to support multiple assets (tests show 4-6 reserves currently), and DeFi lending protocols naturally grow to support more assets over time. The 255 reserve limit suggests the protocol intends to scale significantly.

**Developer Awareness**: The TODO comment confirms this is a known concern that requires mitigation but hasn't been implemented yet.

**Probability**: MEDIUM-HIGH - As the protocol gains adoption and adds more supported assets, this becomes increasingly likely. The exact threshold depends on Sui's gas limits and computational cost per reserve, but the linear O(n) complexity with n=255 makes exceeding limits highly probable.

### Recommendation

**Immediate Mitigation**:
1. Implement lazy state updates - only update reserves that have been modified or are being accessed in the current transaction
2. Track last update timestamp per reserve and skip updates for recently-updated reserves within the same block
3. Implement batched state updates that can be called separately by keepers/operators

**Code-Level Fix**:
```
// Instead of updating all reserves:
public(friend) fun update_state_of_relevant(
    clock: &Clock, 
    storage: &mut Storage,
    relevant_assets: vector<u8>
) {
    let i = 0;
    let len = vector::length(&relevant_assets);
    while (i < len) {
        let asset = *vector::borrow(&relevant_assets, i);
        update_state(clock, storage, asset);
        i = i + 1;
    }
}

// Then in operations, only update the specific asset being operated on
// plus user's collateral/loan assets
```

**Additional Safeguards**:
- Add a maximum reserve count that's tested to be safe within gas limits
- Implement gas profiling tests that verify operations complete within limits as reserves increase
- Add monitoring to alert when operations approach gas limit thresholds

### Proof of Concept

**Initial State**: Protocol has added reserves progressively over time

**Transaction Sequence**:
1. Admin adds reserves 1-100 successfully (gas costs increase but remain acceptable)
2. Admin adds reserves 101-200 (operations become noticeably slower/more expensive)
3. Admin adds reserves 201-250 (approaching critical threshold)
4. User attempts to deposit/withdraw/borrow/repay at reserve count ≥ threshold
5. Transaction fails due to gas limit exceeded
6. User funds are locked - cannot perform any operations
7. Protocol is effectively frozen for all users

**Expected Result**: User operations complete successfully

**Actual Result**: All user operations fail with gas limit exceeded, protocol becomes unusable, funds are locked

**Success Condition**: Protocol can support 255 reserves without any transaction exceeding gas limits

### Notes

This vulnerability is particularly insidious because it creates a "scaling cliff" where the protocol appears to function normally until suddenly crossing a threshold where all operations become impossible. The developer TODO comment confirms this is a known architectural issue that requires redesign but has not been addressed. The dependency of Volo vault's Navi adaptor on this same iteration pattern compounds the problem across the entire protocol ecosystem.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L47-47)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L81-81)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L131-131)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L168-168)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L207-207)
```text
        update_state_of_all(clock, storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L241-242)
```text
    // May cause an increase in gas
    // TODO: If the upgrade fails, need to modify this method to private and add another function
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L11-11)
```text
    public fun max_number_of_reserves(): u8 {255}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L37-72)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L154-180)
```text
    public entry fun init_reserve<CoinType>(
        _: &StorageAdminCap,
        pool_admin_cap: &PoolAdminCap,
        clock: &Clock,
        storage: &mut Storage,
        oracle_id: u8,
        is_isolated: bool,
        supply_cap_ceiling: u256,
        borrow_cap_ceiling: u256,
        base_rate: u256,
        optimal_utilization: u256,
        multiplier: u256,
        jump_rate_multiplier: u256,
        reserve_factor: u256,
        ltv: u256,
        treasury_factor: u256,
        liquidation_ratio: u256,
        liquidation_bonus: u256,
        liquidation_threshold: u256,
        coin_metadata: &CoinMetadata<CoinType>,
        ctx: &mut TxContext
    ) {
        version_verification(storage);

        let current_idx = storage.reserves_count;
        assert!(current_idx < constants::max_number_of_reserves(), error::no_more_reserves_allowed());
        reserve_validation<CoinType>(storage);
```
