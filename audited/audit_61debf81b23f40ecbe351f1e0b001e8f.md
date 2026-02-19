### Title
Unsupported Coin Types in Navi Positions Cause Vault DoS via Oracle Price Lookup Failure

### Summary
The `calculate_navi_position_value()` function retrieves coin types from Navi storage without validating they are supported by the vault's oracle configuration. When the vault's Navi account holds positions in unsupported coin types, the oracle price lookup aborts with `ERR_AGGREGATOR_NOT_FOUND`, causing a complete denial-of-service for critical vault operations including deposits and operation completion.

### Finding Description

The vulnerability exists in the Navi adaptor's position valuation logic: [1](#0-0) 

The function iterates through all Navi reserves and retrieves coin types from Navi storage without validation. For any reserve where the account has a non-zero balance, it attempts to fetch the price from the vault's oracle configuration. [2](#0-1) 

The oracle's `get_asset_price` function contains an assertion that aborts the transaction if the requested coin type is not registered in the aggregators table. This is not a graceful failure that returns 0 - it's a hard abort with error code `ERR_AGGREGATOR_NOT_FOUND`. [3](#0-2) 

Operators can trigger this condition during vault operations by borrowing the `NaviAccountCap` and depositing any Navi-supported coin type into the Navi lending protocol, regardless of whether the vault's oracle supports pricing that asset: [4](#0-3) 

The operation flow has no validation mechanism to ensure that coin types used in Navi interactions are supported by the vault's oracle configuration.

### Impact Explanation

**Operational DoS - Critical Vault Functions Disabled:**

1. **Deposit Execution Blocked**: The vault's deposit flow requires calling `update_navi_position_value` before processing deposits, as evidenced by test patterns: [5](#0-4) 

2. **Operation Completion Blocked**: Regular vault operations that update asset values also require successful Navi position valuation: [6](#0-5) 

3. **Catch-22 Recovery Problem**: To remove the problematic position from Navi, an operation must complete successfully. But completing an operation requires updating Navi position values, which fails due to the unsupported coin type. The vault becomes permanently stuck.

**Affected Parties**: All vault depositors are unable to deposit or withdraw, and operators cannot perform any operations involving Navi positions.

### Likelihood Explanation

**High Likelihood - Multiple Realistic Attack Vectors:**

1. **Operator Error (Unintentional)**: An operator legitimately using the `NaviAccountCap` during operations may deposit a Navi-supported coin type without realizing the vault's oracle doesn't support it. This is especially likely when Navi adds new reserve support before the vault's oracle configuration is updated.

2. **Malicious Operator**: A malicious operator with valid `OperatorCap` can intentionally DOS the vault by depositing even a minimal amount (1 unit) of any unsupported coin type during an operation.

3. **Navi Protocol Evolution**: Navi can add support for new coin types at any time without coordinating with individual vaults. If a vault's Navi account somehow acquires a position in these new reserves (through legitimate strategy adjustments), the vault becomes DOS'd.

**Attack Complexity**: Extremely low - requires only one `deposit_with_account_cap` call during a normal operation window.

**Detection**: The vulnerability manifests immediately upon the next `update_navi_position_value` call, making it instantly detectable but also instantly disruptive.

**Economic Rationality**: Attack cost is minimal (gas + dust amount of unsupported coin), while impact is severe (complete vault DOS). No special conditions required.

### Recommendation

**Immediate Fix - Add Coin Type Validation:**

Add a validation check before calling the oracle to verify the coin type is supported. Modify `calculate_navi_position_value()`:

```move
let coin_type = storage.get_coin_type(i - 1);

if (supply == 0 && borrow == 0) {
    i = i - 1;
    continue
};

// Add validation here - skip reserves with unsupported coin types
if (!config.aggregators.contains(coin_type)) {
    i = i - 1;
    continue
};

let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**Alternative Fix - Preventive Validation in Operations:**

Add a whitelist check in the operation flow to validate that operators can only interact with oracle-supported coin types when using the `NaviAccountCap`. This requires maintaining a list of allowed coin types for Navi interactions.

**Required Test Cases:**
1. Test that position value calculation skips unsupported coin types gracefully
2. Test that deposits/operations succeed when Navi account has positions in unsupported coin types with zero balance
3. Test recovery scenarios when an unsupported position exists

### Proof of Concept

**Initial State:**
- Vault has a `NaviAccountCap` stored as defi asset ID 0
- Oracle config has aggregators for SUI and USDC only
- Navi protocol supports SUI, USDC, and WETH reserves

**Attack Sequence:**

1. Operator starts operation with `start_op_with_bag`, borrowing the `NaviAccountCap`
2. Operator calls `incentive_v3::deposit_with_account_cap<WETH>` with 1 WETH (or any amount)
   - Navi accepts the deposit (WETH is a valid Navi reserve)
   - Account now has non-zero WETH position
3. Operator returns `NaviAccountCap` and calls `end_op_with_bag`
4. System attempts to call `update_navi_position_value` to update vault accounting
5. `calculate_navi_position_value` iterates reserves, finds WETH position with non-zero balance
6. Calls `get_asset_price(config, clock, "WETH_coin_type")`
7. **Transaction aborts with ERR_AGGREGATOR_NOT_FOUND (error code 2_001)**

**Expected Result**: Operation completes successfully with updated position values

**Actual Result**: Transaction aborts, vault cannot complete operations or process deposits, permanent DoS until oracle is updated or WETH position is removed (which requires completing an operation)

**Success Condition for Attacker**: Vault is stuck and cannot process deposits or operations involving Navi positions

### Citations

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

**File:** volo-vault/sources/oracle.move (L17-17)
```text
const ERR_AGGREGATOR_NOT_FOUND: u64 = 2_001;
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/sources/operation.move (L118-124)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };
```

**File:** volo-vault/tests/update/update.test.move (L964-970)
```text
        navi_adaptor::update_navi_position_value<SUI_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage,
        );
```

**File:** volo-vault/tests/update/update.test.move (L1062-1068)
```text
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            navi_asset_type,
            &mut storage,
        );
```
