### Title
Switchboard Aggregator Decimals Field Not Updated on Aggregator Change Leading to Catastrophic Price Miscalculation

### Summary
The `change_switchboard_aggregator()` function updates the aggregator address and price but fails to update the `decimals` field when switching to an aggregator with different decimal precision. This causes `get_normalized_asset_price()` to apply incorrect decimal normalization, resulting in asset valuations that can be off by factors of billions, directly enabling vault drainage or extreme user fund loss through manipulated share calculations.

### Finding Description

**Root Cause Location:**

The `change_switchboard_aggregator()` function only updates three fields of the `PriceInfo` struct: [1](#0-0) 

The `decimals` field at line 26 is never updated during aggregator changes: [2](#0-1) 

In contrast, `add_switchboard_aggregator()` correctly sets all fields including decimals: [3](#0-2) 

**Why Protections Fail:**

When `get_normalized_asset_price()` retrieves prices, it uses the stored `decimals` field for normalization: [4](#0-3) 

If the admin changes from an 18-decimal aggregator to a 9-decimal aggregator, the function will:
1. Fetch new price: 2_000_000_000 (9 decimals for $2.00)
2. Use old decimals: 18
3. Calculate: 2_000_000_000 / 10^9 = 2 (incorrect, should be 2_000_000_000)
4. Result: 1 billion times undervaluation

The admin-only wrapper provides no validation: [5](#0-4) 

**Execution Path:**

The miscalculated normalized price directly impacts vault share calculations. For deposits: [6](#0-5) 

For withdrawals: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**

1. **Deposit Exploitation**: If price is undervalued by 10^9:
   - User deposits 1,000 SUI worth $2,000
   - Calculated USD value: $0.000002 
   - User receives ~0.000002 shares instead of 2,000 shares
   - User loses essentially all deposited value

2. **Withdrawal Exploitation**: If price is overvalued by 10^9 (opposite decimal change):
   - Attacker with 0.001 shares (worth $0.001)
   - Calculated withdrawal: 1,000,000 SUI worth $2,000,000
   - Attacker drains entire vault

3. **Share Ratio Corruption**: All existing users' share values become incorrect relative to true vault value

**Quantified Damage:**
- Factor of error: 10^(|new_decimals - old_decimals|)
- For 18→9 or 9→18 change: 1 billion times error
- For 18→6 change: 1 trillion times error
- Vault can be completely drained or users can lose 99.9999999% of deposits

**Affected Parties:**
- All vault depositors and share holders
- Protocol's solvency and reputation

### Likelihood Explanation

**Reachable Entry Point:**
The function is callable by admin through the public management interface.

**Feasible Preconditions:**
- Admin performs legitimate aggregator maintenance (switching oracle providers)
- Different Switchboard aggregators may have different decimal configurations
- No validation or warning alerts admin to the decimals mismatch
- Function executes successfully without errors

**Execution Practicality:**
1. **Innocent Admin Action**: Admin switches aggregator during routine maintenance
2. **Immediate Impact**: Next deposit/withdrawal uses wrong decimals
3. **No Detection**: Function completes normally, no error raised
4. **Exploitation Window**: Hours to days before discovery

**Economic Rationality:**
- No attack cost required (admin action triggers vulnerability)
- Passive exploitation: Simply depositing or withdrawing after the change
- High probability: Common operational need to switch oracle providers

**Probability Assessment:** HIGH - This is a normal operational scenario where aggregator changes are legitimate maintenance activities, and the code provides no safeguards or warnings about decimal mismatches.

### Recommendation

**Immediate Fix:**

Modify `change_switchboard_aggregator()` to accept and update the decimals parameter:

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // ADD THIS PARAMETER
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
    price_info.decimals = decimals;  // UPDATE DECIMALS
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

Update the wrapper function: [5](#0-4) 

Add decimals parameter to the wrapper.

**Invariant Checks:**

Add validation to ensure decimals match expected values:
- Event emission should include old and new decimals for audit trail
- Consider adding assertion that decimals are within reasonable range (6-18)

**Test Cases:**

Add regression test that:
1. Adds aggregator with 18 decimals
2. Changes to aggregator with 9 decimals
3. Verifies decimals field is updated to 9
4. Verifies normalized price calculation is correct before and after change
5. Verifies share calculations use correct prices

### Proof of Concept

**Initial State:**
- Vault has 100,000 SUI worth $200,000 (price: $2/SUI)
- SUI aggregator A with 18 decimals returns: 2_000_000_000_000_000_000
- Existing users hold 200,000 shares (ratio: $1/share)

**Attack Steps:**

1. Admin calls `change_switchboard_aggregator()` to switch from aggregator A (18 decimals) to aggregator B (9 decimals)
   - Aggregator B returns: 2_000_000_000 (still $2/SUI, but in 9 decimals)
   - Decimals field remains: 18 (not updated)

2. `get_normalized_asset_price()` is called for SUI:
   - Retrieves price: 2_000_000_000
   - Uses decimals: 18
   - Calculates: 2_000_000_000 / 10^9 = 2
   - **Expected**: 2_000_000_000 (correct normalized price)
   - **Actual**: 2 (1 billion times too small)

3. User withdraws 0.001 shares:
   - USD value: 0.001 * $1 = $0.001
   - Amount calculation: $0.001 / 2 = 500,000,000,000,000 (500 trillion units)
   - **Expected**: ~0.0005 SUI (500,000 units)
   - **Actual**: 500,000,000 SUI (entire vault drained)

**Success Condition:**
Attacker receives billions of times more SUI than deserved, draining vault with minimal shares.

### Citations

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
}
```

**File:** volo-vault/sources/oracle.move (L145-154)
```text
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** volo-vault/sources/oracle.move (L172-177)
```text
    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
```

**File:** volo-vault/sources/oracle.move (L217-219)
```text
    price_info.aggregator = aggregator.id().to_address();
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
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

**File:** volo-vault/sources/volo_vault.move (L839-844)
```text
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```
