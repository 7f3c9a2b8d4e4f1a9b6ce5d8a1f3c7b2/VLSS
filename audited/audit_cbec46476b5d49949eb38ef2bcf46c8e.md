### Title
Navi Adaptor Oracle Price Decimal Mismatch Causes Incorrect Share Valuation

### Summary
The Navi adaptor uses `get_asset_price()` which returns oracle prices in their native decimal precision, but then passes these prices to `mul_with_oracle_price()` which assumes 18-decimal precision. When oracle feeds are configured with different decimal precisions (e.g., 8 or 9 decimals, common for crypto oracles), the Navi position USD value is calculated incorrectly, directly corrupting the vault's `total_usd_value` and `share_ratio`, causing share inflation or deflation for all vault users.

### Finding Description

The vulnerability exists in the Navi adaptor's position value calculation: [1](#0-0) 

The adaptor retrieves oracle prices using `get_asset_price()`, which returns prices in their configured decimal precision (variable per asset): [2](#0-1) 

Each asset's price has a configurable `decimals` field: [3](#0-2) [4](#0-3) 

However, `mul_with_oracle_price()` expects prices in exactly 18-decimal format: [5](#0-4) [6](#0-5) 

**Root Cause**: The function divides by `ORACLE_DECIMALS` (10^18), but the input price may have 8, 9, or other decimal precisions. If an asset's oracle is configured with 8 decimals instead of 18, the USD value will be calculated as 10^10 times smaller than it should be.

**Correct Pattern**: Other adaptors like Cetus and Momentum use `get_normalized_asset_price()` which normalizes all prices to 9 decimals: [7](#0-6) [8](#0-7) 

The correct pattern is also used for free principal valuation: [9](#0-8) 

### Impact Explanation

**Direct Fund Impact**: The incorrect Navi position USD value corrupts the vault's total USD value calculation, which directly determines the share ratio used for all deposits and withdrawals: [10](#0-9) 

**Share Inflation Scenario** (oracle with 8 decimals instead of 18):
- Navi position actual value: $1,000,000
- Calculated value: $1,000,000 / 10^10 = $0.0001
- `total_usd_value` understated by 10^10
- `share_ratio` = understated_total_usd / total_shares → artificially low
- On deposit: users receive (deposit_amount / low_share_ratio) → 10^10x more shares than deserved
- Result: Massive share inflation, vault insolvency, existing users lose funds

**Share Deflation Scenario** (oracle with >18 decimals, less common):
- Position value overstated
- `share_ratio` artificially high
- On deposit: users receive fewer shares, losing funds to vault
- On withdrawal: users receive more than deserved, draining vault

**Affected Users**: All vault depositors and withdrawers, as share calculations are system-wide.

**Severity**: HIGH - Direct fund theft/loss through share manipulation, triggered automatically during normal vault operations.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability triggers during `update_navi_position_value()` which is called by vault operators during normal operations: [11](#0-10) 

**Feasible Preconditions**: 
1. Vault has Navi positions (standard DeFi integration)
2. Any asset in the Navi position has an oracle configured with ≠18 decimals
3. Common: Pyth and Switchboard crypto oracles typically use 8-9 decimals, not 18

**Execution Practicality**: No attacker action required - the bug triggers automatically when operators update asset values (required for normal vault operation). The vault operator is trusted but unaware of the decimal mismatch.

**Economic Rationality**: For 8-decimal oracles, depositors can extract 10^10x leverage on their deposits. A $1 deposit could mint shares worth $10 billion in vault value, immediately draining the vault on withdrawal.

**Detection**: Operators may not notice until massive discrepancies appear in share ratios or total USD values, by which time significant damage has occurred.

### Recommendation

**Fix**: Replace `get_asset_price()` with `get_normalized_asset_price()` in the Navi adaptor to ensure consistent 9-decimal precision:

```move
// In navi_adaptor.move, line 63:
- let price = vault_oracle::get_asset_price(config, clock, coin_type);
+ let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This matches the pattern used by Cetus and Momentum adaptors and ensures correct USD value calculation regardless of oracle decimal configuration.

**Additional Checks**:
1. Add validation that oracle decimal precision matches expected format when adding aggregators
2. Add integration tests with various oracle decimal configurations (8, 9, 18 decimals)
3. Add assertion in `mul_with_oracle_price()` to validate price range is reasonable
4. Document decimal precision requirements clearly in function comments

**Test Cases**:
1. Test Navi position valuation with 8-decimal oracle feed
2. Test Navi position valuation with 18-decimal oracle feed  
3. Test share ratio calculations with mixed decimal oracles
4. Test deposit/withdrawal flow with incorrect Navi valuations

### Proof of Concept

**Initial State**:
1. Vault with $1,000,000 total value, 1,000,000 shares (share_ratio = 1.0)
2. Navi position with 1,000 USDC supplied (worth $1,000)
3. USDC oracle configured with 8 decimals: price = 100000000 (representing $1.00)

**Transaction Steps**:
1. Operator calls `update_navi_position_value()` for USDC position
2. Navi adaptor calculates:
   - Scaled balance: 1000 * 10^9 (Navi uses 9-decimal normalization)
   - Gets oracle price: 100000000 (8 decimals, but no normalization applied)
   - Calculates: `mul_with_oracle_price(1000 * 10^9, 100000000)`
   - = (10^12 * 10^8) / 10^18 = 10^20 / 10^18 = 100 (cents instead of $1000!)
3. Vault total_usd_value = $1,000,000 + $1 = $1,000,001 (should be $1,001,000)
4. Alice deposits $1,000 when share_ratio ≈ 1.0 (understated due to missing $999)
5. Alice receives ≈1,000 shares
6. Bob deposits $1,000 after Navi value is corrected to $1,000
7. Vault total_usd_value jumps to $1,002,000, share_ratio = $1,002,000 / 1,001,000 ≈ 1.001
8. Bob receives ≈999 shares for same $1,000 deposit

**Expected Result**: Both Alice and Bob should receive same shares for same deposit amount.

**Actual Result**: Alice receives more shares due to temporarily understated Navi position value, diluting Bob's position. With larger decimal mismatches (e.g., asset with 1-decimal oracle), the discrepancy becomes catastrophic.

### Citations

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
}
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

**File:** volo-vault/sources/oracle.move (L158-178)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);
```

**File:** volo-vault/sources/utils.move (L9-10)
```text
const DECIMALS: u256 = 1_000_000_000; // 10^9
const ORACLE_DECIMALS: u256 = 1_000_000_000_000_000_000; // 10^18
```

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-72)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-64)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1297-1317)
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
```
