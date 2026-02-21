# Audit Report

## Title
Zero Oracle Price Enables Share Ratio Manipulation and Fund Theft

## Summary
The vault oracle system lacks zero-price validation when retrieving Switchboard aggregator prices. When a Navi position asset price returns 0 due to oracle malfunction, the position's USD value is calculated as 0, severely understating the vault's total value. This deflates the share ratio, allowing attackers to acquire excess shares during deposits and subsequently withdraw more funds than deposited, directly stealing value from existing shareholders.

## Finding Description

The vulnerability stems from missing zero-price validation across the oracle price retrieval and position valuation pipeline, breaking the core security guarantee that share ratios accurately reflect vault value.

**1. Switchboard Price Retrieval Without Validation**

The `get_current_price()` function retrieves the raw Switchboard aggregator result value without validating it is non-zero. [1](#0-0) 

The function only validates timestamp freshness but performs no bounds checking on the price value itself. The Switchboard Decimal type explicitly supports zero values. [2](#0-1) 

**2. Asset Price Query Without Validation**

The `get_asset_price()` function returns the cached price directly without validating it is non-zero. [3](#0-2) 

The error constants confirm no zero-price validation exists. [4](#0-3) 

**3. Position Value Calculation With Zero Price**

When `calculate_navi_position_value()` retrieves the asset price and it is 0, the multiplication operations produce zero USD values regardless of actual position balances. [5](#0-4) 

If `price = 0`, then both `supply_usd_value` and `borrow_usd_value` become 0, causing the entire Navi position value to be severely understated.

**4. Understated Total Vault Value**

The incorrect position value flows through to the vault's total value calculation, which simply sums all asset values. [6](#0-5) 

**5. Share Ratio Deflation and Excess Share Issuance**

During deposit execution, the deflated share ratio is used to calculate user shares. [7](#0-6) [8](#0-7) [9](#0-8) 

The attacker receives `user_shares = new_usd_value_deposited / share_ratio_before`. With an artificially deflated `share_ratio_before`, the attacker receives significantly more shares than legitimate.

**6. Slippage Check Bypass**

The slippage validation uses attacker-controlled `expected_shares`. [10](#0-9) 

The attacker sets `expected_shares` based on the current (incorrect) deflated ratio, so all checks pass.

**7. Excess Value Extraction**

Upon withdrawal, the corrected share ratio allows extraction of excess value. [11](#0-10) 

## Impact Explanation

**Direct Fund Theft**: This vulnerability enables direct theft of funds from existing vault shareholders through share dilution.

**Attack Mechanics**:
1. Oracle failure causes Navi position asset price → 0
2. Operator updates position value via `update_navi_position_value()` → position valued at 0
3. Vault total value drops from 1M USD to 700K USD (300K Navi position now valued at 0)
4. Share ratio deflates from 1.0 to 0.7 (30% understatement)
5. Attacker deposits 100K USD and receives 142,857 shares (vs. 100K expected)
6. Oracle corrects, operator updates position value → vault value 1.1M USD
7. New share ratio → 1.1M / 1,142,857 = 0.9625
8. Attacker withdraws: 142,857 shares × 0.9625 = 137.5K USD
9. **Net theft: 37.5K USD from existing shareholders**

The loss scales linearly with the mispriced position size and attacker's deposit amount. Existing shareholders' 1M shares are now worth only 962.5K USD, representing a permanent 3.75% value loss that cannot be recovered.

## Likelihood Explanation

**Precondition: Oracle Failure Returning Zero Price**

While Switchboard oracles are generally reliable, zero prices can occur due to:
- Asset delisting from exchanges
- Extreme market volatility causing data feed gaps
- Oracle infrastructure malfunction
- Price aggregation failures with insufficient valid responses

The critical issue is that **the protocol lacks defensive validation** against this invalid state.

**Execution Path**:
1. Attacker monitors oracle prices off-chain (via public Switchboard aggregators)
2. Upon detecting zero price, creates deposit request via `request_deposit`
3. Operator processes request through standard `execute_deposit` flow within 60-second update interval
4. All protocol checks pass (vault status NORMAL, slippage bounds met with attacker-controlled parameters)
5. After oracle correction and position value update, attacker requests withdrawal
6. Standard withdrawal extracts excess value

**Economic Viability**:
- Profit: (mispriced_value / vault_value) × deposit_amount × (1 - fees)
- Example: 30% understatement on 100K deposit = 37.5% gross profit = 37.3K USD net after 0.2% fees
- Attack costs: Gas fees (negligible on Sui) + deposit/withdrawal fees (10-30 bps total)
- Time window: Hours to days depending on oracle monitoring and correction speed

**No Privilege Requirements**: Any user can create deposit requests. The attack appears as legitimate activity during the oracle malfunction period. The operator honestly executes deposits, unaware of the mispricing.

## Recommendation

Add zero-price validation at the oracle layer:

```move
// In volo-vault/sources/oracle.move
const ERR_ZERO_PRICE: u64 = 2_006;

public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    let price = current_result.result().value() as u256;
    assert!(price > 0, ERR_ZERO_PRICE); // ADD THIS CHECK
    price
}
```

Additionally, consider adding minimum share ratio checks or circuit breakers that pause deposits when vault valuation drops significantly within a short timeframe.

## Proof of Concept

```move
#[test]
fun test_zero_price_share_manipulation() {
    // Setup: Create vault with 1M USD (700K free + 300K Navi position), 1M shares
    let mut scenario = test_scenario::begin(ADMIN);
    
    // 1. Normal state: ratio = 1.0
    let initial_ratio = vault.get_share_ratio(&clock); // = 1e9
    
    // 2. Oracle returns 0 for Navi asset, operator updates position
    oracle.set_current_price(&clock, navi_asset_type, 0);
    navi_adaptor::update_navi_position_value(&mut vault, &oracle, &clock, navi_asset_type, &mut storage);
    
    // 3. Vault value drops to 700K, ratio deflates to 0.7
    let deflated_ratio = vault.get_share_ratio(&clock); // = 0.7e9
    assert!(deflated_ratio < initial_ratio * 7 / 10);
    
    // 4. Attacker deposits 100K, receives excess shares
    let attacker_deposit = 100_000 * DECIMALS;
    vault.execute_deposit(&clock, &oracle, request_id, u256::max_value!());
    let attacker_shares = /* calculate from deposit */ 142_857 * DECIMALS; // ~42% more than expected
    
    // 5. Oracle corrects, value restored
    oracle.set_current_price(&clock, navi_asset_type, correct_price);
    navi_adaptor::update_navi_position_value(&mut vault, &oracle, &clock, navi_asset_type, &mut storage);
    
    // 6. Attacker withdraws with excess shares
    let withdraw_amount = vault.execute_withdraw(&clock, &oracle, withdraw_request_id, u64::max_value!());
    
    // 7. Verify theft
    assert!(withdraw_amount > attacker_deposit * 137 / 100); // 37% profit
    // Existing shareholders lost ~3.75% of value
}
```

## Notes

This vulnerability is particularly severe because:

1. **No operator error required**: The operator correctly executes all operations; the protocol simply lacks validation
2. **Difficult to detect**: During the attack window, all transactions appear legitimate
3. **Irreversible damage**: Share dilution permanently reduces existing shareholders' value
4. **Scales with vault size**: Larger vaults with significant Navi positions face proportionally larger theft potential

The root cause is the oracle system's assumption that Switchboard will never return zero prices, violating defensive programming principles for financial protocols that must handle oracle failures gracefully.

### Citations

**File:** volo-vault/sources/oracle.move (L16-22)
```text
// ---------------------  Errors  ---------------------//
const ERR_AGGREGATOR_NOT_FOUND: u64 = 2_001;
const ERR_PRICE_NOT_UPDATED: u64 = 2_002;
const ERR_AGGREGATOR_ALREADY_EXISTS: u64 = 2_003;
const ERR_AGGREGATOR_ASSET_MISMATCH: u64 = 2_004;
const ERR_INVALID_VERSION: u64 = 2_005;

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

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-69)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L820-821)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L841-844)
```text
    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L845-850)
```text
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1013)
```text
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```
