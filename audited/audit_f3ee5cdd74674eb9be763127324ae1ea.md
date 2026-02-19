### Title
Underwater Navi Positions Valued at Zero Instead of Negative Equity, Hiding Losses and Inflating Vault Share Price

### Summary
The `calculate_navi_position_value` function returns 0 when a Navi lending position becomes underwater (borrows exceed supplies), instead of recognizing the negative net value as a liability. This causes the vault's `total_usd_value` to be artificially inflated, resulting in incorrect share pricing that unfairly distributes losses among shareholders and allows early withdrawers to exit at inflated prices while late withdrawers bear the full losses.

### Finding Description

**AccountCap Usage as Vault Asset:**
Yes, `AccountCap` (aliased as `NaviAccountCap`) is used as collateral/an asset in volo-vault. The `AccountCap` struct has `key, store` abilities [1](#0-0) , allowing it to be stored in the vault's `assets` Bag.

The vault stores DeFi assets including Navi AccountCaps in its assets Bag [2](#0-1) . These AccountCaps are added via `add_new_defi_asset` [3](#0-2)  and borrowed/returned during operations [4](#0-3) [5](#0-4) .

**Value Determination Mechanism:**
The value of a Navi AccountCap is calculated by `calculate_navi_position_value` in the navi_adaptor module [6](#0-5) . This function:
1. Iterates through all Navi reserves
2. Retrieves supply and borrow balances for the account
3. Applies dynamic interest indices
4. Converts to USD using oracle prices
5. Computes net value as: `total_supply_usd_value - total_borrow_usd_value`

**Root Cause - Critical Accounting Flaw:**
When a position becomes underwater (borrows exceed supplies), the function returns 0 instead of recognizing negative equity [7](#0-6) . This value is then stored in the vault's `assets_value` table via `finish_update_asset_value` [8](#0-7) , which aggregates into `total_usd_value` [9](#0-8)  used for share ratio calculations [10](#0-9) .

**Why Existing Protections Fail:**
While the Navi lending protocol prevents positions from becoming unhealthy during user operations [11](#0-10) [12](#0-11) , positions can still become underwater post-creation through:
- Market price movements (collateral depreciation or debt appreciation)
- Interest accrual on borrowed amounts
- Oracle price updates between transactions

The loss tolerance mechanism only detects the drop from positive value to 0 [13](#0-12) , but does not account for the continued negative equity beyond that point or the liquidation penalties that will realize additional losses.

### Impact Explanation

**Direct Financial Harm:**
1. **Hidden Liabilities**: A position with -$10,000 net equity (e.g., $90k collateral, $100k debt) is reported as $0 value instead of recognizing the $10k liability
2. **Inflated Share Pricing**: The vault's `total_usd_value` excludes underwater position liabilities, causing share ratio to be artificially high
3. **Unfair Loss Distribution**: New depositors purchase shares at inflated prices, unknowingly buying into hidden losses
4. **Liquidation Cascade**: When underwater positions are eventually liquidated, 5-10% liquidation penalties [14](#0-13)  create additional unexpected losses
5. **Wealth Transfer**: Early withdrawers extract value at inflated share prices while remaining shareholders absorb the realized losses

**Quantified Damage:**
For a vault holding a single underwater Navi position:
- Position: $80,000 collateral, $100,000 debt = -$20,000 actual value
- Reported value: $0
- Vault's other assets: $200,000
- **Actual total value**: $180,000
- **Reported total value**: $200,000
- **Share price inflation**: 11% overvalued
- Users depositing during this period overpay by 11%

**Affected Parties:**
- Late depositors who buy overpriced shares
- Late withdrawers who bear concentrated losses when positions liquidate
- Protocol reputation from accounting inaccuracies

### Likelihood Explanation

**Attacker Capabilities:**
No special privileges required. The vulnerability is triggered by normal market conditions affecting leveraged Navi positions held by the vault.

**Attack Complexity:**
**Natural Exploitation (High Probability):**
- Vaults using Navi positions with any leverage (>1x exposure) are susceptible
- Normal crypto market volatility (20-50% price swings) can trigger underwater states
- No active attack needed - passive market movements suffice

**Accelerated Exploitation (Medium Difficulty):**
- Oracle price manipulation if oracle security is weak
- Coordinated market manipulation on low-liquidity collateral assets
- Flash crash scenarios in underlying DeFi protocols

**Feasibility Conditions:**
- Vault must hold Navi AccountCap with leveraged positions (borrow > 0)
- Market prices must move adversely: collateral ↓ or debt ↑
- Position health factor drops below 1.0 (underwater)
- Vault operator calls `update_navi_position_value` during operations

**Detection Constraints:**
The issue is masked in normal vault accounting and only becomes apparent when:
- Positions are liquidated
- Manual health factor checks are performed (not currently enforced)
- Post-mortem analysis after withdrawal queue failures

**Probability Assessment:**
**High Likelihood** for vaults with leveraged Navi positions during volatile markets. The 2022 crypto crash saw 40-60% drawdowns on major assets - sufficient to push leveraged positions underwater. Even modest 2-3x leverage becomes underwater with 33-50% collateral depreciation.

### Recommendation

**Immediate Mitigation:**
1. **Enforce Health Factor Checks**: Mandate health factor verification before accepting position value updates:
```
// In navi_adaptor.move, after line 26
let health_factor = limiter::navi_adaptor::is_navi_position_healthy(
    clock, storage, oracle, account, MIN_HEALTH_FACTOR
);
assert!(health_factor, ERR_UNDERWATER_POSITION);
```

2. **Reject Underwater Positions**: Prevent returning underwater positions to vault:
```
// In operation.move end_op_with_bag, after line 238
if (defi_asset_type == type_name::get<NaviAccountCap>()) {
    // Verify position is healthy before accepting return
    verify_navi_position_health(navi_account_cap, storage, oracle, clock);
    vault.return_defi_asset(navi_asset_type, navi_account_cap);
}
```

3. **Track Negative Equity Separately**: Add explicit liability tracking:
```
// In Vault struct
liabilities: Table<String, u256>,
```
Update `calculate_navi_position_value` to return signed integers or split into assets/liabilities.

4. **Implement Loss Recognition**: When positions go underwater, immediately recognize full loss including estimated liquidation penalty (not just to zero).

**Long-term Solution:**
- Redesign accounting to support negative asset values (liabilities)
- Implement automated position closure when health factor drops below threshold
- Add comprehensive health monitoring with off-chain alerts
- Create liquidation reserve fund to absorb underwater position losses

**Test Cases:**
1. Test vault behavior when Navi position becomes underwater
2. Verify share price calculation with underwater positions
3. Test loss tolerance triggers with negative equity positions
4. Simulate liquidation scenarios and verify loss accounting

### Proof of Concept

**Initial State:**
1. Vault holds NaviAccountCap with:
   - 100 ETH supplied ($200,000 @ $2,000/ETH)
   - 150,000 USDC borrowed
   - Net value: $50,000
   - Health factor: 1.33 (healthy)
2. Vault total_usd_value: $250,000 (including $200k free principal)
3. Total shares: 250,000
4. Share ratio: $1.00 per share

**Exploitation Steps:**

**Transaction 1 - Market Crash:**
- ETH price drops from $2,000 to $1,400
- Position now: 100 ETH ($140,000) - 150,000 USDC debt
- Net value: -$10,000 (underwater)
- Health factor: 0.93 (can be liquidated)

**Transaction 2 - Vault Operation & Value Update:**
```
operation::start_op_with_bag() // Borrow AccountCap
navi_adaptor::update_navi_position_value() // Returns 0 instead of -$10k
operation::end_op_value_update_with_bag() // Accepts 0 value
```

**Transaction 3 - User Deposits:**
- Vault total_usd_value reported: $200,000 (free principal) + $0 (underwater Navi) = $200,000
- Actual value: $200,000 - $10,000 = $190,000
- User deposits 20,000 USDC
- Shares minted: 20,000 / ($200,000 / 250,000) = 25,000 shares
- **Should receive**: 20,000 / ($190,000 / 250,000) = ~26,316 shares
- **Loss to user**: 1,316 shares (~$1,053)

**Transaction 4 - Position Liquidated:**
- Liquidator repays debt, seizes collateral with 10% bonus
- Net loss to vault: $10,000 + 10% penalty = ~$11,000
- Loss suddenly appears in vault accounting
- Late shareholders absorb concentrated loss

**Expected vs Actual:**
- **Expected**: Underwater position recognized as -$10k liability, share price reflects true NAV
- **Actual**: Underwater position valued at $0, share price inflated by 5.3%, losses hidden until liquidation

**Success Condition:**
The vault reports `total_usd_value = $200,000` when true net asset value is $190,000, demonstrating the accounting flaw allows a 5.3% share price inflation.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L8-11)
```text
    struct AccountCap has key, store {
        id: UID,
        owner: address
    }
```

**File:** volo-vault/sources/volo_vault.move (L113-114)
```text
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
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

**File:** volo-vault/sources/operation.move (L235-239)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L28-28)
```text
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L91-91)
```text
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L739-748)
```text
    public fun execute_liquidate_for_testing<CoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        liquidated_user: address,
        collateral_asset: u8,
        loan_asset: u8,
        amount: u256
    ): (u256, u256, u256) {
        execute_liquidate<CoinType, CollateralCoinType>(clock, oracle, storage, liquidated_user, collateral_asset, loan_asset, amount)
```
