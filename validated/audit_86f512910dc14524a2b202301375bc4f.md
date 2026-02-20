# Audit Report

## Title
Underwater Navi Positions Valued at Zero Instead of Negative Equity, Hiding Losses and Inflating Vault Share Price

## Summary
The `calculate_navi_position_value` function incorrectly returns 0 for underwater Navi lending positions (where borrows exceed collateral) instead of recognizing negative equity. This causes the vault's total USD value calculation to exclude liabilities, artificially inflating the share price. Depositors overpay for shares while early withdrawers extract excess value, creating unfair loss distribution among vault participants.

## Finding Description

**Root Cause - Critical Accounting Flaw:**

The `calculate_navi_position_value` function contains a fundamental accounting error. When calculating the net value of a Navi lending position, it computes `total_supply_usd_value - total_borrow_usd_value`. However, when the position becomes underwater (borrows exceed supplies), instead of returning a negative value or signaling an error, it simply returns 0. [1](#0-0) 

This zero value flows directly into the vault's accounting system through `finish_update_asset_value`, which stores it in the `assets_value` table without validation. [2](#0-1) [3](#0-2) 

**Impact on Share Pricing:**

The vault's `get_total_usd_value` function aggregates all individual asset values from the `assets_value` table, including the incorrectly reported 0 for underwater positions. [4](#0-3) 

This inflated total USD value directly affects the share ratio calculation. [5](#0-4) 

During deposit execution, the inflated share ratio causes users to receive fewer shares than they should. [6](#0-5) 

**Why Existing Protections Fail:**

1. **Navi Protocol Health Checks**: While the Navi lending protocol enforces health factor checks during borrow and withdraw operations, these only prevent creating unhealthy positions during active transactions. Positions can still become underwater AFTER creation due to market price movements, interest accrual, or oracle price updates. [7](#0-6) 

2. **Loss Tolerance Mechanism**: The operation loss tolerance check compares total USD value before and after operations, but only detects the drop FROM a positive value. It does not account for continued negative equity beyond that point when the position is already reporting as 0. [8](#0-7) 

3. **Health Limiter Not Enforced**: While a health limiter module exists for verifying Navi position health, grep search confirms it is never called in the vault's operation flow. [9](#0-8) 

4. **Value Updates Allowed Independently**: Asset values can be updated through `update_navi_position_value` which directly calls `finish_update_asset_value`, allowing underwater positions to be recorded as 0 at any time. [2](#0-1) 

## Impact Explanation

**Direct Financial Harm:**

1. **Hidden Liabilities**: A position with -$20,000 net equity (e.g., $80k collateral, $100k debt) is reported as $0, completely hiding the $20k liability from vault accounting.

2. **Inflated Share Pricing**: For a vault with $200k in other assets and a -$20k underwater Navi position:
   - **Actual total value**: $180,000  
   - **Reported total value**: $200,000
   - **Share price inflation**: 11.1% overvalued

3. **Unfair Loss Distribution**: 
   - New depositors purchase shares at the inflated 11% premium, unknowingly buying into hidden losses
   - Early withdrawers extract value at inflated share prices
   - Late withdrawers and remaining shareholders absorb the concentrated losses when positions are liquidated

4. **Liquidation Cascade**: When underwater positions are eventually liquidated, the liquidation bonus defined in the Navi protocol's LiquidationFactors creates additional unexpected losses beyond the debt shortfall. [10](#0-9) 

**Affected Parties:**
- Late depositors who overpay by the inflation percentage
- Late withdrawers who bear disproportionate losses  
- Protocol reputation from accounting inaccuracies
- All shareholders through wealth transfer to early withdrawers

## Likelihood Explanation

**High Likelihood** - This vulnerability is triggered by normal market conditions without requiring any attacker privileges or active exploitation.

**Natural Exploitation Path:**

1. **Preconditions** (Common):
   - Vault holds Navi AccountCap with leveraged positions (borrow > 0)
   - Any vault using Navi for yield generation meets this condition

2. **Trigger** (Passive - No Attack Needed):
   - Market prices move adversely: collateral value ↓ 33-50% or debt value ↑
   - Interest accrues on borrowed amounts between transactions
   - Oracle prices update reflecting market conditions
   - Position health factor drops below 1.0 (underwater)

3. **Exploitation** (Automatic):
   - Normal vault operations call `update_navi_position_value` before deposits/withdrawals
   - Function returns 0 for underwater position
   - Share price becomes inflated automatically
   - Depositors overpay, early withdrawers benefit

**Probability Assessment:**

Even modest 2-3x leverage becomes underwater with 33-50% collateral depreciation, which is common during crypto market volatility. Historical precedent: The 2022 crypto crash saw 40-60% drawdowns on major assets, sufficient to push leveraged positions underwater. Current DeFi markets regularly experience 20-50% price swings that would trigger this condition.

**No Special Capabilities Required:**
- No admin/operator privileges needed
- No oracle manipulation required  
- No coordinated attack necessary
- Simply normal market conditions affecting leveraged positions

## Recommendation

Modify the `calculate_navi_position_value` function to handle underwater positions properly:

**Option 1 (Preferred): Error on Underwater Positions**
- Add an assertion to abort when `total_borrow_usd_value > total_supply_usd_value`
- This prevents the vault from operating with negative equity positions
- Forces liquidation or position adjustment before continuing operations

**Option 2: Track Negative Equity**
- Change return type to support signed integers (use i256 or separate flag)
- Modify `assets_value` table to track negative values
- Update `get_total_usd_value` to properly subtract liabilities

**Option 3: Enforce Health Limiter**
- Make `verify_navi_position_healthy` mandatory in operation flow
- Add health factor checks before and after all operations touching Navi positions
- Set minimum health factor threshold (e.g., 1.2x) with safety margin

**Implementation for Option 1:**
```move
// In calculate_navi_position_value function
if (total_supply_usd_value < total_borrow_usd_value) {
    abort error::position_underwater() // Add new error code
};
```

## Proof of Concept

```move
#[test]
fun test_underwater_navi_position_hides_losses() {
    // Setup: Create vault with Navi position
    let mut scenario = test_scenario::begin(ADMIN);
    
    // 1. Initialize vault with $100k in free principal
    let vault = create_test_vault(&mut scenario);
    add_principal_to_vault(&mut vault, 100_000 * DECIMAL_9);
    
    // 2. Create Navi position with leverage
    // Supply: $80k collateral, Borrow: $60k (healthy at 1.33x)
    let navi_account = create_navi_position(
        &mut scenario,
        80_000 * DECIMAL_9, // supply
        60_000 * DECIMAL_9  // borrow
    );
    add_navi_asset_to_vault(&mut vault, navi_account);
    
    // 3. Update values - position is healthy, total = $100k free + $20k net = $120k
    update_all_asset_values(&mut vault, &clock, &oracle_config);
    let total_before = vault.get_total_usd_value(&clock);
    assert!(total_before == 120_000 * DECIMAL_PRICE, 0);
    
    // 4. Market crash: Collateral drops 50% to $40k, Debt stays $60k
    // Position is now underwater: $40k collateral - $60k debt = -$20k
    update_oracle_price(&mut oracle_config, COLLATERAL_TYPE, 50_000); // 50% drop
    
    // 5. Update Navi position value - BUG: Returns 0 instead of error/negative
    navi_adaptor::update_navi_position_value(
        &mut vault,
        &oracle_config,
        &clock,
        navi_asset_type,
        &mut navi_storage
    );
    
    // 6. Verify the bug: Total value reports $100k (free principal only)
    // Should be $80k ($100k - $20k loss), but reports $100k
    let total_after = vault.get_total_usd_value(&clock);
    assert!(total_after == 100_000 * DECIMAL_PRICE, 0); // BUG: Hides $20k loss
    
    // 7. Depositor overpays: Share ratio is inflated by 25%
    let share_ratio = vault.get_share_ratio(&clock);
    // Actual ratio should be: $80k / shares
    // Reported ratio is: $100k / shares (25% inflated)
    
    // 8. New deposit receives fewer shares than deserved
    let deposit_amount = 20_000 * DECIMAL_9;
    let shares_received = execute_test_deposit(&mut vault, deposit_amount);
    
    // Expected: deposit adds $20k actual value to $80k = $100k total
    // Should receive: shares * (20k/100k) = 20% of total shares
    // Actually receives: shares * (20k/120k) = 16.7% of shares
    // Loss: 3.3% fewer shares = overpaid by 20%
    
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability represents a critical accounting flaw where negative equity is silently converted to zero, violating the fundamental principle that liabilities must be tracked. The issue is particularly severe because:

1. **Silent Failure**: No error or event signals the underwater condition
2. **Cascading Effect**: Each deposit at inflated prices compounds the unfairness
3. **Market Reality**: Leveraged positions becoming underwater is not rare but common during volatility
4. **Protocol-Wide Risk**: Affects all vaults using Navi adaptor for yield generation

The fix should prioritize preventing operations with underwater positions (Option 1) rather than attempting to track negative equity, as the latter adds complexity and may violate vault invariants elsewhere in the system.

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/volo_vault.move (L820-844)
```text
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
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1174-1187)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
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

**File:** volo-vault/sources/volo_vault.move (L1297-1310)
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

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-91)
```text
    public(friend) fun execute_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256 // e.g. 100USDT -> 100000000000
    ): u64 {
        assert!(user_collateral_balance(storage, asset, user) > 0, error::user_have_no_collateral());

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_withdraw<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
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

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-49)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);

    emit(NaviHealthFactorVerified {
        account,
        health_factor,
        safe_check_hf: min_health_factor,
    });

    let is_healthy = health_factor > min_health_factor;

    // hf_normalized has 9 decimals
    // e.g. hf = 123456 (123456 * 1e27)
    //      hf_normalized = 123456 * 1e9
    //      hf = 0.5 (5 * 1e26)
    //      hf_normalized = 5 * 1e8 = 0.5 * 1e9
    //      hf = 1.356 (1.356 * 1e27)
    //      hf_normalized = 1.356 * 1e9
    let mut hf_normalized = health_factor / DECIMAL_E18;

    if (hf_normalized > DECIMAL_E9) {
        hf_normalized = DECIMAL_E9;
    };

    assert!(is_healthy, hf_normalized as u64);
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L97-101)
```text
    struct LiquidationFactors has store {
        ratio: u256, 
        bonus: u256,
        threshold: u256,
    }
```
