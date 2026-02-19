### Title
Missing Health Factor Verification for Suilend Obligations Allows Liquidatable Positions

### Summary
The `end_op_value_update_with_bag()` function only verifies that Suilend obligations are returned to the vault but does not check their health status or debt levels. This allows operators to return overleveraged obligations (where debt exceeds collateral) that can be liquidated by external actors, causing losses beyond the intended loss tolerance protection. Unlike Navi positions which have dedicated health verification, Suilend obligations have no equivalent health checks.

### Finding Description

The vulnerability exists in the Suilend obligation verification logic [1](#0-0) .

The check only verifies that the `SuilendObligationOwnerCap` is present in the vault's asset bag, but performs no validation of the obligation's health status, debt levels, or whether it is in a liquidatable state.

**Root Cause**: Missing health factor verification for Suilend obligations, creating an asymmetry with Navi integration:

1. **Navi has health checks**: A dedicated health limiter module exists [2](#0-1)  that explicitly verifies health factors before allowing operations.

2. **Suilend has NO health checks**: Despite Suilend providing `is_healthy()` and `is_liquidatable()` functions [3](#0-2) , these are never called in the vault operation flows.

3. **Valuation treats overleveraged as zero**: When an obligation has more debt than collateral, the adaptor returns a value of 0 [4](#0-3) .

4. **Loss tolerance is insufficient**: While the system checks for value losses [5](#0-4)  and enforces tolerance limits [6](#0-5) , this treats overleveraged obligations as mere "valuation losses" rather than liquidatable liabilities.

**Why Existing Protections Fail**:

The loss tolerance mechanism is designed to limit strategy losses per epoch, but it fundamentally mischaracterizes the risk of an overleveraged obligation. An obligation where `borrowed_value > deposited_value` is not just "worth less" - it is actively liquidatable by any external actor on the Suilend protocol [7](#0-6) . The liquidation carries additional penalties (liquidation bonuses) that cause losses beyond what the tolerance system accounts for.

### Impact Explanation

**Direct Fund Impact**: 
- Vault holds obligations with liabilities exceeding collateral value
- External actors can liquidate these positions on Suilend at any time
- Liquidation penalties (typically 5-10% based on `liquidation_bonus` configuration) cause additional losses beyond the tolerance-allowed valuation decrease
- With default tolerance of 0.1% per epoch, an operator could create multiple small overleveraged positions within a single epoch

**Security Integrity Impact**:
- Violates the stated invariant that "Health-factor enforcement for Navi" extends to all lending integrations
- Creates asymmetric risk management between Navi (health-checked) and Suilend (unchecked)
- Bypasses the intended purpose of health limiters for lending positions

**Quantified Impact**:
- If vault has $1M USD value with 0.1% tolerance = $1,000 allowed loss per epoch
- An obligation with $1,000 collateral and $1,050 debt appears as $0 value (within tolerance)
- External liquidation with 10% bonus extracts $100 additional value beyond the tolerance limit
- Multiple operations per epoch could compound this effect

**Affected Parties**: All vault depositors whose funds back the overleveraged obligations.

### Likelihood Explanation

**Reachable Entry Point**: The `start_op_with_bag()` function is publicly callable by any operator with valid `OperatorCap` [8](#0-7) .

**Feasible Preconditions**: 
- Attacker needs `OperatorCap` (a granted but not admin role)
- No special timing or market conditions required
- Does not require compromising admin capabilities

**Execution Practicality**:
1. Operator borrows healthy Suilend obligation via `start_op_with_bag()`
2. Uses obligation to borrow additional funds on Suilend protocol
3. Takes on debt exceeding collateral value (making it overleveraged)
4. Returns obligation via `end_op_with_bag()` - passes presence check
5. Value update shows loss within tolerance - transaction completes
6. External actor liquidates the obligation on Suilend for profit

**Attack Complexity**: Low - straightforward sequence of standard operations.

**Detection**: Difficult to detect as the operation completes successfully and appears as a legitimate "loss within tolerance."

**Economic Rationality**: 
- Loss tolerance settings determine feasibility (default 0.1% allows $1K loss per $1M)
- Liquidation incentives make external actors likely to liquidate quickly
- Multiple operations per epoch can amplify the impact

### Recommendation

**Immediate Fix**: Implement Suilend health verification analogous to Navi:

1. **Create `suilend_limiter.move`** in the health-limiter module:
```
module limiter::suilend_adaptor;

public fun verify_suilend_obligation_healthy<ObligationType>(
    lending_market: &LendingMarket<ObligationType>,
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    clock: &Clock,
) {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());
    obligation::refresh(obligation, lending_market.reserves(), clock);
    
    assert!(
        obligation::is_healthy(obligation),
        EObligationUnhealthy
    );
    
    assert!(
        !obligation::is_liquidatable(obligation),
        EObligationLiquidatable
    );
}
```

2. **Add health check in `end_op_value_update_with_bag()`** after line 342:
```
if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
    let suilend_asset_type = vault_utils::parse_key<...>(defi_asset_id);
    assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
    
    // ADD HEALTH CHECK HERE
    let obligation_cap = vault.get_defi_asset<T, SuilendObligationOwnerCap<ObligationType>>(
        suilend_asset_type
    );
    limiter::suilend_adaptor::verify_suilend_obligation_healthy(
        lending_market,
        obligation_cap,
        clock
    );
};
```

3. **Add regression tests** that verify:
   - Healthy Suilend obligations can complete operations
   - Overleveraged obligations (debt > collateral) abort with clear error
   - Liquidatable obligations cannot pass verification
   - Consistency with Navi health checking behavior

### Proof of Concept

**Initial State**:
- Vault has $1M total value with 0.1% loss tolerance ($1,000 allowed loss per epoch)
- Vault holds a healthy Suilend obligation with $5,000 collateral and $2,500 debt (net value = $2,500)

**Attack Sequence**:

1. **Operator starts operation** calling `start_op_with_bag()` with the Suilend obligation
2. **During operation**: Operator borrows additional $3,000 on Suilend, making the obligation:
   - Collateral: $5,000
   - Debt: $5,500
   - Net value: -$500 (overleveraged, liquidatable)
3. **Operator returns assets** via `end_op_with_bag()`:
   - Line 342 check passes (obligation cap is present) ✓
   - No health verification performed ✓
4. **Value update** via `end_op_value_update_with_bag()`:
   - `total_usd_value_before` = $1,000,000 (includes $2,500 obligation value)
   - Suilend adaptor returns 0 for overleveraged obligation
   - `total_usd_value_after` = $997,500 (obligation now valued at 0)
   - Loss = $2,500
   - Tolerance check: $2,500 > $1,000 → **ABORTS with ERR_EXCEED_LOSS_LIMIT**

**Note**: With default tolerance, this specific scenario would abort. However, if tolerance is set higher (e.g., 1% = $10,000 allowed loss), or if multiple smaller overleveraged positions are created, the attack succeeds.

**Modified PoC with Higher Tolerance**:
- Same setup but vault tolerance = 1% ($10,000 allowed loss)
- Obligation becomes overleveraged by $2,500
- Loss tolerance check passes ($2,500 < $10,000) ✓
- Operation completes successfully
- **External actor liquidates** the obligation on Suilend
- Liquidation bonus (10%) extracts additional $500 from collateral
- **Total actual loss**: $3,000 ($2,500 overleveraging + $500 liquidation penalty)

**Expected vs Actual**:
- **Expected**: Health check should abort when obligation becomes liquidatable
- **Actual**: Only presence check performed, overleveraged obligations can pass if within loss tolerance

**Success Condition**: Vault holds a liquidatable Suilend obligation that external actors can exploit, with actual losses exceeding intended tolerance protection.

### Citations

**File:** volo-vault/sources/operation.move (L94-104)
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
```

**File:** volo-vault/sources/operation.move (L336-343)
```text
        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L790-796)
```text
    public fun is_healthy<P>(obligation: &Obligation<P>): bool {
        le(obligation.weighted_borrowed_value_upper_bound_usd, obligation.allowed_borrow_value_usd)
    }

    public fun is_liquidatable<P>(obligation: &Obligation<P>): bool {
        gt(obligation.weighted_borrowed_value_usd, obligation.unhealthy_borrow_value_usd)
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L85-88)
```text
    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L511-519)
```text
    public fun liquidate<P, Repay, Withdraw>(
        lending_market: &mut LendingMarket<P>,
        obligation_id: ID,
        repay_reserve_array_index: u64,
        withdraw_reserve_array_index: u64,
        clock: &Clock,
        repay_coins: &mut Coin<Repay>, // mut because we probably won't use all of it
        ctx: &mut TxContext,
    ): (Coin<CToken<P, Withdraw>>, RateLimiterExemption<P, Withdraw>) {
```
