### Title
Momentum Position Liquidity Drainage Enables Fund Theft via Zero-Value Reporting

### Summary
The `get_position_token_amounts()` function faithfully returns zero token amounts when a MomentumPosition's liquidity has been drained to zero. A malicious operator can exploit this by removing all liquidity from a borrowed position, keeping the withdrawn tokens, and returning the empty position to the vault. The position then reports $0 value, resulting in vault fund theft limited only by the loss_tolerance parameter.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The `get_position_token_amounts()` function queries the current state of a MomentumPosition by reading its `liquidity` field: [2](#0-1) 

When the position's liquidity field is 0 (after being drained), the function calls `liquidity_math::get_amounts_for_liquidity()` with `liquidity = 0`, which returns `(amount_a = 0, amount_b = 0)`. This zero-value result propagates through the valuation chain: [3](#0-2) 

**Root Cause:**
There is no invariant check to verify that a borrowed MomentumPosition maintains its liquidity between borrow and return operations. The protocol assumes operators act honestly but provides no enforcement mechanism.

**Why Existing Protections Fail:**

1. **Asset Return Check**: The protocol only verifies the position object is returned, not its liquidity state: [4](#0-3) 

2. **Loss Tolerance**: The only protection is the loss tolerance mechanism, which allows legitimate trading losses but can be exploited: [5](#0-4) 

The default tolerance is 0.1% per epoch, but if set higher (or accumulated across multiple operations), it enables theft: [6](#0-5) 

**Execution Path:**

1. Operator calls `start_op_with_bag()` to borrow MomentumPosition: [7](#0-6) 

2. Operator calls Momentum protocol's `remove_liquidity()` to drain the position: [8](#0-7) 

3. Operator keeps the withdrawn tokens instead of returning them to vault

4. Operator calls `end_op_with_bag()` to return the empty position: [9](#0-8) 

5. `update_momentum_position_value()` calculates $0 value for the drained position: [10](#0-9) 

6. `end_op_value_update_with_bag()` compares before/after values, showing a loss equal to the stolen amount: [11](#0-10) 

### Impact Explanation

**Direct Fund Theft:**
- An operator can steal up to `(vault_base_value * loss_tolerance) / 10000` per epoch
- With default 0.1% tolerance on a $10M vault: $10,000 theft per epoch
- If tolerance is misconfigured to 1%: $100,000 theft per epoch
- Multiple positions can be drained in a single operation to maximize theft within tolerance

**Who is Affected:**
- All vault depositors suffer proportional losses
- The vault's total_usd_value decreases, reducing share values for all holders
- Legitimate operators and admins face reputational damage

**Severity Justification:**
HIGH severity because:
1. Direct, quantifiable fund theft from vault
2. Requires only operator role (not admin compromise)
3. Loss scales with vault size and tolerance configuration
4. No cryptographic complexity - straightforward liquidity manipulation
5. Violates critical invariant: "All borrowed DeFi assets returned"

### Likelihood Explanation

**Attacker Capabilities:**
- Requires OperatorCap - a semi-trusted role with existing vault operation privileges
- Does NOT require AdminCap compromise
- Operator already has legitimate access to borrow and manipulate positions

**Attack Complexity:**
- LOW complexity - requires only:
  1. Call `start_op_with_bag()` with MomentumPosition ID
  2. Call external Momentum protocol `remove_liquidity()`
  3. Transfer withdrawn tokens to attacker wallet
  4. Call `end_op_with_bag()` and `end_op_value_update_with_bag()`

**Feasibility Conditions:**
- Vault must hold at least one MomentumPosition with liquidity
- Loss from theft must be within loss_tolerance limits
- Operation must be enabled (vault in NORMAL status)
- Operator must not be frozen

**Economic Rationality:**
- Operator can steal up to tolerance limit per epoch with minimal gas costs
- Attack is profitable even with 0.1% default tolerance on medium-sized vaults
- Risk of detection is low if done gradually within tolerance bounds

**Detection Constraints:**
- Loss appears as legitimate trading loss within tolerance
- No on-chain evidence distinguishes malicious drainage from legitimate position management
- Only off-chain monitoring of position liquidity changes before/after operations could detect

### Recommendation

**Code-Level Mitigation:**

1. **Add Position State Snapshot at Borrow Time:**
Add to `start_op_with_bag()` to record initial liquidity: [7](#0-6) 

Create a snapshot table storing position ID → initial liquidity mapping for all borrowed positions.

2. **Validate Liquidity Invariant at Return Time:**
Add to `end_op_with_bag()` before returning position: [9](#0-8) 

```
assert!(
    current_position.liquidity() >= initial_snapshot.liquidity() * (1 - allowed_liquidity_decrease_bps) / 10000,
    ERR_POSITION_LIQUIDITY_DECREASED
)
```

3. **Enhanced Value Update Check:**
In `update_momentum_position_value()`, compare against last recorded value: [10](#0-9) 

Add assertion that position value hasn't decreased by more than expected slippage plus fees.

4. **Strengthen Loss Tolerance Granularity:**
Instead of per-epoch aggregate loss tolerance: [5](#0-4) 

Implement per-asset-type loss tracking to prevent concentrating theft in single positions.

**Invariant Checks to Add:**
- `position.liquidity() at return >= position.liquidity() at borrow * (1 - max_acceptable_decrease)`
- Track per-operation, per-asset value changes separately from aggregate vault loss
- Alert or revert if any single position loses > threshold value (e.g., 0.5%) in one operation

**Test Cases:**
1. Test that borrowing and returning position with reduced liquidity fails
2. Test that draining position liquidity completely is caught and reverted
3. Test that partial liquidity removal within acceptable bounds succeeds
4. Test edge case: position with zero liquidity at borrow time (should be handled)
5. Test operator attempting to drain multiple positions in single operation

### Proof of Concept

**Required Initial State:**
- Vault contains MomentumPosition with ID = 1, liquidity = 1000000, worth $10,000
- Vault total_usd_value = $1,000,000
- Vault loss_tolerance = 10 (0.1% = $1,000 max loss per epoch)
- Operator has valid OperatorCap not frozen
- Vault status = NORMAL

**Transaction Steps:**

**Step 1: Start Operation**
```
call start_op_with_bag<PrincipalCoin, CoinA, ObligationB>(
    vault,
    operation,
    operator_cap,
    clock,
    defi_asset_ids: vector[1],  // MomentumPosition ID
    defi_asset_types: vector[type_name::get<MomentumPosition>()],
    principal_amount: 0,
    coin_type_asset_amount: 0,
)
```
- Returns Bag containing MomentumPosition
- Records total_usd_value_before = $1,000,000

**Step 2: Drain Position Liquidity**
```
call mmt_v3::remove_liquidity<CoinA, CoinB>(
    pool,
    borrowed_position,  // from Bag
    liquidity: 1000000,  // drain all liquidity
    min_amount_a: 0,
    min_amount_b: 0,
    clock,
    version,
)
```
- Receives Coin<CoinA> + Coin<CoinB> worth ~$10,000
- Position.liquidity now = 0
- **Operator transfers coins to personal wallet (THEFT)**

**Step 3: Return Empty Position**
```
call end_op_with_bag<PrincipalCoin, CoinA, ObligationB>(
    vault,
    operation,
    operator_cap,
    defi_assets_bag,  // contains position with liquidity=0
    tx,
    principal_balance: empty,
    coin_type_asset_balance: empty,
)
```
- Position returned to vault (check passes - object exists)
- But position now has zero liquidity

**Step 4: Update Position Value**
```
call update_momentum_position_value<PrincipalCoin, CoinA, CoinB>(
    vault,
    config,
    clock,
    asset_type: "momentum_position_1",
    pool,
)
```
- `get_position_token_amounts()` reads liquidity = 0
- Returns (amount_a=0, amount_b=0)
- Calculates position value = $0 (was $10,000)

**Step 5: Finalize Operation**
```
call end_op_value_update_with_bag<PrincipalCoin, ObligationB>(
    vault,
    operation,
    operator_cap,
    clock,
    tx_for_check_value_update,
)
```
- total_usd_value_after = $990,000 (lost $10,000)
- loss = $10,000
- loss_limit = $1,000,000 * 0.001 = $1,000
- **FAILS**: loss ($10,000) > loss_limit ($1,000)

**Expected Result:** Transaction reverts with ERR_EXCEED_LOSS_LIMIT

**Actual Result (if tolerance higher):** If loss_tolerance is set to 100 (1%), loss_limit = $10,000, assertion passes, and theft succeeds.

**Success Condition for Attacker:**
- Operator wallet receives ~$10,000 in CoinA + CoinB
- Vault total_usd_value decreases by $10,000
- All depositors' shares are now worth 1% less
- Operation completes successfully with recorded "loss" within tolerance

**Notes:**
- With default 0.1% tolerance, attacker could steal $1,000 per operation
- Attacker could execute multiple operations per epoch up to tolerance limit
- If admin has configured higher tolerance (e.g., 1-5% for volatile DeFi strategies), theft potential increases proportionally
- No cryptographic or economic complexity - pure position state manipulation

### Citations

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L34-67)
```text
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);

    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );

    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L10-24)
```text
    public struct Position has store, key {
        id: UID,
        pool_id: ID,
        fee_rate: u64,
        type_x: TypeName,
        type_y: TypeName,
        tick_lower_index: I32,
        tick_upper_index: I32,
        liquidity: u128,
        fee_growth_inside_x_last: u128,
        fee_growth_inside_y_last: u128,
        owed_coin_x: u64,
        owed_coin_y: u64,
        reward_infos: vector<PositionRewardInfo>,
    }
```

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L259-265)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L345-348)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };
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

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L168-193)
```markdown
```move
/// Removes liquidity from the specified position in the given pool.
///
/// # Parameters
/// - `pool`: A mutable reference to the pool from which liquidity will be removed.
/// - `position`: A mutable reference to the position from which liquidity will be removed.
/// - `liquidity`: The amount of liquidity to be removed.
/// - `min_amount_x`: The minimum amount of coin X to be removed.
/// - `min_amount_y`: The minimum amount of coin Y to be removed.
/// - `clock`: A reference to the clock object to track time.
/// - `version`: A reference to the version object to ensure compatibility.
/// - `ctx`: A mutable reference to the transaction context.
///
/// # Returns
/// A tuple containing the coins of type X and Y that were removed.
 public fun remove_liquidity<X, Y>(
    pool: &mut Pool<X, Y>, 
    position: &mut Position, 
    liquidity: u128, 
    min_amount_x: u64, 
    min_amount_y: u64, 
    clock: &Clock, 
    version: &Version,        
    ctx: &mut TxContext
    ): (Coin<X>, Coin<Y>) {}
```
```
