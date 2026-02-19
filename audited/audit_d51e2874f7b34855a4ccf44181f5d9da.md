### Title
Asset Type Mismatch in Momentum Position Valuation Allows Incorrect USD Value Storage

### Summary
The `update_momentum_position_value` function is publicly callable without access controls and fails to validate that the provided pool's coin types match the position's actual coin types. An attacker can provide a pool with different coin types, causing the position's value to be calculated using wrong token prices and storing incorrect USD values in the vault's accounting system.

### Finding Description

The vulnerability exists in the `update_momentum_position_value` function which is declared as `public fun`, making it callable by any user via Programmable Transaction Blocks (PTBs) in Sui without requiring operator capabilities or any authorization. [1](#0-0) 

The function retrieves a MomentumPosition from the vault using the `asset_type` string, then calls `get_position_value` to calculate its USD value. The critical flaw is in how `get_position_value` extracts coin types: [2](#0-1) 

The function extracts types from the **pool's generic parameters** (`CoinA` and `CoinB`), not from the position itself. The MomentumPosition struct stores the actual coin types in its `type_x` and `type_y` fields: [3](#0-2) 

However, these fields have no public getter functions, and more critically, **there is no validation** anywhere in the code that the pool's generic types match the position's stored types. The function also never validates that the pool's ID matches the position's `pool_id` field.

The extracted types are then used to fetch oracle prices and calculate the position value: [4](#0-3) 

The pool price slippage check at lines 55-58 only validates that the pool's internal price is consistent with oracle prices **for that specific pool's tokens**. It does NOT validate that the pool matches the position.

Finally, the incorrect USD value is stored in the vault through `finish_update_asset_value`: [5](#0-4) 

This function is `public(package)` and performs no authorization checks beyond vault status, allowing the momentum adaptor to update values freely.

### Impact Explanation

This vulnerability has **HIGH severity** impact:

1. **Direct Fund Impact**: The vault's `total_usd_value` becomes incorrect, which directly affects share price calculations. Users depositing or withdrawing receive wrong amounts of shares or principal based on manipulated valuations.

2. **Vault Accounting Corruption**: Violates the critical invariant "total_usd_value correctness" from the audit requirements. The vault's `assets_value` table stores fundamentally wrong USD values for momentum positions.

3. **Systematic Manipulation**: An attacker can repeatedly call this function to maintain artificially high or low valuations, enabling:
   - Depositing when value is artificially low to receive more shares
   - Withdrawing when value is artificially high to extract more principal
   - Preventing legitimate loss tolerance checks from triggering during operations

4. **All Users Affected**: Since share prices are calculated from total vault value, all depositors in the vault are impacted by incorrect position valuations.

The impact is concrete and measurable - incorrect USD values directly translate to wrong share prices, enabling value extraction from the vault.

### Likelihood Explanation

The likelihood of exploitation is **HIGH**:

1. **Reachable Entry Point**: The function is `public fun`, meaning any user can call it via a Programmable Transaction Block without any special permissions or capabilities. No OperatorCap or access control is required.

2. **Feasible Preconditions**: 
   - Attacker only needs knowledge of which momentum positions exist in the vault (observable on-chain)
   - Attacker needs access to a different momentum pool with similar token pairs that would pass the slippage validation
   - Both requirements are easily met in production environments

3. **Execution Practicality**: Attack sequence is straightforward:
   - Identify target vault with momentum position for TokenA/TokenB
   - Find or create pool for TokenC/TokenD where prices are similar enough to pass slippage check
   - Construct PTB calling `update_momentum_position_value` with mismatched pool
   - No complex timing, front-running, or state manipulation required

4. **Economic Rationality**: 
   - Attack cost is minimal (just transaction fees)
   - No capital lockup required
   - Can be repeated to maintain incorrect valuations
   - Profit potential through share price manipulation makes this economically viable

5. **Detection Constraints**: The attack leaves no obvious on-chain evidence of malicious intent - the transaction appears as a normal value update call.

### Recommendation

Implement strict validation to ensure pool and position compatibility:

**Primary Fix - Add Pool ID Validation**:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Add validation: pool ID must match position's pool_id
    assert!(
        object::id(pool) == position.pool_id(),
        ERR_POOL_MISMATCH
    );
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**Alternative Fix - Add Access Control**:
If pool_id getter is not available, restrict the function to operator-only access:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    _cap: &OperatorCap,  // Add operator capability requirement
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
)
```

**Testing Requirements**:
- Add test case attempting to update position with wrong pool - should fail
- Add test case with correct pool - should succeed
- Verify total_usd_value remains correct after attempted manipulation

### Proof of Concept

**Initial State**:
- Vault has MomentumPosition P1 created for USDC/SUI pool (pool_id = 0x123)
- Position has liquidity L, stored with type_x = USDC, type_y = SUI
- Position is stored in vault with asset_type = "MomentumPosition_0"

**Attack Sequence**:

1. Attacker identifies position P1 in vault for USDC/SUI
2. Attacker locates or creates momentum pool P2 for USDT/SUI (pool_id = 0x456)
3. Attacker constructs PTB with transaction:
```
update_momentum_position_value<SUI, USDT, SUI>(
    vault,           // shared object reference
    oracle_config,   // shared object reference  
    clock,           // shared object reference
    "MomentumPosition_0",  // asset_type string
    pool_P2          // USDT/SUI pool reference (WRONG POOL)
)
```

4. Function executes:
   - Retrieves correct position P1 (USDC/SUI position)
   - NO validation that pool_P2 matches P1's pool_id
   - Extracts types from pool_P2: CoinA = USDT, CoinB = SUI
   - Calculates liquidity amounts using pool_P2's sqrt_price
   - Fetches oracle prices for USDT (wrong - should be USDC) and SUI
   - Calculates USD value using USDT price instead of USDC price
   - Stores incorrect USD value in vault.assets_value["MomentumPosition_0"]

**Expected Result**: Transaction should fail with pool mismatch error

**Actual Result**: Transaction succeeds, storing incorrect USD value. If USDC = $1.00 and USDT = $0.98, the position is undervalued by 2% on the USDC component, directly affecting share price calculations and enabling value extraction.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L42-43)
```text
    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-66)
```text
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
