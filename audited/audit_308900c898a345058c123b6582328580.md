### Title
Generic Type Confusion in Cetus Position Valuation Allows Incorrect Asset Pricing or Denial of Service

### Summary
The `update_cetus_position_value()` function accepts generic type parameters `CoinA` and `CoinB` that are used to type the pool and fetch oracle prices, but the retrieved `CetusPosition` has no type parameters. This allows anyone to call the function with a mismatched pool or wrong coin types, causing either runtime failures (DoS) or incorrect asset valuations that corrupt the vault's total value calculations.

### Finding Description

The root cause is a type safety gap between the parameterized mock implementation and the real Cetus integration: [1](#0-0) 

The real Cetus `Position` type is imported without generic parameters, unlike the mock version which correctly includes `<phantom CoinTypeA, phantom CoinTypeB>`: [2](#0-1) 

In `update_cetus_position_value()`, the function signature accepts generic `CoinA` and `CoinB` parameters: [3](#0-2) 

However, `get_defi_asset()` returns an untyped `CetusPosition`: [4](#0-3) 

The retrieved position is then passed to `calculate_cetus_position_value()` which uses the caller-provided generic types to:
1. Query the pool for position amounts
2. Extract type names for oracle price lookups
3. Calculate USD value [5](#0-4) 

**Critical Flow Gap:**
There is NO verification that:
- The position actually belongs to the provided pool instance
- The `CoinA`/`CoinB` types match the position's actual coin types
- The pool reference corresponds to the pool where the position was created

The function is publicly accessible without operator restrictions: [6](#0-5) 

While `finish_update_asset_value()` has an `assert_enabled()` check, this only prevents updates when the vault is disabled, not type mismatches: [7](#0-6) 

The slippage check provides partial mitigation but doesn't prevent same-coin-type different-pool attacks: [8](#0-7) 

### Impact Explanation

**Concrete Harm:**

1. **Incorrect Valuation Attack**: 
   - Attacker calls with wrong pool instance of same coin types (e.g., 0.05% fee tier instead of 0.3% fee tier)
   - If `pool.get_position_amounts(position_id)` returns `(0, 0)` for non-existent positions, the position is valued at $0
   - Vault's `total_usd_value` becomes incorrect, affecting share price calculations
   - Users can deposit at artificially low share prices or withdraw at artificially high prices
   - Direct fund loss through mispriced deposits/withdrawals

2. **Denial of Service**:
   - If Cetus protocol aborts when querying non-existent positions, the transaction fails
   - Value updates for that asset become permanently blocked
   - Vault operations requiring updated valuations cannot complete
   - `end_op_value_update_with_bag()` depends on correct value updates

3. **Wrong Coin Type Pricing**:
   - Attacker provides different coin types (e.g., `USDT` instead of `SUI`)
   - Oracle prices fetched for wrong coins
   - While slippage check provides some protection, edge cases exist where similar price ratios could pass
   - Results in persistent incorrect valuations

**Affected Parties:**
- All vault depositors/withdrawers (mispriced shares)
- Protocol solvency (incorrect asset accounting)
- Operators (DoS prevents normal operations)

**Severity Justification:**
High severity due to:
- Public function accessible by any transaction
- Direct fund impact through share price manipulation
- No access control beyond vault enabled status
- Affects critical invariant: total_usd_value correctness

### Likelihood Explanation

**Attacker Capabilities:**
- Any unprivileged user can call the public function
- Vault is a shared object, accessible in any transaction
- Cetus pools are shared objects, attacker can reference any pool
- Only needs to know: correct `PrincipalCoinType`, correct `asset_type` string, and a pool reference

**Attack Complexity:**
Low to medium:
- **Easy Attack**: Call with different pool instance of same coin pair (different fee tier exists in Cetus)
- **Moderate Attack**: Call with coin types having similar price ratios to bypass slippage check

**Feasibility Conditions:**
- Vault must have at least one Cetus position stored
- Multiple pools for same coin pair must exist (standard in Cetus - 0.01%, 0.05%, 0.3%, 1% fee tiers)
- Attacker can obtain pool references (public shared objects)
- No operator authentication required

**Detection/Constraints:**
- Slippage check limits wrong-coin-type attacks but doesn't prevent wrong-pool-instance attacks
- No transaction logs distinguish legitimate vs malicious update calls
- Value updates can be called anytime vault is enabled

**Probability:**
High - The attack vector is straightforward:
1. Observe vault has position in Pool A (fee tier 0.3%)
2. Call `update_cetus_position_value()` with Pool B (fee tier 0.05%) of same coin types
3. Position doesn't exist in Pool B → zero valuation or DoS
4. Repeat to maintain incorrect valuations

### Recommendation

**Immediate Fix:**
Store pool type information alongside the position and enforce matching:

```move
// In vault storage, store position metadata
public struct CetusPositionMetadata has store {
    pool_id: ID,
    coin_type_a: TypeName,
    coin_type_b: TypeName,
}

// Modified update function with verification
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let metadata = vault.get_position_metadata(asset_type);
    
    // Verify pool ID matches
    assert!(object::id(pool) == metadata.pool_id, ERR_POOL_MISMATCH);
    
    // Verify coin types match
    assert!(type_name::get<CoinA>() == metadata.coin_type_a, ERR_COIN_TYPE_MISMATCH);
    assert!(type_name::get<CoinB>() == metadata.coin_type_b, ERR_COIN_TYPE_MISMATCH);
    
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**Additional Checks:**
1. Store pool ID when adding Cetus position via `add_new_defi_asset()`
2. Add error codes: `ERR_POOL_MISMATCH`, `ERR_COIN_TYPE_MISMATCH`
3. Consider making function `public(package)` and requiring operator cap

**Test Cases:**
1. Test calling with wrong pool instance (different fee tier)
2. Test calling with wrong coin types
3. Test calling with correct parameters (should succeed)
4. Test that metadata is correctly stored and verified

### Proof of Concept

**Initial State:**
- Vault has `CetusPosition` X stored for Pool1<SUI, USDC> (0.3% fee tier)
- Position X has liquidity: 100 SUI, 200 USDC
- Correct valuation: ~$400 (assuming SUI=$2, USDC=$1)

**Attack Steps:**

1. Attacker obtains reference to Pool2<SUI, USDC> (0.05% fee tier - different pool instance)

2. Attacker calls:
```move
cetus_adaptor::update_cetus_position_value<PrincipalCoinType, SUI, USDC>(
    &mut vault,
    &config,
    &clock,
    "CetusPosition::0",  // asset_type for Position X
    &mut pool2,           // Wrong pool instance
)
```

3. Function executes:
   - Retrieves Position X from vault ✓
   - Calls `pool2.get_position_amounts(position_x_id)`
   - Position X doesn't exist in Pool2
   - Either: Returns (0, 0) OR aborts

**Expected Result:**
Transaction should fail with verification error that pool doesn't match position

**Actual Result:**
- If returns (0, 0): Position valued at $0, vault undervalued by $400
- If aborts: DoS, position value updates blocked indefinitely

**Success Condition:**
Vault's `assets_value["CetusPosition::0"]` changes from correct value to $0, or transaction aborts causing DoS on value updates.

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L4-4)
```text
use cetusclmm::position::Position as CetusPosition;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-25)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L33-52)
```text
public fun calculate_cetus_position_value<CoinTypeA, CoinTypeB>(
    pool: &mut CetusPool<CoinTypeA, CoinTypeB>,
    position: &CetusPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let position_id = object::id(position);

    let (amount_a, amount_b) = pool.get_position_amounts(position_id);

    let type_name_a = into_string(get<CoinTypeA>());
    let type_name_b = into_string(get<CoinTypeB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L61-66)
```text
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/tests/mock/mock_cetus.move (L11-17)
```text
public struct MockCetusPosition<phantom CoinTypeA, phantom CoinTypeB> has key, store {
    id: UID,
    coin_type_a: TypeName,
    coin_type_b: TypeName,
    token_a_amount: u64,
    token_b_amount: u64,
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1182)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

```

**File:** volo-vault/sources/volo_vault.move (L1451-1456)
```text
public fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType {
    self.assets.borrow<String, AssetType>(asset_type)
}
```
