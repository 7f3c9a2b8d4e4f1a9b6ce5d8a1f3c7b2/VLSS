### Title
Cetus Adaptor Lacks Protocol Version Compatibility Checks Leading to Incorrect Position Valuations

### Summary
The Cetus adaptor in `volo-vault/sources/adaptors/cetus_adaptor.move` has no mechanism to verify compatibility with the Cetus protocol version it interacts with. If Cetus upgrades their protocol and changes the semantics of `get_position_amounts()` or `current_sqrt_price()` methods (e.g., decimal scaling changes, fee handling modifications), the Volo adaptor will continue calculating position values using outdated assumptions, leading to systematically incorrect valuations that affect share ratios, deposits, and withdrawals.

### Finding Description

The `calculate_cetus_position_value()` function directly calls Cetus protocol methods without any version or compatibility validation: [1](#0-0) 

The adaptor depends on a specific Cetus version pinned in the dependency configuration: [2](#0-1) 

**Root Cause:** The adaptor makes implicit assumptions about Cetus protocol behavior (amount scaling, decimal handling, fee inclusion) without verifying these assumptions remain valid. Unlike the vault and oracle modules which implement version checking: [3](#0-2) [4](#0-3) 

The Cetus adaptor has no such mechanism.

**Why Existing Protections Fail:**

1. **Slippage Check Insufficient:** The pool price vs oracle price comparison only validates relative pricing, not amount calculation correctness: [5](#0-4) 

This check would not catch if `get_position_amounts()` returns values with different decimal scaling or fee treatment.

2. **Loss Tolerance Limited:** The epoch-based loss tolerance only triggers on detected losses and has a threshold: [6](#0-5) 

It misses systematic overvaluations and subtle errors below the tolerance threshold.

**Execution Path:**
1. Operator initiates operation via `start_op_with_bag()` borrowing Cetus positions
2. After manipulation, `end_op_value_update_with_bag()` requires value updates
3. Operator calls `update_cetus_position_value()` which invokes `calculate_cetus_position_value()`
4. Adaptor calls Cetus methods with potentially changed semantics
5. Incorrect values propagate to `finish_update_asset_value()` and `get_total_usd_value()`
6. Wrong total USD value affects share ratio calculations for all subsequent deposits/withdrawals [7](#0-6) [8](#0-7) 

### Impact Explanation

**Direct Fund Impact:**
- If Cetus changes `get_position_amounts()` decimal scaling (e.g., from 9 to 18 decimals), positions could be overvalued by 10^9, making share ratios artificially low
- Users depositing during this period receive far fewer shares than deserved
- Users withdrawing receive far more principal than deserved, draining vault funds
- Conversely, undervaluation causes opposite harm

**Affected Parties:**
- All vault depositors/withdrawers during the incompatibility window
- The vault's solvency if systematic overwithdrawals occur
- Protocol reputation and user trust

**Quantified Impact:**
For a decimal scaling error (9→18 decimals):
- $1M Cetus position incorrectly valued at $1B
- Share ratio drops 1000x
- New depositor with $1000 receives 1000x fewer shares
- Existing withdrawer with 1000 shares receives $1M instead of $1000

**Severity Justification:** HIGH - Direct fund loss, affects core accounting invariants (total_usd_value correctness, share mint/burn consistency), no user error required.

### Likelihood Explanation

**Attacker Capabilities:** Not applicable - this is a protocol integration risk, not an active attack. Normal operations during a compatibility window cause the issue.

**Preconditions:**
1. Cetus performs protocol upgrade changing method semantics (e.g., decimal scaling, fee calculation, tick math)
2. Volo has not yet upgraded their adaptor to match
3. Vault operations occur using the stale adaptor

**Feasibility:**
- DeFi protocols regularly upgrade (bug fixes, optimizations, new features)
- Semantic changes are realistic (Cetus v1.48.4 → v2.x could change amount normalization)
- Coordination delays between Cetus upgrade and Volo adaptor update are expected
- In Sui Move, package upgrades can change implementations while maintaining type compatibility

**Operational Constraints:**
- Requires actual Cetus upgrade with behavioral changes
- Window exists between Cetus upgrade and Volo adaptor update
- Detection may be delayed if changes are subtle

**Probability Assessment:** MEDIUM - Cetus upgrades are probable, breaking changes possible, coordination delays realistic, but requires specific circumstances to align.

### Recommendation

**1. Implement Adaptor Version Tracking:**

Add version constants and checks to `cetus_adaptor.move`:
```move
const CETUS_ADAPTOR_VERSION: u64 = 1;
const COMPATIBLE_CETUS_PACKAGE_VERSION: vector<u8> = b"mainnet-v1.48.4";
```

**2. Add Protocol Compatibility Validation:**

Before calling Cetus methods, validate compatibility:
- Store expected Cetus package address/version in vault configuration
- Check Cetus objects originate from compatible package version
- Assert adaptor logic matches current Cetus semantics

**3. Add Sanity Bounds:**

Validate returned amounts are within reasonable bounds:
- Check amounts don't exceed position's max theoretical value
- Validate price calculations against historical ranges
- Add secondary oracle price cross-validation

**4. Implement Graceful Degradation:**

If compatibility cannot be verified:
- Prevent operations using uncertain valuations
- Emit events warning of potential incompatibility
- Require admin intervention to update or freeze affected assets

**5. Test Cases:**

Add regression tests simulating:
- Cetus method return value scaling changes
- Fee inclusion/exclusion changes
- Decimal precision modifications
- Cross-version compatibility validation

### Proof of Concept

**Initial State:**
- Vault has Cetus CLMM position worth 1,000 SUI (1000e9 native units)
- Cetus v1.48.4: `get_position_amounts()` returns amounts in native decimals
- Adaptor calculates: 1000e9 units × $3 oracle price / 1e9 = $3,000 USD value

**Cetus Upgrade Event:**
- Cetus upgrades to v2.0.0 
- `get_position_amounts()` now returns amounts normalized to 18 decimals for consistency
- Same position now returns: 1000e18 units

**Exploitation Sequence:**
1. Operator calls `start_op_with_bag()` borrowing Cetus position
2. Operator performs normal rebalancing 
3. Operator calls `end_op_with_bag()` returning position
4. Operator calls `update_cetus_position_value()` to update valuation
5. Stale adaptor receives 1000e18 from new Cetus method
6. Adaptor calculates: 1000e18 units × $3 / 1e9 = $3,000,000,000 USD (1000x overvalued)
7. `get_total_usd_value()` reflects massively inflated value
8. Share ratio drops to 1/1000 of correct value
9. User deposits $10,000, receives only 10 shares instead of 10,000 shares
10. Another user withdraws 10,000 shares, receives $10,000,000 instead of $10,000

**Success Condition:**
- Position valuation is systematically incorrect by orders of magnitude
- Share ratios become completely detached from actual vault value
- Fund distribution becomes unfair or vault becomes insolvent

**Notes:**
This vulnerability is inherent to the adaptor pattern when integrating with upgradeable external protocols. The issue is exacerbated by:
- Sui Move's package upgrade model allowing implementation changes
- Lack of version metadata in Cetus pool/position objects
- No compatibility verification layer between protocols
- Silent failures (wrong values) rather than loud failures (transaction reverts)

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L33-75)
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

    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18

    // pool price = price_a / price_b (not consider decimals)
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
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

**File:** volo-vault/Move.toml (L25-31)
```text
[dependencies.CetusClmm]
git    = "https://github.com/CetusProtocol/cetus-clmm-interface.git"
subdir = "sui/cetus_clmm"
rev    = "mainnet-v1.48.4"
# rev = "mainnet-v1.25.0"
# addr     = "0xc6faf3703b0e8ba9ed06b7851134bbbe7565eb35ff823fd78432baa4cbeaa12e"
override = true
```

**File:** volo-vault/sources/volo_vault.move (L21-21)
```text
const VERSION: u64 = 1;
```

**File:** volo-vault/sources/volo_vault.move (L463-469)
```text

public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
