# Audit Report

## Title
Vault Operations Can Be Blocked by Strict Price Deviation Check During High Volatility

## Summary
The Momentum and Cetus adaptors enforce a strict 1% price deviation check between DEX pool prices and oracle prices during vault value updates. During high market volatility, legitimate price deviations exceeding this tolerance cause assertion failures that leave the vault stuck in DURING_OPERATION_STATUS, preventing all user deposits and withdrawals until prices realign or the configuration is updated.

## Finding Description

The vault operation flow follows a three-step process. When operators initiate operations, the vault status is set to DURING_OPERATION_STATUS to prevent concurrent user actions [1](#0-0) . The vault only returns to NORMAL_STATUS after successful completion of value updates [2](#0-1) .

During value updates, the Momentum adaptor's `get_position_value()` function enforces a strict price deviation check [3](#0-2) . This assertion calculates the percentage deviation between the DEX pool price and oracle-derived price, requiring it to be less than the configured `dex_slippage` tolerance. The Cetus adaptor contains an identical check [4](#0-3) .

The default slippage tolerance is set to only 1% (100 basis points) [5](#0-4)  and is initialized to this value [6](#0-5) .

When this assertion fails during a value update, the entire transaction reverts, preventing the completion of `end_op_value_update_with_bag()` which would return the vault to NORMAL_STATUS. The vault remains stuck in DURING_OPERATION_STATUS.

While in DURING_OPERATION_STATUS, both `request_deposit` and `request_withdraw` operations are blocked by the `assert_normal()` check [7](#0-6) [8](#0-7) . This function requires the vault status to be VAULT_NORMAL_STATUS [9](#0-8) , effectively blocking all user access.

The `set_status` function that could reset the vault status is package-private [10](#0-9) , meaning admins cannot directly call it to recover from this state. Additionally, the `set_enabled` function explicitly prevents being called when the vault is in DURING_OPERATION_STATUS [11](#0-10) , removing another potential recovery path.

## Impact Explanation

**Operational Denial of Service (Medium Severity)**

The vulnerability causes a complete operational DoS for all vault users:
- Users cannot submit new deposit requests due to the `assert_normal()` check
- Users cannot submit new withdrawal requests due to the same check
- The DoS affects all vault participants simultaneously as vault status is global
- The condition persists until market conditions change or admin updates configuration

**Why Medium and not High:**
- No direct fund loss occurs - user assets remain safe
- The condition is temporary and self-resolving when prices realign
- Admins can update the slippage tolerance via `set_dex_slippage` [12](#0-11)  to allow operations to proceed

**Why Medium and not Low:**
- Blocks critical user operations (deposits/withdrawals) during the most critical times (high volatility)
- Affects protocol availability and user confidence
- No emergency recovery mechanism exists - admins cannot directly reset vault status
- The 1% default tolerance is unrealistically strict for crypto markets, making this likely to occur

## Likelihood Explanation

**High Likelihood**

This vulnerability will manifest during normal protocol operations:

1. **Reachable Entry Point**: Operators routinely call value update functions as part of standard vault management
2. **Feasible Preconditions**: 
   - Market volatility causing >1% price deviation between DEX pools and oracles
   - No attacker required - natural market conditions trigger the issue
3. **Common Occurrence**: Cryptocurrency markets regularly experience >1% price movements during:
   - Flash crashes
   - Large trades
   - Liquidation cascades
   - Major news events
4. **Oracle Delay**: Oracle prices can lag up to 1 minute behind real-time DEX prices [13](#0-12) , creating natural windows where deviation exceeds 1%

The vulnerability affects routine operations, not edge cases, and will occur whenever natural market volatility causes legitimate price deviations to exceed the overly strict 1% tolerance.

## Recommendation

Implement multiple safeguards to prevent and recover from this DoS condition:

1. **Increase Default Tolerance**: Raise `DEFAULT_DEX_SLIPPAGE` from 100 (1%) to a more reasonable value like 300-500 (3-5%) to account for normal crypto market volatility and oracle lag.

2. **Add Emergency Recovery Function**: Implement an admin-callable emergency function that can reset vault status from DURING_OPERATION_STATUS to NORMAL_STATUS with appropriate safeguards:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Only allow if vault has been stuck for sufficient time
    // and no active borrowed assets
    vault.set_status(VAULT_NORMAL_STATUS);
}
```

3. **Make Tolerance Configurable Per Asset**: Allow different tolerance levels for different asset pairs based on their typical volatility characteristics.

## Proof of Concept

A proof of concept would demonstrate:
1. Initialize a vault with Momentum/Cetus position
2. Start an operation that sets DURING_OPERATION_STATUS
3. Simulate market conditions where pool price deviates >1% from oracle price
4. Attempt value update - transaction reverts
5. Vault remains in DURING_OPERATION_STATUS
6. User attempts to deposit/withdraw - both fail with ERR_VAULT_NOT_NORMAL

The vulnerability is confirmed by the strict assertion in the adaptors combined with the lack of emergency recovery mechanisms when the vault is stuck in operation status.

### Citations

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L63-66)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
```

**File:** volo-vault/sources/oracle.move (L14-14)
```text
const DEFAULT_DEX_SLIPPAGE: u256 = 100; // 1%
```

**File:** volo-vault/sources/oracle.move (L90-90)
```text
        dex_slippage: DEFAULT_DEX_SLIPPAGE,
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L533-533)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/manage.move (L136-138)
```text
public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}
```
