### Title
Denial of Service via Pool Price Manipulation During Momentum Position Value Updates

### Summary
An attacker can manipulate the Momentum pool price to exceed the configured slippage threshold during vault operations, causing `update_momentum_position_value` to fail with `ERR_INVALID_POOL_PRICE`. This prevents the vault from completing the three-step operation flow, leaving it permanently stuck in `VAULT_DURING_OPERATION_STATUS` until admin intervention. During this state, all user deposits and withdrawals are blocked, causing a complete denial of service.

### Finding Description

The vulnerability exists in the `get_position_value` function which enforces a runtime slippage check between the Momentum pool's spot price and the oracle price: [1](#0-0) 

The pool price is read directly from the pool at transaction execution time: [2](#0-1) 

The default slippage tolerance is only 1%: [3](#0-2) 

**Attack Execution Path:**

1. Vault operator calls `start_op_with_bag`, setting vault status to `VAULT_DURING_OPERATION_STATUS`: [4](#0-3) 

2. Operator completes operations and calls `end_op_with_bag`, enabling value updates: [5](#0-4) 

3. **Attack Point**: Before the operator can call `update_momentum_position_value`, the attacker executes large trades on the Momentum pool to push the spot price more than 1% away from the oracle price.

4. When the operator calls `update_momentum_position_value`, the assertion fails, aborting the transaction before `finish_update_asset_value` can mark the asset as updated.

5. The operator cannot complete `end_op_value_update_with_bag` because the value update check will fail: [6](#0-5) 

6. The vault remains stuck in `VAULT_DURING_OPERATION_STATUS` with no direct recovery mechanism.

**Why Protections Fail:**

The admin cannot force the vault status back to normal. The `set_enabled` function explicitly prevents status changes during operations: [7](#0-6) 

### Impact Explanation

**Primary Impact - Complete Vault DoS:**

While the vault is stuck in `VAULT_DURING_OPERATION_STATUS`, all user operations are blocked:

- Users cannot request new deposits because `request_deposit` requires `VAULT_NORMAL_STATUS`: [8](#0-7) 

- Users cannot request new withdrawals because `request_withdraw` requires `VAULT_NORMAL_STATUS`: [8](#0-7) 

**Secondary Impact - Security Degradation:**

The only recovery mechanism requires the admin to permanently increase the slippage tolerance: [9](#0-8) 

This permanently weakens the protocol's protection against sandwich attacks and price manipulation in future operations.

**Affected Parties:**
- All vault users unable to deposit or withdraw
- Protocol reputation damage
- Admin forced to weaken security parameters

### Likelihood Explanation

**Attacker Capabilities:**

The attacker needs:
1. Sufficient capital to move the Momentum pool price by >1% from the oracle price
2. Ability to monitor on-chain operations to detect when vault enters `DURING_OPERATION_STATUS`
3. Ability to execute transactions with timing (MEV capabilities increase success rate)

**Attack Complexity:**

The attack is moderately complex:
- Requires monitoring vault state transitions
- Requires executing large trades on the Momentum pool
- Cost increases with pool liquidity depth
- Natural arbitrage may counter the manipulation

**Economic Feasibility:**

The attack becomes economically viable when:
- The pool has lower liquidity (easier to manipulate)
- The attacker can profit from:
  - Shorting vault-related tokens during the DoS period
  - Arbitraging the price manipulation itself
  - Causing reputational damage to competitors

**Attack Sustainability:**

The attacker can maintain the DoS by continuously trading to keep the pool price outside bounds, though this becomes increasingly expensive as arbitrageurs respond.

### Recommendation

**Immediate Mitigations:**

1. **Add Emergency Admin Override Function**

Add a new admin function in `vault_manage.move` to force status reset:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

2. **Implement Operation Timeout**

Add timestamp tracking to operations and allow automatic reversion after a timeout period (e.g., 5 minutes).

3. **Use Time-Weighted Average Price (TWAP)**

Replace the spot price check with a TWAP calculation over a window (e.g., 30 seconds) to make manipulation more expensive and less effective.

4. **Add Circuit Breaker**

If the slippage check fails multiple consecutive times, allow the operator to bypass it with increased scrutiny or reduced position size limits.

**Long-term Improvements:**

1. Add comprehensive monitoring for vault stuck states
2. Implement automated alerts when operations exceed expected duration
3. Add retry logic with exponential backoff in the operator's off-chain systems
4. Consider using Chainlink or other manipulation-resistant oracles for critical price checks

### Proof of Concept

**Initial State:**
- Vault is operational with a Momentum position containing CoinA/CoinB
- Default slippage is 100 (1%)
- Oracle price for CoinA/CoinB is stable
- Momentum pool has moderate liquidity

**Attack Steps:**

1. **Setup**: Attacker monitors for `OperationStarted` event indicating vault entering `DURING_OPERATION_STATUS`

2. **Wait**: Attacker waits for the `OperationEnded` event indicating `end_op_with_bag` has been called

3. **Execute Price Manipulation**: 
   - Attacker executes large swap on Momentum pool: CoinA → CoinB
   - This moves the pool's sqrt_price by >1% from the oracle price
   - Example: If oracle price is 1.0, attacker moves pool price to 1.015 or 0.985

4. **Operator Attempts Update**:
   - Operator calls `update_momentum_position_value`
   - `get_position_value` reads the manipulated pool price
   - Slippage check: `(1.015 - 1.0) / 1.0 * 100% = 1.5%` > 1% threshold
   - Transaction aborts with `ERR_INVALID_POOL_PRICE`

5. **Vault Stuck**:
   - Operator cannot complete `end_op_value_update_with_bag`
   - Vault remains in `VAULT_DURING_OPERATION_STATUS`
   - User calls to `deposit` or `withdraw` fail with `ERR_VAULT_NOT_NORMAL`

**Expected Result**: Operation completes successfully and vault returns to NORMAL status

**Actual Result**: Vault stuck in DURING_OPERATION status, all user operations blocked until admin increases slippage tolerance via `set_dex_slippage` and operator retries

**Success Condition**: Vault remains stuck until admin intervention, proving the DoS vulnerability

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L73-73)
```text
    let sqrt_price = pool.sqrt_price();
```

**File:** volo-vault/sources/oracle.move (L14-14)
```text
const DEFAULT_DEX_SLIPPAGE: u256 = 100; // 1%
```

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

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L649-650)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/manage.move (L136-138)
```text
public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}
```
