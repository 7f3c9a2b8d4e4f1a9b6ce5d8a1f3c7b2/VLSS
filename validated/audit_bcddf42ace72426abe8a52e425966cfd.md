### Title
Missing Sanity Checks in Oracle and Vault Configuration Functions Enable Protocol DoS and Security Bypass

### Summary
Multiple admin configuration functions in the Volo vault system lack sanity checks on critical time-based and slippage parameters, directly analogous to the external vulnerability. Setting `update_interval` to 0 causes complete oracle failure and protocol-wide DoS, while setting locking times to 0 bypasses security mechanisms, and incorrect `dex_slippage` values either block all DEX operations or allow manipulated prices.

### Finding Description

The external vulnerability describes missing sanity checks on time/duration parameters in admin-controlled functions. Volo contains the same vulnerability class in three critical configuration setters:

**Vulnerability 1: Oracle Update Interval (Highest Severity)**

The `set_update_interval` function accepts any u64 value without validation: [1](#0-0) 

This parameter is used to validate price staleness in critical oracle functions: [2](#0-1) [3](#0-2) 

If `update_interval` is set to 0, the condition `price_info.last_updated.diff(now) < 0` always fails, causing all `get_asset_price()` calls to revert with `ERR_PRICE_NOT_UPDATED`. This breaks all vault operations (deposits, withdrawals, value updates) that depend on oracle prices.

**Vulnerability 2: Locking Time Parameters**

The locking time setters have no validation: [4](#0-3) [5](#0-4) 

Test code confirms zero values are accepted without checks: [6](#0-5) 

These parameters are used in security-critical time checks: [7](#0-6) [8](#0-7) 

Setting `locking_time_for_cancel_request` to 0 allows immediate request cancellation, bypassing the cooldown mechanism. Setting `locking_time_for_withdraw` to 0 removes the deposit-to-withdraw delay. Setting either to extremely large values (e.g., `u64::MAX`) effectively locks funds forever.

**Vulnerability 3: DEX Slippage Parameter**

The `set_dex_slippage` function lacks bounds checking: [9](#0-8) 

This parameter validates pool prices against oracle prices in DEX adaptors: [10](#0-9) [11](#0-10) 

Setting `dex_slippage` to 0 causes all DEX position value updates to fail (any price deviation is rejected). Setting it to 10,000 or higher effectively disables the check, allowing acceptance of manipulated pool prices.

### Impact Explanation

**Critical Impact - Protocol-Wide DoS:**
If `update_interval` is mistakenly set to 0, all oracle price queries fail immediately. Since vault operations require price updates, this causes complete protocol failure:
- All `execute_deposit` calls fail (cannot calculate shares from USD value)
- All `execute_withdraw` calls fail (cannot calculate principal from shares)  
- All operator value updates fail (cannot price DeFi positions)
- Protocol becomes completely inoperable until admin corrects the value

**High Impact - Security Mechanism Bypass:**
Setting locking times to 0 removes designed security delays:
- Users can cancel deposit/withdraw requests immediately, potentially gaming price movements
- Users can withdraw immediately after deposit, bypassing the 12-hour lock intended to prevent flash-loan style attacks
- No minimum time-lock enforcement exists

**High Impact - Price Manipulation or DEX Operation DoS:**
Incorrect `dex_slippage` values either:
- Block all Cetus and Momentum position operations (if set to 0)
- Allow acceptance of heavily manipulated pool prices (if set too high)

### Likelihood Explanation

**Medium-High Likelihood** - While these are admin-controlled functions, operational mistakes are realistic:

1. **No validation exists** - Admin can set any value including 0, confirmed by test usage
2. **Unit confusion risks** - Admin might confuse seconds/milliseconds (e.g., setting 60 instead of 60,000 for 1 minute)
3. **No rollback protection** - Once set incorrectly, protocol suffers immediate impact
4. **Multiple attack vectors** - Three separate parameters with the same vulnerability class
5. **Admin functions exposed** through the manage module: [12](#0-11) [13](#0-12) [14](#0-13) 

### Recommendation

Add sanity checks to all configuration setters:

**For `set_update_interval`:**
```move
public(package) fun set_update_interval(config: &mut OracleConfig, update_interval: u64) {
    config.check_version();
    // Minimum 1 second, maximum 10 minutes
    assert!(update_interval >= 1_000 && update_interval <= 600_000, ERR_INVALID_UPDATE_INTERVAL);
    config.update_interval = update_interval;
    emit(UpdateIntervalSet { update_interval })
}
```

**For locking time setters:**
```move
public(package) fun set_locking_time_for_cancel_request(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    // Minimum 1 minute, maximum 7 days
    assert!(locking_time >= 60_000 && locking_time <= 7 * 24 * 3600_000, ERR_INVALID_LOCKING_TIME);
    self.locking_time_for_cancel_request = locking_time;
    // ... emit event
}

public(package) fun set_locking_time_for_withdraw(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    // Minimum 1 hour, maximum 30 days
    assert!(locking_time >= 3600_000 && locking_time <= 30 * 24 * 3600_000, ERR_INVALID_LOCKING_TIME);
    self.locking_time_for_withdraw = locking_time;
    // ... emit event
}
```

**For `set_dex_slippage`:**
```move
public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();
    // Maximum 50% slippage (5000 basis points)
    assert!(dex_slippage > 0 && dex_slippage <= 5000, ERR_INVALID_SLIPPAGE);
    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
```

### Proof of Concept

**Scenario 1: Protocol-Wide DoS via update_interval**

1. Admin calls `vault_manage::set_update_interval(&admin_cap, &mut oracle_config, 0)`
2. Any subsequent call to `get_asset_price(config, clock, asset_type)` fails:
   - Line 135 evaluates: `price_info.last_updated.diff(now) < 0` → always false
   - Function aborts with `ERR_PRICE_NOT_UPDATED`
3. All vault operations fail:
   - `execute_deposit()` cannot calculate USD value → aborts
   - `execute_withdraw()` cannot calculate principal amount → aborts  
   - Operator value updates for all DeFi positions fail → operations stuck
4. Protocol is completely unusable until admin corrects the value

**Scenario 2: Security Bypass via Zero Locking Times**

1. Admin accidentally calls `vault_manage::set_locking_time_for_cancel_request(&admin_cap, &mut vault, 0)`
2. User submits deposit request at timestamp T
3. User can immediately call `cancel_deposit()` at timestamp T:
   - Line 780-782 check: `request_time + 0 <= T` → passes
   - Cooldown mechanism bypassed
4. User can game price movements by canceling requests instantly without waiting

**Scenario 3: DEX Operation DoS via Zero Slippage**

1. Admin calls `vault_manage::set_dex_slippage(&admin_cap, &mut oracle_config, 0)`  
2. Operator attempts to update Cetus position value
3. Slippage check at line 64-66 always fails:
   - Formula: `(pool_price.diff(oracle_price) * DECIMAL / oracle_price) < (DECIMAL * 0 / SLIPPAGE_BASE)`
   - Right side evaluates to 0, any non-zero price difference causes abort
4. All Cetus and Momentum position value updates fail with `ERR_INVALID_POOL_PRICE`

### Notes

This vulnerability directly mirrors the external report's pattern: admin-controlled configuration functions with missing sanity checks on time-based and threshold parameters. The lack of validation enables both accidental operational mistakes (DoS) and intentional bypass of security mechanisms (time locks). The external report's recommendation to "add sanity checks to make sure that these parameters are set to the correct values" applies identically to Volo's configuration functions.

### Citations

**File:** volo-vault/sources/oracle.move (L110-115)
```text
public(package) fun set_update_interval(config: &mut OracleConfig, update_interval: u64) {
    config.check_version();

    config.update_interval = update_interval;
    emit(UpdateIntervalSet { update_interval })
}
```

**File:** volo-vault/sources/oracle.move (L117-122)
```text
public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();

    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
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

**File:** volo-vault/sources/volo_vault.move (L543-554)
```text
public(package) fun set_locking_time_for_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    self.locking_time_for_withdraw = locking_time;

    emit(LockingTimeForWithdrawChanged {
        vault_id: self.vault_id(),
        locking_time: locking_time,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L556-567)
```text
public(package) fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    self.locking_time_for_cancel_request = locking_time;

    emit(LockingTimeForCancelRequestChanged {
        vault_id: self.vault_id(),
        locking_time: locking_time,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L702-703)
```text
    self.locking_time_for_withdraw + receipt.last_deposit_time() <= clock.timestamp_ms()
}
```

**File:** volo-vault/sources/volo_vault.move (L780-782)
```text
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/tests/init_vault.move (L57-59)
```text
        vault.set_locking_time_for_withdraw(12 * 3600 * 1_000);
        vault.set_locking_time_for_cancel_request(0);
        test_scenario::return_shared(vault);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L62-66)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L54-58)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/manage.move (L66-80)
```text
public fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_cancel_request(locking_time);
}

public fun set_locking_time_for_withdraw<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_withdraw(locking_time);
}
```

**File:** volo-vault/sources/manage.move (L128-134)
```text
public fun set_update_interval(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    update_interval: u64,
) {
    oracle_config.set_update_interval(update_interval);
}
```

**File:** volo-vault/sources/manage.move (L136-138)
```text
public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}
```
