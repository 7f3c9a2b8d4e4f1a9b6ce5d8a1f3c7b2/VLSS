### Title
Missing Validation in Oracle Configuration Setters Enables Protocol-Wide Denial of Service

### Summary
The `set_update_interval` and `set_dex_slippage` functions in the oracle configuration module lack input validation, allowing administrators to accidentally set values that break critical protocol functionality. Setting `update_interval` to zero causes all price fetches to fail, resulting in complete denial of service for deposits, withdrawals, and DeFi operations. This mirrors the external report's vulnerability class where setter functions fail to enforce constraints that are implicitly assumed during instantiation.

### Finding Description

The external report identifies missing validation in setter functions that should enforce the same constraints as during struct instantiation. Volo exhibits the exact same vulnerability pattern in its oracle configuration module.

**Root Cause in Volo:**

In [1](#0-0) , the `OracleConfig` is initialized with safe default values: `update_interval: MAX_UPDATE_INTERVAL` (60,000 milliseconds) and `dex_slippage: DEFAULT_DEX_SLIPPAGE` (100 basis points).

However, the setter functions lack any validation: [2](#0-1) [3](#0-2) 

**Exploit Path - Update Interval DoS:**

1. Admin calls the public entry point: [4](#0-3) 

2. This sets `oracle_config.update_interval = 0` with no validation

3. Any subsequent price fetch fails at the critical assertion: [5](#0-4) 

4. The assertion `price_info.last_updated.diff(now) < config.update_interval` always fails when `update_interval = 0` because no time difference can be less than zero

5. This breaks all operations requiring price data:
   - Deposit execution: [6](#0-5)  calls `update_free_principal_value` at line 839
   - The update function requires price data: [7](#0-6) 
   - Withdraw execution similarly breaks at: [8](#0-7) 

**Exploit Path - DEX Slippage:**

Setting `dex_slippage = 0` breaks pool price validation in DeFi adaptors: [9](#0-8) 

Setting `dex_slippage > 10000` (the SLIPPAGE_BASE constant at [10](#0-9) ) allows accepting pools with >100% price deviation from oracle prices, enabling loss of funds through manipulated pool prices.

### Impact Explanation

**Critical Severity - Protocol-Wide Denial of Service:**

Setting `update_interval = 0` renders the entire vault system inoperable. All user deposit executions, withdrawal executions, and DeFi operations requiring price data will permanently fail until an admin corrects the configuration. Users cannot access their funds, operators cannot perform operations, and the protocol is completely frozen.

**High Severity - Fund Loss via Excessive Slippage:**

Setting `dex_slippage` to values exceeding 10,000 allows the protocol to accept DEX pool prices that deviate by more than 100% from oracle prices. This enables attackers to manipulate pool prices through flash loans or large trades, then trigger vault operations that use the manipulated prices, resulting in loss of vault funds.

### Likelihood Explanation

**Realistic Admin Configuration Error:**

This is not a compromised admin scenario but a realistic configuration mistake. An administrator might:
- Misunderstand that `update_interval = 0` means "no tolerance" rather than "no limit"
- Set it to zero during testing and forget to restore it
- Make a typo when entering millisecond values

The external report from OtterSec validates this likelihood assessment - missing setter validation is considered a legitimate vulnerability even when only admins can call the function, because it protects against human error in protocol configuration.

The entry points are accessible via: [11](#0-10) 

### Recommendation

Add validation to the setter functions to enforce reasonable bounds:

```move
public(package) fun set_update_interval(config: &mut OracleConfig, update_interval: u64) {
    config.check_version();
    // Enforce minimum of 1ms and reasonable maximum (e.g., 1 hour)
    assert!(update_interval > 0, ERR_INVALID_UPDATE_INTERVAL);
    assert!(update_interval <= 3_600_000, ERR_INVALID_UPDATE_INTERVAL); // 1 hour max
    config.update_interval = update_interval;
    emit(UpdateIntervalSet { update_interval })
}

public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();
    // Enforce reasonable slippage bounds (e.g., max 50% = 5000 bps)
    assert!(dex_slippage > 0, ERR_INVALID_DEX_SLIPPAGE);
    assert!(dex_slippage <= 5000, ERR_INVALID_DEX_SLIPPAGE);
    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
```

### Proof of Concept

**Step 1:** Admin calls `manage::set_update_interval(admin_cap, oracle_config, 0)`

**Step 2:** Oracle config is updated with `update_interval = 0` (no validation prevents this)

**Step 3:** User requests deposit via `user_entry::request_deposit` (public function)

**Step 4:** Operator attempts to execute deposit via `operation::execute_deposit_request`

**Step 5:** The execution path reaches `update_free_principal_value` which calls `vault_oracle::get_normalized_asset_price`

**Step 6:** Inside `get_asset_price`, the assertion `assert!(price_info.last_updated.diff(now) < 0, ERR_PRICE_NOT_UPDATED)` fails

**Step 7:** Transaction reverts with `ERR_PRICE_NOT_UPDATED` 

**Step 8:** All subsequent deposits, withdrawals, and operations fail indefinitely until admin corrects the configuration

**Result:** Complete protocol denial of service affecting all users and operations, requiring emergency admin intervention to restore functionality.

### Citations

**File:** volo-vault/sources/oracle.move (L84-94)
```text
fun init(ctx: &mut TxContext) {
    let config = OracleConfig {
        id: object::new(ctx),
        version: VERSION,
        aggregators: table::new(ctx),
        update_interval: MAX_UPDATE_INTERVAL,
        dex_slippage: DEFAULT_DEX_SLIPPAGE,
    };

    transfer::share_object(config);
}
```

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

**File:** volo-vault/sources/manage.move (L128-138)
```text
public fun set_update_interval(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    update_interval: u64,
) {
    oracle_config.set_update_interval(update_interval);
}

public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}
```

**File:** volo-vault/sources/volo_vault.move (L806-840)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
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

```

**File:** volo-vault/sources/volo_vault.move (L1015-1022)
```text
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1109-1113)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L15-15)
```text
const SLIPPAGE_BASE: u256 = 10_000; // 10000 = 100%
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L62-66)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```
