### Title
Missing Zero Price Validation in Vault Oracle Enables Share Ratio Manipulation

### Summary
The vault oracle's `get_asset_price()` and `get_normalized_asset_price()` functions lack validation to reject zero prices, unlike the lending protocol's oracle which explicitly checks `token_price.value > 0`. When a receipt's principal asset price is zero, `mul_with_oracle_price()` mathematically returns zero correctly, but this causes severe undervaluation of receipt assets, artificially deflating the vault's total USD value and share ratio, enabling attackers to mint inflated shares and extract excess value.

### Finding Description

The vulnerability exists in the vault oracle's price retrieval flow: [1](#0-0) 

The `get_asset_price()` function validates price staleness but does NOT validate that `price_info.price > 0` before returning it. [2](#0-1) 

The `get_normalized_asset_price()` function normalizes the price to 9 decimals but also lacks zero validation.

This zero price flows into receipt value calculations: [3](#0-2) 

When `principal_price` is zero, the `mul_with_oracle_price()` calls at lines 66-69 and 70-73 mathematically return zero: [4](#0-3) 

Since `v1 * 0 / ORACLE_DECIMALS = 0`, both `pending_deposit_value` and `claimable_principal_value` become zero, severely undervaluing the receipt.

This undervalued receipt asset affects the vault's total USD value calculation: [5](#0-4) [6](#0-5) 

The underestimated total USD value causes an artificially low share ratio: [7](#0-6) 

During deposits, users receive inflated shares due to the depressed share ratio: [8](#0-7) 

**Why existing protections fail:**

The lending protocol's oracle includes proper zero price validation: [9](#0-8) 

However, the vault oracle lacks this critical check, creating an inconsistency in security standards across the codebase.

### Impact Explanation

**Direct Fund Theft via Share Ratio Manipulation:**

1. When a receipt vault's principal asset price is zero (due to oracle initialization, malfunction, or Switchboard aggregator failure), the receipt value is drastically undervalued
2. The holding vault's total USD value becomes artificially low
3. The share ratio (`total_usd_value / total_shares`) drops significantly
4. An attacker deposits funds and receives far more shares than deserved due to the formula `user_shares = new_usd_value_deposited / share_ratio_before`
5. When the oracle is corrected and prices normalize, the share ratio recovers
6. The attacker withdraws using their inflated shares, extracting more value than deposited

**Quantified Impact:**
If a receipt asset represents 50% of vault value and its price becomes zero, the total USD value drops by ~50%, causing the share ratio to halve. An attacker depositing $100K would receive ~$200K worth of shares, enabling $100K theft upon price correction.

**Affected Parties:**
- Existing vault shareholders suffer dilution and value loss
- Protocol integrity is compromised
- Trust in oracle price handling is undermined

**Operational Impact:**
Zero prices also cause transaction failures in withdrawal operations due to division by zero: [10](#0-9) [11](#0-10) 

This creates denial-of-service conditions for legitimate withdrawals.

### Likelihood Explanation

**Feasible Preconditions:**

Zero price conditions can occur through:
1. **Oracle Initialization:** Before first price update, as evidenced by test code that explicitly sets price to 0
2. **Switchboard Aggregator Malfunction:** External oracle failures or stale data
3. **Configuration Errors:** Incorrect aggregator setup or network issues
4. **Maintenance Windows:** Temporary oracle downtime during upgrades

**Attacker Capabilities:**

The attacker needs only standard user access to:
1. Monitor oracle price feeds for zero values (public on-chain data)
2. Execute deposit transactions when condition is detected
3. Wait for price correction
4. Execute withdrawal to extract inflated value

No privileged access or admin compromise required.

**Execution Practicality:**

The exploitation follows normal protocol flows using standard entry points. All operations are valid user actions within Move execution model. The attacker acts opportunistically when external conditions (oracle failure) create the vulnerability window.

**Detection Constraints:**

Oracle failures may occur during off-hours or maintenance windows. The attacker can front-run legitimate deposits once the condition is detected, making the exploit practical despite requiring external trigger.

**Probability Assessment:**

While requiring external oracle failure, such events are realistic in blockchain systems. The severity of impact when the condition occurs, combined with the lack of defensive validation present in comparable protocol code, justifies Medium severity classification.

### Recommendation

**Immediate Fix:**

Add zero price validation in the vault oracle module:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    // Add zero price validation
    assert!(price_info.price > 0, ERR_INVALID_PRICE);
    
    price_info.price
}
```

**Error Constants to Add:**

```move
const ERR_INVALID_PRICE: u64 = 2_006;
```

**Additional Safeguards:**

1. Add minimum price thresholds for sanity checks
2. Implement price change limits to detect anomalous updates
3. Add circuit breakers that pause operations on extreme price movements
4. Emit warning events when prices approach zero

**Test Cases:**

1. Test that `get_asset_price()` aborts with `ERR_INVALID_PRICE` when price is zero
2. Test that `update_receipt_value()` fails gracefully with zero prices
3. Test deposit/withdraw operations reject transactions when any asset price is zero
4. Integration tests covering oracle initialization scenarios

### Proof of Concept

**Initial State:**
- Vault A holds receipts from Vault B as DeFi asset (asset_type="Receipt_VaultB")
- Vault B's principal coin type is SUI
- Vault A has 1M shares with total USD value $1M (share ratio = 1.0)
- Legitimate user Alice holds 100K shares worth $100K

**Exploitation Steps:**

1. **Oracle Failure Occurs:**
   - Switchboard aggregator for SUI malfunctions or is being initialized
   - SUI price in oracle becomes 0

2. **Attacker Monitors and Detects:**
   - Bob (attacker) monitors oracle and detects SUI price = 0
   - Bob prepares deposit transaction

3. **Receipt Value Update:**
   - Operator calls `update_receipt_value<USDC, SUI>(vault_a, vault_b, config, clock, "Receipt_VaultB")`
   - `get_normalized_asset_price()` returns 0 for SUI
   - `mul_with_oracle_price(pending_deposit_balance, 0)` = 0
   - `mul_with_oracle_price(claimable_principal, 0)` = 0
   - Receipt value stored as ~0 (only share component if any)

4. **Total USD Value Drops:**
   - `get_total_usd_value()` sums undervalued receipt asset
   - If receipt was 50% of vault value, total drops from $1M to $500K

5. **Share Ratio Drops:**
   - `get_share_ratio()` calculates: $500K / 1M shares = $0.50 per share

6. **Attacker Deposits:**
   - Bob deposits $100K USDC
   - `execute_deposit()` calculates: `user_shares = $100K / $0.50 = 200K shares`
   - Bob receives 200K shares for $100K deposit

7. **Oracle Recovers:**
   - SUI price corrected to normal value ($1.50)
   - Receipt value recalculated correctly
   - Total USD value returns to $1M + $100K = $1.1M
   - New share ratio: $1.1M / 1.2M shares = $0.917

8. **Attacker Withdraws:**
   - Bob withdraws 200K shares
   - Value = 200K * $0.917 = $183.4K
   - Bob extracts $183.4K for $100K deposit = $83.4K profit

**Expected vs Actual Result:**
- **Expected:** Bob's deposit rejected or receives 100K shares for $100K deposit
- **Actual:** Bob receives 200K shares, enabling value extraction and theft from existing shareholders

**Success Condition:**
Bob's final balance exceeds initial deposit by the amount stolen from diluted shareholders, demonstrating exploitable share ratio manipulation via missing zero price validation.

### Notes

The answer to the specific question "does mul_with_oracle_price return zero correctly?" is **YES** - it mathematically returns zero when principal_price is zero. However, this correct mathematical behavior creates a **critical vulnerability** because zero prices should be rejected at the oracle level before reaching value calculations. The lending protocol's oracle demonstrates this is a known best practice that the vault oracle fails to implement.

### Citations

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

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-73)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L73-76)
```text
// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
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

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```
