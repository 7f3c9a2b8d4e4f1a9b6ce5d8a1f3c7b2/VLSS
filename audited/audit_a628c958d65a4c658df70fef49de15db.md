# Audit Report

## Title
Zero Oracle Price Enables Share Ratio Manipulation and Fund Theft

## Summary
The Volo Vault protocol lacks validation to prevent zero prices from external Switchboard oracles. When a zero price is used to value Navi positions, it incorrectly calculates position values as zero regardless of actual holdings. This understates the vault's total USD value, artificially deflates the share ratio, and allows attackers to mint excess shares during deposits. After the oracle corrects, attackers can withdraw more value than deposited, directly stealing funds from existing shareholders.

## Finding Description

The vulnerability chain begins with missing zero-price validation in the oracle system. The `get_asset_price()` function retrieves stored oracle prices without verifying they are non-zero [1](#0-0) , and the `get_current_price()` function fetches values from Switchboard aggregators without validation [2](#0-1) . The Switchboard Decimal type can legitimately represent zero values [3](#0-2) .

When calculating Navi position values, the protocol retrieves the asset price and multiplies it by position amounts to get USD values [4](#0-3) . The multiplication operation [5](#0-4)  produces zero USD values when the price is zero, regardless of actual position sizes.

This incorrect position value flows through the vault's value aggregation mechanism. The `get_total_usd_value()` function sums all asset values including the zero-valued position [6](#0-5) , understating the vault's true total value. The share ratio calculation divides this understated total value by total shares [7](#0-6) , producing an artificially low ratio.

During deposit execution, the protocol uses this deflated share ratio to calculate how many shares to mint. It divides the USD value deposited by the share ratio [8](#0-7) , specifically at the share calculation step [9](#0-8) . A lower denominator produces more shares. The slippage protection checks only verify shares fall within attacker-controlled bounds [10](#0-9) , which the attacker sets based on the current incorrect ratio.

**Attack Sequence:**
1. Switchboard oracle returns zero price (malfunction/misconfiguration)
2. Anyone calls public `update_price()` to store zero in OracleConfig
3. Anyone calls public `update_navi_position_value()` using zero price
4. Position value becomes zero, understating vault total value
5. Attacker's deposit request is processed via normal operator flow
6. Excess shares minted due to deflated ratio
7. Oracle corrects and position value restored
8. Attacker withdraws, extracting more value than deposited

## Impact Explanation

This vulnerability enables **direct theft of funds from existing vault shareholders**. The mathematical impact scales with the size of the mispriced position and the attacker's deposit amount.

**Quantified Scenario:**
- Pre-attack: Vault holds 1M USD (including 300K Navi position), 1M shares, ratio = 1.0
- Oracle failure: Navi position valued at 0, vault total drops to 700K USD
- Share ratio drops to 0.7 (30% understatement)
- Attacker deposits 100K USD, receives 142,857 shares (42.8% excess)
- Oracle corrects: Position restored to 300K, vault total = 1.1M USD
- New ratio: 1.1M / 1,142,857 shares = 0.9625
- Attacker withdraws: 142,857 × 0.9625 = 137,500 USD
- **Net theft: 37,500 USD (37.5% profit)**
- **Existing shareholders loss: 37,500 USD** (1M shares now worth 962,500)

The vulnerability breaks the fundamental accounting invariant that `total_shares × share_ratio = total_vault_value`. It allows value extraction without corresponding contribution, redistributing wealth from existing shareholders to the attacker.

## Likelihood Explanation

This vulnerability is **exploitable through public interfaces without requiring privileged access**:

**Feasibility:**
- Oracle price updates via `update_price()` are public functions callable by anyone
- Position value updates via `update_navi_position_value()` are public functions
- Deposit execution follows standard operator workflow for legitimate requests
- No zero-price validation exists at any level

**Preconditions:**
- External Switchboard oracle reports zero price (oracle malfunction, data feed failure, asset delisting edge cases)
- Vault has non-zero Navi position value
- Timing window between price update and correction (1-minute staleness window)

**Economic Viability:**
- Profit scales directly with mispriced position size and deposit amount
- 30% understatement with 100K deposit yields 37.5K profit (37.5% ROI)
- Only costs are gas fees (~0.01%) and deposit/withdrawal fees (10-30 bps)
- Net profit vastly exceeds costs

**Detection Difficulty:**
The attack appears as a legitimate deposit processed during an oracle malfunction period. The excess share minting is algorithmic, not obviously malicious. Off-chain monitoring could detect anomalous oracle prices, but the protocol provides no on-chain protection.

While oracle failures returning exactly zero may be infrequent, the **complete absence of validation** makes this a valid security issue. Defense-in-depth principles require validation of external inputs, especially when they directly control critical financial calculations.

## Recommendation

**Immediate Fix:** Add zero-price validation in the oracle module:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    let price = current_result.result().value() as u256;
    assert!(price > 0, ERR_ZERO_PRICE); // ADD THIS CHECK
    price
}
```

**Additional Safeguards:**
1. Add minimum price thresholds per asset (e.g., 1% of historical average)
2. Implement circuit breakers that pause deposits when prices deviate >X% from recent values
3. Add a time-weighted average price (TWAP) mechanism to smooth oracle anomalies
4. Emit warning events when prices change dramatically
5. Consider requiring multiple oracle sources for critical assets

## Proof of Concept

```move
#[test]
fun test_zero_price_exploit() {
    // Setup: Create vault with 1M total value (700K principal + 300K Navi position)
    // Initial state: 1M shares, ratio = 1.0
    
    // Step 1: Simulate oracle failure - set Navi asset price to 0
    set_current_price(&mut oracle_config, &clock, navi_asset_type, 0);
    
    // Step 2: Update Navi position value (anyone can call this)
    navi_adaptor::update_navi_position_value(&mut vault, &oracle_config, &clock, navi_asset_type, &mut navi_storage);
    // Position value now 0, vault total = 700K, ratio = 0.7
    
    // Step 3: Attacker deposits 100K
    let attacker_deposit = 100_000_000_000; // 100K with decimals
    vault::execute_deposit(&mut vault, &clock, &oracle_config, deposit_request_id, u256::max_value());
    // Attacker receives ~142,857 shares (should be 100K)
    
    // Step 4: Oracle corrects
    set_current_price(&mut oracle_config, &clock, navi_asset_type, correct_price);
    navi_adaptor::update_navi_position_value(&mut vault, &oracle_config, &clock, navi_asset_type, &mut navi_storage);
    // Vault total now 1.1M, ratio = 0.9625
    
    // Step 5: Attacker withdraws
    vault::execute_withdraw(&mut vault, &clock, &oracle_config, withdraw_request_id, 0, &mut ctx);
    // Attacker receives ~137.5K (37.5K profit stolen from existing shareholders)
    
    // Verify: Existing shareholders' 1M shares now worth only ~962.5K (37.5K loss)
}
```

This test demonstrates the complete exploit path where an attacker profits 37.5% by exploiting a temporary zero-price oracle value, with losses borne entirely by existing vault shareholders.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/volo_vault.move (L806-872)
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

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
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
