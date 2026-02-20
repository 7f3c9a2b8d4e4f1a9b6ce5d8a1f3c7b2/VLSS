# Audit Report

## Title
Zero Oracle Price Enables Share Ratio Manipulation and Fund Theft

## Summary
When the Switchboard oracle returns a zero price for Navi position assets, the protocol fails to validate this critical error condition. This allows attackers to exploit the artificially deflated vault share ratio to mint excess shares during deposits, subsequently withdrawing more value than deposited and directly stealing funds from existing shareholders.

## Finding Description

The vulnerability exists in the oracle price retrieval and position valuation pipeline, which lacks zero-price validation at multiple critical checkpoints.

**Oracle Price Retrieval Without Validation:**

The `get_current_price` function retrieves prices from Switchboard aggregators and returns them without validating that the price is non-zero. [1](#0-0)  The Switchboard Decimal type explicitly supports zero values through its constructor. [2](#0-1) 

When prices are updated via `update_price`, the protocol stores these values without checking if they are zero. [3](#0-2)  Similarly, `get_asset_price` returns the cached price without any zero validation. [4](#0-3) 

**Zero USD Value Calculation:**

The Navi position valuation logic in `calculate_navi_position_value` retrieves oracle prices and multiplies asset balances by these prices without verifying the price is valid. [5](#0-4)  The multiplication function `mul_with_oracle_price` performs `balance * price / ORACLE_DECIMALS`, which yields zero when price is zero. [6](#0-5)  When the price is zero, both supply and borrow USD values become zero regardless of actual position size, causing the net position value to be calculated as zero.

**Vault Value Corruption:**

The zero position value flows directly into the vault's asset value storage through `update_navi_position_value` without validation. [7](#0-6)  When calculating total vault value, `get_total_usd_value` iterates through all assets and sums their values, including the understated Navi position value. [8](#0-7) 

**Share Ratio Deflation:**

The share ratio is calculated by dividing total USD value by total shares in `get_share_ratio`. [9](#0-8)  An understated total value directly causes an understated share ratio.

**Excess Share Issuance:**

During deposit execution, user shares are calculated by dividing the deposited USD value by the share ratio before the deposit. [10](#0-9)  A deflated share ratio causes excess shares to be minted at line 844. The slippage protection can be bypassed because the attacker controls the `expected_shares` parameter and can set it based on the current (incorrect) ratio, allowing the checks at lines 849-850 to pass.

## Impact Explanation

This vulnerability enables **direct theft of funds from existing vault shareholders** through share dilution. The impact is:

1. **Quantifiable Loss**: Existing shareholders suffer proportional losses equal to the attacker's gains. The theft amount scales with both the mispriced position size and the deposit amount during the oracle failure window.

2. **Mathematical Example**: With a 30% vault value understatement (e.g., 300K Navi position mispriced to zero in 1M vault), an attacker depositing 100K USD receives ~142,857 shares instead of 100K. After oracle correction, these shares are worth ~137.5K USD, representing a 37.5K theft from existing shareholders.

3. **Permanent Fund Loss**: Unlike temporary price manipulation attacks, this results in permanent reallocation of vault value from existing shareholders to the attacker through the share issuance mechanism. There is no mechanism to reverse or recover these losses.

4. **No Self-Healing**: The protocol lacks any circuit breakers, price sanity checks, or oracle validation that would prevent or reverse this exploitation. The `MAX_UPDATE_INTERVAL` check only validates freshness, not correctness of values. [11](#0-10) 

## Likelihood Explanation

This vulnerability has **medium-to-high likelihood** of exploitation:

**Feasible Preconditions:**
- External Switchboard oracle returns zero price due to oracle malfunction, data feed failure, asset delisting, or extreme market conditions
- No compromise of trusted protocol roles required - the vulnerability exploits the protocol's handling of external oracle data
- Vault must have a Navi position with non-zero actual value
- Attack window exists between oracle failure detection and correction (potentially hours)

**Accessible Entry Point:**
The `execute_deposit` function is callable by operators who process legitimate user deposit requests. [12](#0-11)  The attacker simply creates a deposit request during the oracle failure window, and standard protocol execution grants excess shares.

**Economic Rationality:**
- Clear profit proportional to (mispriced_value / vault_value) × deposit_amount
- Minimal costs (gas fees + 0.1-0.3% deposit/withdrawal fees)
- Example: 30% understatement on 100K deposit yields ~37% profit (37.5K USD)

**Detection Difficulty:**
The attack appears as a legitimate deposit transaction during the oracle malfunction period. The excess shares are algorithmically granted by the protocol's own calculation logic, not through any obviously malicious action.

## Recommendation

Implement zero-price validation at multiple defense layers:

1. **Oracle Level**: Add validation in `get_current_price` and `update_price`:
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
    assert!(price > 0, ERR_ZERO_PRICE); // Add this check
    price
}
```

2. **Adaptor Level**: Add validation in `calculate_navi_position_value`:
```move
let price = vault_oracle::get_asset_price(config, clock, coin_type);
assert!(price > 0, ERR_INVALID_PRICE); // Add this check
```

3. **Vault Level**: Add sanity checks on share ratio changes during deposits to detect abnormal fluctuations that could indicate oracle failures.

## Proof of Concept

```move
#[test]
fun test_zero_price_share_manipulation() {
    // Setup: Create vault with 1M total value (700K free + 300K Navi position)
    // 1. Update oracle to return zero for Navi asset
    // 2. Update Navi position value (becomes zero)
    // 3. Total vault value now 700K instead of 1M
    // 4. Share ratio deflated to 0.7 instead of 1.0
    // 5. Attacker deposits 100K with expected_shares = 142,857 (based on 0.7 ratio)
    // 6. Execute deposit - attacker receives 142,857 shares
    // 7. Fix oracle back to correct price
    // 8. Attacker's shares now worth 137.5K (142,857 * 1.0 ratio after fix)
    // 9. Profit: 37.5K stolen from existing shareholders
}
```

**Notes:**
This vulnerability is valid because it exploits a critical missing validation in the protocol's oracle integration. While the likelihood depends on external Switchboard oracle failures, the protocol's responsibility is to handle such failures gracefully rather than silently accepting invalid data that enables fund theft. The impact is severe and permanent, making this a high-priority security issue requiring immediate remediation.

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

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
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

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
```
