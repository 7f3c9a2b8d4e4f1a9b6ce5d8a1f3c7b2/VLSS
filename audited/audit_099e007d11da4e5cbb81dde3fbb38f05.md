# Audit Report

## Title
Zero Oracle Price Causes Division by Zero in Vault Share Calculations Leading to Complete DoS

## Summary
Volo's oracle system lacks validation to prevent zero prices, and the vault's share calculation functions perform division without zero-checks. When oracle prices become zero (from Switchboard or Suilend's Pyth integration), the vault's share ratio becomes zero, causing division by zero errors in `execute_deposit()` and `execute_withdraw()`, completely disabling all deposit and withdrawal operations.

## Finding Description

**Root Cause - No Zero Price Validation:**

Volo's oracle accepts prices from Switchboard without any zero validation. The `update_price()` function directly stores whatever price value is returned from the Switchboard aggregator: [1](#0-0) 

The `get_current_price()` function retrieves the price from Switchboard as `current_result.result().value() as u256` with no validation that the price is non-zero: [2](#0-1) 

**Propagation Path - Zero Prices → Zero Share Ratio:**

When asset prices are zero, `get_total_usd_value()` sums all asset values, resulting in zero: [3](#0-2) 

The `get_share_ratio()` function then calculates the ratio as `total_usd_value / total_shares`. When `total_usd_value = 0` and `total_shares > 0`, this returns `0`: [4](#0-3) 

**Division by Zero in execute_deposit():**

In `execute_deposit()`, user shares are calculated by dividing the new USD value by the share ratio. When `share_ratio = 0`, this causes division by zero: [5](#0-4) 

The `div_d()` function performs `v1 * DECIMALS / v2` without checking if `v2` is zero: [6](#0-5) 

**Division by Zero in execute_withdraw():**

In `execute_withdraw()`, the amount to withdraw is calculated by dividing USD value by the principal coin's oracle price. If the oracle price is zero, this causes division by zero: [7](#0-6) 

The `div_with_oracle_price()` function performs `v1 * ORACLE_DECIMALS / v2` without checking if `v2` is zero: [8](#0-7) 

**Suilend Integration Risk:**

Suilend positions can also contribute zero values when their underlying Pyth oracle returns zero prices. The `parse_price_to_decimal()` function in Suilend will return a decimal with value 0 when `price_mag = 0`: [9](#0-8) 

This propagates through to the Suilend adaptor's position value calculation: [10](#0-9) 

## Impact Explanation

**HIGH Severity - Complete Vault DoS:**

This vulnerability causes complete operational failure of the vault's core deposit and withdrawal functionality:

1. All `execute_deposit()` calls abort with division by zero when calculating user shares (line 844 in volo_vault.move)
2. All `execute_withdraw()` calls abort with division by zero when calculating withdrawal amounts (lines 1014-1022 in volo_vault.move)
3. Users with pending deposit requests cannot execute deposits, locking their principal in the request buffer
4. Users with pending withdrawal requests cannot execute withdrawals, preventing access to their shares
5. The vault remains in this frozen state until oracle prices are restored to non-zero values

**Affected Operations:**
- `operation::execute_deposit()` and `operation::batch_execute_deposit()` become unusable
- `operation::execute_withdraw()` and `operation::batch_execute_withdraw()` become unusable
- Protocol fee collection halts as deposits/withdrawals cannot complete
- Pending requests may exceed locking windows while frozen

**State Integrity:**
While no funds are directly stolen, users lose access to their capital. The vault's fundamental invariant that "users can withdraw their proportional share of assets" is broken. This represents a critical failure of vault availability guarantees.

## Likelihood Explanation

**MODERATE Likelihood:**

**Preconditions:**
1. Vault has existing depositors (`total_shares > 0`)
2. Oracle prices become zero through either:
   - Switchboard aggregator returning zero prices (oracle malfunction/manipulation)
   - Suilend's Pyth oracle returning zero prices (external oracle failure)
3. Any user attempts to execute a deposit or withdrawal request

**Feasibility:**
- No attacker action required - this is a natural failure mode from oracle issues
- Oracle providers occasionally report zero/stale prices during outages or network issues
- Volo's oracle has no defensive validation to reject zero prices
- Switchboard is assumed honest per threat model, but honest oracles can still experience technical failures
- The vulnerability triggers through standard user flows with no special permissions

**Attack Complexity:**
- LOW - Any user calling `execute_deposit()` or `execute_withdraw()` triggers the bug
- No special transaction construction or timing requirements
- Immediate transaction abortion makes the issue obvious

**Detection:**
- Division by zero causes immediate transaction failure with clear error
- Recovery requires waiting for valid oracle prices or admin intervention
- No on-chain mechanism to automatically bypass zero prices

## Recommendation

**Primary Fix - Add Zero Price Validation in Oracle:**

Add validation in `update_price()` to reject zero prices:

```move
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);
    
    // Add zero price validation
    assert!(current_price > 0, ERR_INVALID_PRICE);
    
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

**Secondary Fix - Add Defensive Checks in Division Functions:**

Add zero-denominator checks in `vault_utils`:

```move
public fun div_d(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * DECIMALS / v2
}

public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * ORACLE_DECIMALS / v2
}
```

**Tertiary Fix - Add Minimum Price Threshold:**

Consider adding a configurable minimum effective price per asset type in `OracleConfig`, similar to Navi's oracle design, to prevent unreasonably low prices from being accepted.

## Proof of Concept

```move
#[test]
fun test_zero_price_causes_division_by_zero() {
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Setup: Create vault with existing shares
    setup_vault_with_shares(&mut scenario);
    
    // Set oracle price to zero (simulating oracle malfunction)
    scenario.next_tx(ADMIN);
    {
        let mut config = scenario.take_shared<OracleConfig>();
        let clock = scenario.take_shared<Clock>();
        
        // This simulates what happens when Switchboard returns zero
        vault_oracle::set_current_price(&mut config, &clock, sui_type, 0);
        
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };
    
    // Attempt to execute deposit - should abort with division by zero
    scenario.next_tx(USER);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let mut reward_manager = scenario.take_shared<RewardManager<SUI>>();
        let config = scenario.take_shared<OracleConfig>();
        let clock = scenario.take_shared<Clock>();
        let operation = scenario.take_shared<Operation>();
        let cap = scenario.take_from_sender<OperatorCap>();
        
        // This call will abort with division by zero at line 844 of volo_vault.move
        operation::execute_deposit(
            &operation,
            &cap,
            &mut vault,
            &mut reward_manager,
            &clock,
            &config,
            1, // request_id
            1000000, // max_shares_received
        );
        
        // Cleanup (unreachable due to abort)
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
        test_scenario::return_shared(operation);
        test_scenario::return_to_sender(&scenario, cap);
    };
    
    scenario.end();
}
```

## Notes

**Clarification on "minimum_effective_price":**
The claim references `minimum_effective_price` which is actually a configuration parameter in Navi/Suilend's external oracle system (seen in `volo-vault/local_dependencies/protocol/oracle/sources/config.move`), not in Volo's own oracle module. However, the core vulnerability is valid: Volo's oracle lacks any minimum price validation, allowing zero prices from Switchboard to propagate through the system.

**Scope Verification:**
All affected files are in scope:
- `volo-vault/sources/oracle.move` (Volo's oracle)
- `volo-vault/sources/volo_vault.move` (vault core logic)
- `volo-vault/sources/utils.move` (division functions)
- `volo-vault/sources/operation.move` (deposit/withdraw operations)
- `volo-vault/sources/adaptors/suilend_adaptor.move` (Suilend integration)

**Attack Vector:**
No malicious actor is required - this is a defensive programming failure. Oracle technical failures or network issues naturally occurring in production can trigger this DoS.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L994-1077)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Get the current share ratio
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

    // Decrease the share in vault and receipt
    self.total_shares = self.total_shares - shares_to_withdraw;

    // Split balances from the vault
    assert!(amount_to_withdraw <= self.free_principal.value(), ERR_NO_FREE_PRINCIPAL);
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);

    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);

    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
    });

    // Update total usd value after withdraw executed
    // This update should not generate any performance fee
    // (actually the total usd value will decrease, so there is no performance fee)
    self.update_free_principal_value(config, clock);

    // Update the vault receipt info
    let vault_receipt = &mut self.receipts[withdraw_request.receipt_id()];

    let recipient = withdraw_request.recipient();
    if (recipient != address::from_u256(0)) {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            0,
        )
    } else {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            withdraw_balance.value(),
        )
    };

    self.delete_withdraw_request(request_id);

    (withdraw_balance, recipient)
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

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-70)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let expo = price::get_expo(&price);

        if (i64::get_is_negative(&expo)) {
            div(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))),
            )
        } else {
            mul(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))),
            )
        }
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L42-89)
```text
public(package) fun parse_suilend_obligation<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &LendingMarket<ObligationType>,
    clock: &Clock,
): u256 {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());

    let mut total_deposited_value_usd = 0;
    let mut total_borrowed_value_usd = 0;
    let reserves = lending_market.reserves();

    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```
