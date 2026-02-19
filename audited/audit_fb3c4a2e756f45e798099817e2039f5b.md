### Title
Zero Oracle Price Causes Division by Zero in Vault Share Calculations Leading to Complete DoS

### Summary
When oracle prices are zero (either due to `minimum_effective_price = 0` configuration or Suilend reserve zero prices), the vault's `total_usd_value` becomes zero. This causes `get_share_ratio()` to return zero, which then triggers division by zero errors in both `execute_deposit()` and `execute_withdraw()`, completely disabling all vault deposit and withdrawal operations.

### Finding Description

**Root Cause - No Zero Price Validation:**

The oracle validation system allows zero prices to pass through: [1](#0-0) 

If `minimum_effective_price` is configured as 0, then zero prices pass this validation. There is no enforcement that `minimum_effective_price` must be non-zero: [2](#0-1) 

Additionally, the `update_price()` function accepts zero values without validation: [3](#0-2) 

**Propagation Path - Zero Prices → Zero Total USD Value:**

When all asset prices are zero, `get_total_usd_value()` sums to zero: [4](#0-3) 

This can occur through:
1. Volo's own oracle returning zero prices (if `minimum_effective_price = 0`)
2. Suilend positions returning zero value when Suilend reserves have zero prices: [5](#0-4) 

Note that Suilend's `parse_price_to_decimal()` does return 0 when price_mag = 0: [6](#0-5) 

**Division by Zero in Share Calculations:**

When `total_shares > 0` and `total_usd_value = 0`, the share ratio calculation returns zero: [7](#0-6) 

The `div_d()` function performs division without zero checks: [8](#0-7) 

This zero `share_ratio` causes division by zero in `execute_deposit()`: [9](#0-8) 

Similarly, zero principal coin price causes division by zero in `execute_withdraw()`: [10](#0-9) 

The `div_with_oracle_price()` function also lacks zero checks: [11](#0-10) 

### Impact Explanation

**Operational Impact - Complete Vault DoS:**
- All `execute_deposit()` calls abort with division by zero when calculating `user_shares`
- All `execute_withdraw()` calls abort with division by zero when calculating `amount_to_withdraw`
- Users cannot execute pending deposit or withdrawal requests
- Vault operations are completely frozen until oracle prices are restored to non-zero values
- Pending requests remain locked, potentially exceeding locking windows

**Affected Parties:**
- All vault depositors with pending deposit requests cannot complete deposits
- All vault withdrawers with pending withdrawal requests cannot complete withdrawals
- New deposits and withdrawals cannot be initiated until prices recover
- Protocol revenue collection halts as no deposit/withdraw fees can be collected

**Severity Justification:**
This is HIGH severity because it causes complete operational failure of core vault functionality. While funds are not directly stolen, the DoS prevents all user access to their capital until administrative intervention restores valid oracle prices.

### Likelihood Explanation

**Preconditions:**
1. `minimum_effective_price = 0` is configured for at least one asset (admin misconfiguration), OR
2. Suilend reserve prices become zero through their Pyth oracle integration
3. At least one existing depositor exists (`total_shares > 0`)
4. Any user attempts to execute a deposit or withdrawal

**Attack Complexity:**
- No attacker action required - this is a failure mode from configuration/oracle issues
- Natural occurrence possible if oracle feeds malfunction or are misconfigured
- No special permissions needed to trigger - any user executing requests triggers the bug

**Feasibility Conditions:**
- Oracle misconfiguration is realistic given no enforcement of `minimum_effective_price > 0`
- Oracle providers occasionally report zero/invalid prices during outages
- Suilend's integration inherits their oracle risks without additional validation
- The vulnerability is reachable through standard user flows (`execute_deposit`, `execute_withdraw`)

**Detection/Mitigation:**
- Division by zero causes immediate transaction abortion, making detection obvious
- Recovery requires admin intervention to update oracle configuration or wait for valid prices
- No on-chain mechanism to automatically recover from zero price state

**Probability Assessment:**
MODERATE likelihood - requires specific misconfiguration or oracle failure, but lacks defensive checks that would prevent the issue.

### Recommendation

**1. Add Non-Zero Price Validation in Oracle System:**

Add validation when setting `minimum_effective_price`:
```move
// In oracle_manage.move::set_minimum_effective_price_to_price_feed
assert!(value > 0, ERR_ZERO_MINIMUM_PRICE);
```

Add runtime zero price check in `update_price()`:
```move
// In oracle.move::update_price
assert!(token_price > 0, ERR_ZERO_PRICE);
```

**2. Add Zero Check Before Division in Share Calculations:**

In `get_share_ratio()`:
```move
let total_usd_value = self.get_total_usd_value(clock);
assert!(total_usd_value > 0, ERR_ZERO_TOTAL_VALUE);
let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

In `execute_withdraw()`:
```move
let price = vault_oracle::get_normalized_asset_price(...);
assert!(price > 0, ERR_ZERO_PRICE);
let amount_to_withdraw = vault_utils::div_with_oracle_price(usd_value_to_withdraw, price);
```

**3. Add Test Cases:**
- Test deposit execution with zero share_ratio scenario
- Test withdrawal execution with zero principal price
- Test oracle configuration rejection of zero `minimum_effective_price`
- Test Suilend position valuation with zero reserve prices

### Proof of Concept

**Initial State:**
1. Vault has existing deposits: `total_shares = 1000 * 10^9`, `total_usd_value = 1000 * 10^9`
2. Admin configures `minimum_effective_price = 0` for SUI asset
3. Oracle updates SUI price to 0 (passes validation)
4. Suilend reserve prices also drop to 0 through their Pyth integration

**Exploit Sequence:**

**Step 1:** Asset values update to zero
- `update_free_principal_value()` calculates: `free_principal_balance * 0 = 0`
- `update_suilend_position_value()` returns 0 from `parse_suilend_obligation()`
- `assets_value[free_principal] = 0`, `assets_value[suilend_position] = 0`

**Step 2:** User attempts to execute deposit request
- Transaction calls `execute_deposit(request_id, max_shares_received)`
- `get_share_ratio()` executes:
  - `total_usd_value = 0` (sum of all zero asset values)
  - `share_ratio = div_d(0, 1000 * 10^9) = 0`
- Line 844: `user_shares = div_d(new_usd_value_deposited, 0)`
- **Result:** Division by zero abort, transaction fails

**Step 3:** User attempts to execute withdrawal request
- Transaction calls `execute_withdraw(request_id, max_amount_received)`
- Line 1015: `amount_to_withdraw = div_with_oracle_price(usd_value, 0)`
- **Result:** Division by zero abort, transaction fails

**Expected vs Actual:**
- **Expected:** Deposits and withdrawals execute successfully with appropriate slippage checks
- **Actual:** All deposit and withdrawal executions abort with division by zero error, vault is completely unusable

**Success Condition:**
Vault enters permanent DoS state where no deposits or withdrawals can be executed until oracle prices are manually restored to non-zero values.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L38-41)
```text
        // check if the price is less than the minimum configuration value
        if (price < minimum_effective_price) {
            return false
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L77-80)
```text
    public fun set_minimum_effective_price_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u256) {
        config::version_verification(oracle_config);
        config::set_minimum_effective_price_to_price_feed(oracle_config, feed_id, value)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L115-135)
```text
    public(friend) fun update_price(clock: &Clock, price_oracle: &mut PriceOracle, oracle_id: u8, token_price: u256) {
        // TODO: update_token_price can be merged into update_price
        version_verification(price_oracle);

        let price_oracles = &mut price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let price = table::borrow_mut(price_oracles, oracle_id);
        let now = clock::timestamp_ms(clock);
        emit(PriceUpdated {
            price_oracle: object::uid_to_address(&price_oracle.id),
            id: oracle_id,
            price: token_price,
            last_price: price.value,
            update_at: now,
            last_update_at: price.timestamp,
        });

        price.value = token_price;
        price.timestamp = now;
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

**File:** volo-vault/sources/utils.move (L27-30)
```text
// div with decimals
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/utils.move (L73-76)
```text
// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```
