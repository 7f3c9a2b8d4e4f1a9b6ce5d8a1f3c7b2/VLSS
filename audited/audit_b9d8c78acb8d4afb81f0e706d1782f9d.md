### Title
Stale Oracle Prices Enable Incorrect Share Minting During Deposit Execution

### Summary
The `execute_deposit()` function uses oracle prices from `OracleConfig` that can be up to 1 minute stale to calculate the USD value of deposited assets, which directly determines share minting amounts. This creates a systemic vulnerability where deposits executed during periods of price volatility result in incorrect share allocation, harming either depositors or existing shareholders depending on price movement direction.

### Finding Description

The vulnerability exists in the deposit execution flow across multiple components:

**Primary Entry Point:**
The operator-callable `execute_deposit()` function in operation.move calls the vault's deposit execution logic. [1](#0-0) 

**Core Vulnerability Location:**
The vault's `execute_deposit()` implementation calculates shares using oracle prices via `update_free_principal_value()`. [2](#0-1) 

**Root Cause - Dual Staleness Standards:**

There are TWO separate staleness checks with conflicting guarantees:

1. **Vault-level check** requires same-transaction asset value updates: [3](#0-2) [4](#0-3) 

2. **Oracle-level check** allows 1-minute stale prices: [5](#0-4) [6](#0-5) 

**Why Protections Fail:**

The `update_free_principal_value()` function fetches oracle prices that pass the 1-minute staleness check but may not reflect current market conditions: [7](#0-6) 

The oracle price retrieval allows up to 1 minute staleness: [8](#0-7) 

**Execution Path:**
1. Operator calls `execute_deposit()` with `max_shares_received` parameter
2. Function calls `update_free_principal_value()` which uses `vault_oracle::get_normalized_asset_price()`
3. Oracle price from `OracleConfig` can be up to 1 minute old (validated at oracle level, not vault level)
4. Stale price calculates incorrect USD value: `total_usd_value_after - total_usd_value_before`
5. Shares minted using incorrect USD value: `user_shares = new_usd_value_deposited / share_ratio_before`
6. Slippage checks compare against user's `expected_shares` and operator's `max_shares_received`, but neither enforces oracle freshness

### Impact Explanation

**Direct Fund Impact:**

- **Scenario 1 - Stale LOW Price:** Real market price increases but oracle shows old lower price → depositors receive FEWER shares than fair value → depositors lose value, existing shareholders gain unfairly
- **Scenario 2 - Stale HIGH Price:** Real market price decreases but oracle shows old higher price → depositors receive MORE shares than fair value → existing shareholders suffer dilution, depositors gain unfairly

**Quantified Risk:**
For a volatile asset with 10% price movement in 1 minute and a $100,000 deposit:
- Potential value discrepancy: $10,000 worth of incorrectly minted/denied shares
- Affects every deposit executed during volatile periods
- Cumulative impact across all deposits can be substantial

**Who Is Affected:**
- Depositors submitting deposit requests
- All existing vault shareholders (share value dilution/concentration)
- Protocol integrity and fair value guarantees

**Severity Justification:**
CRITICAL - Direct fund impact through systematic mispricing mechanism that affects core vault functionality (share minting) without requiring any malicious actor.

### Likelihood Explanation

**Attacker Capabilities:**
This is NOT an attack requiring malicious actors - it's a systemic operational risk:
- Normal operator operations can trigger the vulnerability
- No special permissions beyond standard operator role needed
- Oracle prices naturally become stale during normal operation

**Attack Complexity:**
LOW - The vulnerability manifests through normal protocol operation:
1. Oracle prices in `OracleConfig` age toward 1-minute staleness
2. Market prices move during crypto volatility (common occurrence)
3. Operator executes pending deposits following standard procedures
4. Incorrect shares minted automatically due to stale prices

**Feasibility Conditions:**
HIGHLY FEASIBLE - All conditions occur naturally:
- Crypto markets exhibit frequent volatility
- 1-minute windows allow significant price divergence for volatile assets
- Operators execute deposits asynchronously from oracle updates
- No on-chain enforcement requires fresh oracle data at execution time

**Detection/Operational Constraints:**
- Operators cannot distinguish between fresh and near-stale oracle prices on-chain
- The `max_shares_received` parameter is manually calculated off-chain (error-prone)
- No automatic circuit breakers for price staleness at deposit execution
- Silent failure mode - incorrect shares minted with no error

**Probability:**
HIGH - Occurs whenever deposits execute during the oracle staleness window (up to 1 minute) with concurrent price movements, which is common in crypto markets.

### Recommendation

**Immediate Mitigation:**

1. **Enforce Fresh Oracle Updates in Same Transaction:**
Modify `execute_deposit()` to require oracle price updates within the same programmable transaction block (PTB):

```move
// In operation.move execute_deposit()
// Add before vault.execute_deposit():
vault_oracle::update_price(config, aggregator, clock, asset_type);
```

2. **Reduce Oracle Staleness Window:**
Decrease `update_interval` in `OracleConfig` from 60 seconds to a much shorter period (e.g., 5-10 seconds) via admin configuration to minimize price divergence window.

3. **Add On-Chain Oracle Freshness Validation:**
In `vault.execute_deposit()`, add explicit check before share calculation:
```move
// Verify oracle was updated very recently (e.g., within 5 seconds)
let oracle_age = clock.timestamp_ms() - oracle_config.last_price_update(principal_asset_type);
assert!(oracle_age < 5000, ERR_ORACLE_TOO_STALE);
```

4. **Implement Vault-Level Oracle Update Requirement:**
Modify `update_free_principal_value()` to validate that the oracle price itself (not just the vault's cached value) was updated within the vault's `MAX_UPDATE_INTERVAL` (currently 0, meaning same transaction).

**Invariant Checks to Add:**
- Oracle price timestamp must match or be within seconds of current transaction timestamp
- All oracle prices used in share calculations must be from current transaction execution
- Add event emission showing oracle age at deposit execution for monitoring

**Test Cases to Prevent Regression:**
1. Test deposit execution with 30-second-old oracle → should fail
2. Test deposit execution immediately after oracle update → should succeed  
3. Test that price movements between oracle update and deposit execution are bounded
4. Test that share minting matches expected values with fresh vs stale prices
5. Verify PTB pattern requiring oracle update + deposit execution atomically

### Proof of Concept

**Required Initial State:**
- Vault with existing shares and total_usd_value
- Oracle price for principal asset in `OracleConfig` at $100
- Market price moves to $110 (10% increase)
- Oracle price NOT updated (now 50 seconds stale but still < 60 second limit)

**Transaction Steps:**

1. **User submits deposit request:**
   - Deposits 1000 tokens
   - Sets `expected_shares` based on current $110 market price
   - Expects approximately (1000 * 110) / current_share_ratio shares

2. **Operator executes deposit (standard operation):**
   - Calls `operation::execute_deposit()` with deposit request_id
   - Sets `max_shares_received` calculated off-chain (potentially using stale data)

3. **Internal execution flow:**
   - `update_free_principal_value()` called
   - `vault_oracle::get_normalized_asset_price()` returns $100 (stale by 50 seconds, but passes 60-second check)
   - USD value calculated as 1000 * $100 = $100,000 (should be $110,000)
   - Shares minted: $100,000 / share_ratio (FEWER than deserved)

**Expected vs Actual Result:**
- **Expected (fair value):** User receives shares worth $110,000 at current market price
- **Actual (vulnerability):** User receives shares worth $100,000 due to stale oracle price
- **Discrepancy:** User loses $10,000 worth of share value (9% loss)
- **Beneficiaries:** Existing shareholders gain through reduced dilution

**Success Condition:**
Deposit executes successfully with `ERR_UNEXPECTED_SLIPPAGE` NOT triggered (because user's `expected_shares` and operator's `max_shares_received` don't account for the stale oracle price), resulting in provably incorrect share allocation based on outdated pricing data.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
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

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
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
