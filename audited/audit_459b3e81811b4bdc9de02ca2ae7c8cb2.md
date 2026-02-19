### Title
Switchboard Queue Authority Compromise Enables Price Manipulation in Volo Vault Operations

### Summary
Volo Vault's oracle price feeds consume Switchboard aggregator prices without validating the security state of the underlying queue authority or oracle enablement method. If a Switchboard queue authority is compromised (outside Volo's control), an attacker can enable malicious oracles and inject fake prices that directly affect vault share calculations, deposit/withdrawal amounts, and USD valuations across all vault operations.

### Finding Description

**Root Cause**: Volo Vault's `OracleConfig` stores Switchboard aggregator addresses and consumes their prices without any validation of the queue's authority status, oracle enablement method, or configuration integrity. [1](#0-0) 

The `get_current_price()` function only validates price staleness using the vault's own `update_interval`, but performs zero validation of:
- Queue authority state
- Aggregator authority state  
- Oracle enablement method (guardian attestation vs. queue override)
- Queue configuration parameters (min_attestations, oracle_validity_length_ms)

**Attack Vector**: Switchboard's queue authority can enable malicious oracles via `queue_override_oracle_action::run()` without requiring guardian attestations: [2](#0-1) [3](#0-2) 

Once enabled, malicious oracles can submit fake prices that pass all Switchboard validation checks since the oracle's `secp256k1_key` matches the attacker's key: [4](#0-3) 

**Exploitation Path**: Multiple vault adaptors consume these unvalidated prices for critical USD valuations: [5](#0-4) 

These manipulated USD values propagate to deposit/withdrawal execution: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Fund Impact**: 
- **Inflated collateral prices**: Attacker can over-borrow vault funds by making Navi positions appear more valuable than actual worth
- **Deflated collateral prices**: Attacker can receive excess shares during deposits or excess coins during withdrawals
- **Share ratio manipulation**: Fake prices directly affect `share_ratio` calculations used in all deposit/withdrawal operations

**Quantified Damage**:
- If attacker inflates a $1M Navi position to appear as $10M (10x manipulation), they could extract $9M excess value from vault during withdrawals
- If attacker deflates principal coin price during deposit, they receive proportionally more shares for the same coin amount
- All vault participants affected as total_usd_value and share ratios become corrupted

**Affected Parties**:
- All vault depositors (share value dilution)
- Vault protocol reserves (direct fund loss)
- Legitimate withdrawers (insufficient funds available)

**Severity Justification**: Critical - Direct theft of vault funds with no on-chain recovery mechanism once prices are consumed and shares/balances updated.

### Likelihood Explanation

**Precondition**: Switchboard queue authority compromise (external to Volo, but stated as precondition). This could occur through:
- Switchboard key management failure
- Switchboard infrastructure compromise
- Malicious queue operator
- Social engineering of Switchboard team

**Attack Execution**:
1. Attacker calls `queue_override_oracle_action::run()` using compromised queue authority to enable their own oracle with their `secp256k1_key`
2. Attacker calls `aggregator_submit_result_action::run()` with fake prices signed by their key
3. Volo Vault consumes fake prices via `get_current_price()` with zero validation
4. Attacker executes deposit/withdrawal with manipulated share ratios

**Attack Complexity**: Low - Once queue authority is compromised, only 2 transactions needed (enable oracle, submit fake price)

**Detection Constraints**: 
- No on-chain monitoring of queue authority changes
- No validation of oracle enablement events  
- Price manipulation only detected after exploitation when vault accounting breaks

**Economic Rationality**: Highly rational - Attacker gains direct access to vault funds proportional to price manipulation magnitude with minimal gas costs

### Recommendation

**Immediate Mitigation**:
1. Add queue authority validation in `OracleConfig`:
   - Store expected queue authority address when aggregator is added
   - Validate queue authority hasn't changed before consuming prices
   - Add `assert!(queue.authority() == expected_authority, ERR_QUEUE_AUTHORITY_CHANGED)`

2. Add oracle enablement method tracking:
   - Store whether oracle was guardian-attested vs. queue-overridden
   - Reject prices from queue-overridden oracles or require additional validation
   - Monitor `QueueOracleOverride` events

3. Implement aggregator configuration validation:
   - Store expected `feed_hash`, `max_staleness_seconds`, `min_responses` when aggregator is added
   - Validate configs haven't changed before consuming prices
   - Add circuit breaker if configs change unexpectedly

**Code-Level Fix** in `oracle.move`:

```move
public struct AggregatorSecurity has store {
    expected_queue_authority: address,
    expected_feed_hash: vector<u8>,
    oracle_enablement_method: u8, // 0=attestation, 1=override
}

// Store in OracleConfig alongside PriceInfo
// Validate before get_current_price()
```

**Test Cases**:
- Test price rejection when queue authority changes
- Test price rejection when feed_hash changes
- Test price rejection from queue-overridden oracles
- Test event monitoring for authority/config changes

### Proof of Concept

**Initial State**:
- Volo Vault OracleConfig has legitimate Switchboard aggregator for SUI price
- Aggregator belongs to queue with legitimate authority
- Current SUI price: $30

**Attack Sequence**:

1. **Queue Authority Compromised** (external precondition):
   - Switchboard queue authority address `0xLEGIT` compromised
   - Attacker gains control of queue authority private key

2. **Enable Malicious Oracle**:
   ```
   Call: queue_override_oracle_action::run(
     queue: &mut Queue,
     oracle: &mut Oracle,  // attacker's oracle
     secp256k1_key: <attacker's key>,
     mr_enclave: <any value>,
     expiration_time_ms: <far future>,
   )
   ```
   - Validates `queue.has_authority(ctx)` ✓ (attacker has compromised authority)
   - Calls `oracle.enable_oracle()` ✓
   - Malicious oracle now enabled

3. **Submit Fake Price**:
   ```
   Call: aggregator_submit_result_action::run(
     aggregator: &mut Aggregator,
     queue: &Queue,
     value: 300_000_000_000, // $300 instead of $30 (10x inflation)
     timestamp_seconds: <current time>,
     oracle: &Oracle,  // attacker's enabled oracle
     signature: <valid ECDSA signature from attacker's key>,
   )
   ```
   - Validates `oracle.queue() == aggregator.queue()` ✓
   - Validates `oracle.expiration_time_ms() > clock.timestamp_ms()` ✓
   - Validates ECDSA signature matches oracle's key ✓
   - Aggregator accepts fake price ✓

4. **Exploit Vault**:
   ```
   Call: navi_adaptor::update_navi_position_value()
   ```
   - Calls `vault_oracle::get_asset_price()` 
   - Returns $300 instead of $30 (NO VALIDATION) ✓
   - Calculates inflated USD value for Navi position ✓
   - Calls `vault.finish_update_asset_value()` with fake value ✓

5. **Withdraw Excess Funds**:
   ```
   Call: execute_withdraw()
   ```
   - Calculates share ratio using inflated USD values
   - User receives 10x more coins than legitimate value
   - Vault fund theft complete ✓

**Expected Result**: Vault rejects fake prices due to queue authority validation

**Actual Result**: Vault accepts fake prices and allows theft of funds through share ratio manipulation

### Citations

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L32-44)
```text
public fun validate(
    queue: &Queue,
    oracle: &Oracle, 
    expiration_time_ms: u64,
    ctx: &mut TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(oracle.version() == EXPECTED_ORACLE_VERSION, EInvalidOracleVersion);
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(expiration_time_ms > 0, EInvalidExpirationTime);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L46-59)
```text
fun actuate(
    oracle: &mut Oracle,
    queue: &mut Queue,
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
    clock: &Clock,
) {
    oracle.enable_oracle(
        secp256k1_key,
        mr_enclave,
        expiration_time_ms,
    ); 

```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L42-96)
```text
public fun validate<T>(
    aggregator: &Aggregator,
    queue: &Queue,
    oracle: &Oracle,
    timestamp_seconds: u64,
    value: &Decimal,
    signature: vector<u8>,
    clock: &Clock,
    coin: &Coin<T>,
) {

    // check that the versions are correct
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);

    // check that the aggregator version is correct
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);

    // verify that the oracle is servicing the correct queue
    assert!(oracle.queue() == aggregator.queue(), EAggregatorQueueMismatch);

    // verify that the oracle is up
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);

    // make sure that update staleness point is not in the future
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);

    // check that the signature is valid length
    assert!(signature.length() == 65, ESignatureInvalid);

    // check that the signature is valid
    let update_msg = hash::generate_update_msg(
        value,
        oracle.queue_key(),
        aggregator.feed_hash(),
        x"0000000000000000000000000000000000000000000000000000000000000000",
        aggregator.max_variance(),
        aggregator.min_responses(),
        timestamp_seconds,
    );

    // recover the pubkey from the signature
    let recovered_pubkey_compressed = ecdsa_k1::secp256k1_ecrecover(
        &signature, 
        &update_msg, 
        1,
    );
    let recovered_pubkey = ecdsa_k1::decompress_pubkey(&recovered_pubkey_compressed);

    // check that the recovered pubkey is valid
    assert!(hash::check_subvec(&recovered_pubkey, &oracle.secp256k1_key(), 1), ERecoveredPubkeyInvalid);

    // fee check
    assert!(queue.has_fee_type<T>(), EInvalidFeeType);
    assert!(coin.value() >= queue.fee(), EInsufficientFee);
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
```

**File:** volo-vault/sources/volo_vault.move (L806-850)
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
```

**File:** volo-vault/sources/volo_vault.move (L994-1030)
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
```
