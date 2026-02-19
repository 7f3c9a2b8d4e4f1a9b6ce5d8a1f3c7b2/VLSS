### Title
Stale Expected Amount in WithdrawRequest Bypasses User Slippage Protection

### Summary
The `expected_amount` parameter in `WithdrawRequest` is fixed at request creation time but the actual withdrawal amount is calculated using the current share ratio at execution time. Since there is no time constraint on request execution and the share ratio can change significantly during vault operations, the stored `expected_amount` becomes stale and fails to provide meaningful slippage protection. The operator-controlled `max_amount_received` parameter at execution time further undermines user-intended slippage bounds.

### Finding Description

The vulnerability exists in the withdraw request flow across multiple functions:

**Request Creation**: When a user creates a withdrawal request, the `expected_amount` is stored in the `WithdrawRequest` struct [1](#0-0) . This value represents the user's minimum acceptable withdrawal amount based on the share ratio at request time [2](#0-1) .

**Share Ratio Calculation**: The share ratio is calculated dynamically as `total_usd_value / total_shares` [3](#0-2) . This ratio depends on `total_usd_value`, which is the sum of all asset values stored in `self.assets_value`.

**Asset Value Updates**: During vault operations, asset values are updated through `finish_update_asset_value`, which modifies the `assets_value` table [4](#0-3) . These updates occur after DeFi operations when adaptors revalue positions, causing the share ratio to change significantly.

**Request Execution**: When the operator executes a withdrawal request, the actual withdrawal amount is calculated using the **current** share ratio at execution time, not the ratio at request creation time [5](#0-4) . The slippage check only verifies that `amount_to_withdraw >= expected_amount`, where `expected_amount` is the stale value from request creation.

**Root Cause**: There is no time constraint on when a request can be executed (no check on `request_time` in `execute_withdraw`), and there is no mechanism for users to update their `expected_amount` without canceling and recreating the request. The `max_amount_received` parameter, which should protect against upside slippage, is provided by the operator at execution time rather than being stored with the user's request [6](#0-5) .

**Why Existing Protections Fail**: While test cases show `max_amount_received` being set equal to `expected_amount` for immediate execution [7](#0-6) , the code does not enforce this pattern or any time-bound execution, allowing significant divergence between user intentions and actual execution conditions.

### Impact Explanation

**Direct Impact**:
1. **User Slippage Protection Bypass**: Users set `expected_amount` based on current market conditions, but if the request sits for days or weeks, this becomes meaningless. A user expecting ~1000 tokens (with 5% tolerance = 950 expected_amount) could receive 1500 tokens if the ratio increases 50%, or their request could fail if the ratio decreases moderately.

2. **Unfair Value Distribution**: When the share ratio increases significantly and old requests with low `expected_amount` values are executed, these users extract more value from the vault than is proportionate to current conditions, potentially disadvantaging other vault participants.

3. **Operator Discretion**: The operator controls when requests are executed and the `max_amount_received` parameter, enabling selective execution timing that could favor certain users or execution conditions.

4. **Request Gridlock**: If share ratios decrease significantly, many old requests become unexecutable (would fail the `expected_amount` check), forcing users to cancel and recreate requests, creating operational friction.

**Quantified Impact**: For a vault with $10M TVL and typical DeFi strategy returns of ±20% per month, requests stored for 30+ days could face ratio changes of 20-50%. A user with $100K withdrawal expecting 5% slippage tolerance could see actual amounts ranging from $80K (failed transaction) to $150K (50% over expectation).

**Affected Parties**: All users who create withdrawal requests that are not executed immediately, especially during periods of high vault operation activity or volatile market conditions.

### Likelihood Explanation

**Reachable Entry Point**: Any user can create a withdrawal request via `user_entry::withdraw` or `user_entry::withdraw_with_auto_transfer`, providing their chosen `expected_amount`. These are public entry functions requiring no special privileges.

**Feasible Preconditions**: 
- User has vault shares and creates a withdrawal request
- Vault undergoes normal operations (borrowing assets, generating yields, incurring losses)
- Time passes between request creation and execution (realistic in practice, especially if the operator batches requests or delays execution)

**Execution Practicality**: The scenario requires no attacker actions - it occurs naturally through normal protocol operation:
1. User creates request with expected_amount based on current ratio
2. Operator performs vault operations over days/weeks
3. Asset values are updated through normal adaptor flows
4. Share ratio changes as a natural result of operations
5. Operator executes the request with a liberal `max_amount_received`

**Economic Rationality**: No attack cost is required. The vulnerability manifests through normal usage patterns where requests are not executed immediately. Operators have incentive to batch requests for gas efficiency, naturally creating delays.

**Probability**: HIGH - The protocol explicitly supports multi-day operation cycles with asset rebalancing. The lack of time constraints on request execution makes this scenario inevitable in production environments where request queues build up and execution is batched.

### Recommendation

**Immediate Mitigations**:

1. **Add Request Expiration**: Implement a maximum staleness period for withdrawal requests (e.g., 24-48 hours). Add a check in `execute_withdraw`:
```
assert!(
    clock.timestamp_ms() - withdraw_request.request_time() <= MAX_REQUEST_AGE,
    ERR_REQUEST_EXPIRED
);
```

2. **Store Max Amount in Request**: Modify `WithdrawRequest` struct to store a user-provided `max_amount` (in addition to `expected_amount`) at request creation time, and enforce this at execution instead of using operator-provided `max_amount_received`.

3. **Add Request Update Function**: Allow users to update the `expected_amount` (and new `max_amount`) of pending requests without canceling, enabling users to adjust their slippage tolerance as conditions change.

4. **Ratio Deviation Limit**: Add a check that fails execution if the current share ratio deviates more than a reasonable threshold (e.g., 10%) from the ratio at request creation time, forcing users to recreate requests with updated expectations.

**Long-term Solution**: Implement a two-sided slippage protection mechanism where both `expected_amount` (minimum) and `max_amount` (maximum) are:
- Provided by the user at request creation time
- Stored in the WithdrawRequest struct
- Enforced at execution time
- Adjustable by the user before execution

### Proof of Concept

**Initial State**:
- Vault has 1000 total_shares and $10,000 total_usd_value
- Share ratio = 10 (each share worth $10)
- Principal token price = $1
- User owns 100 shares

**Transaction Steps**:

1. **T0 - User Creates Withdrawal Request**:
   - User calls `user_entry::withdraw(vault, 100 shares, 950 tokens, receipt, clock, ctx)`
   - Expected withdrawal: 100 shares × ratio(10) = $1000 = 1000 tokens
   - User sets `expected_amount = 950` (5% downside tolerance)
   - Request stored with: `{shares: 100, expected_amount: 950, request_time: T0}`

2. **T1 to T30 - Vault Operations**:
   - Operator performs multiple operation cycles over 30 days
   - Vault generates 50% returns through DeFi strategies
   - `finish_update_asset_value` updates asset values after each operation
   - New total_usd_value = $15,000 (vault grew from $10K to $15K)
   - New share ratio = $15,000 / 1000 = 15

3. **T30 - Operator Executes Withdrawal**:
   - Operator calls `operation::execute_withdraw` with `max_amount_received = 2000`
   - Calculation: amount = 100 shares × ratio(15) = $1500 = 1500 tokens
   - Check 1: `1500 >= 950` (expected_amount) ✓ **PASSES**
   - Check 2: `1500 <= 2000` (max_amount_received) ✓ **PASSES**
   - User receives 1500 tokens (50% more than expected)

**Expected Result**: User should receive ~1000 tokens ± 5% (950-1050 tokens) based on conditions at request time.

**Actual Result**: User receives 1500 tokens (50% more than originally expected) because the stored `expected_amount` of 950 provides no meaningful upper bound protection, and the operator's `max_amount_received` of 2000 is too permissive.

**Success Condition**: The vulnerability is confirmed when a withdrawal request with stale `expected_amount` executes successfully despite the actual withdrawal amount deviating significantly (>10%) from what the user calculated when creating the request, demonstrating that the slippage protection has been bypassed by the passage of time and changing share ratio.

### Citations

**File:** volo-vault/sources/requests/withdraw_request.move (L5-17)
```text
public struct WithdrawRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Withdraw Info ---- //
    shares: u256, // Shares to withdraw
    expected_amount: u64, // Expected amount to get after withdraw
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** volo-vault/sources/volo_vault.move (L896-940)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);
    assert!(vault_receipt.shares() >= shares, ERR_EXCEED_RECEIPT_SHARES);

    // Generate request id
    let current_request_id = self.request_buffer.withdraw_id_count;
    self.request_buffer.withdraw_id_count = current_request_id + 1;

    // Record this new request in Vault
    let new_request = withdraw_request::new(
        current_request_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        shares,
        expected_amount,
        clock.timestamp_ms(),
    );
    self.request_buffer.withdraw_requests.add(current_request_id, new_request);

    emit(WithdrawRequested {
        request_id: current_request_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        shares: shares,
        expected_amount: expected_amount,
    });

    vault_receipt.update_after_request_withdraw(shares, recipient);

    current_request_id
}
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

**File:** volo-vault/sources/volo_vault.move (L1174-1200)
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

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
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

**File:** volo-vault/sources/operation.move (L449-479)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let withdraw_request = vault.withdraw_request(request_id);
    reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

    let (withdraw_balance, recipient) = vault.execute_withdraw(
        clock,
        config,
        request_id,
        max_amount_received,
    );

    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
    }
}
```

**File:** volo-vault/tests/withdraw/withdraw.test.move (L2485-2540)
```text
        user_entry::withdraw(
            &mut vault,
            1_000_000_000,
            500_000_000,
            &mut receipt,
            &clock,
            s.ctx(),
        );

        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        s.return_to_sender(receipt);
    };

    // Request withdraw
    s.next_tx(ALICE);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();

        user_entry::withdraw(
            &mut vault,
            2_000_000_000,
            1_000_000_000,
            &mut receipt,
            &clock,
            s.ctx(),
        );

        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };

    // Check total usd value before execute withdraw
    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let total_usd_value = vault.get_total_usd_value(&clock);
        assert!(total_usd_value == 6_000_000_000);

        test_scenario::return_shared(vault);
    };

    // Batch execute withdraw
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();

        let request_ids = vector<u64>[0, 1];
        let max_amount_received = vector<u64>[500_000_000, 1_000_000_000];

```
