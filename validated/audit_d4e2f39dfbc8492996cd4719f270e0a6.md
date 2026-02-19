### Title
Missing Share Ratio Validation Allows Zero-Value Withdrawals Despite Burning Shares

### Summary
The Volo Vault withdrawal logic fails to validate that `share_ratio > 0` before calculating withdrawal amounts, analogous to the external report's missing `weight_ratio > 0` validation. When `total_usd_value == 0` but `total_shares > 0`, users receive zero tokens regardless of shares burned, breaking the fundamental invariant that shares represent proportional vault value.

### Finding Description

The external vulnerability class is **missing ratio validation in proportional amount calculations**, where invalid ratios cause `amountOut = 0` irrespective of `amountIn`.

**Volo Analog Surface:**

In `get_share_ratio`, the function only validates the denominator (`total_shares`) but not the numerator (`total_usd_value`): [1](#0-0) 

When `total_usd_value == 0` but `total_shares > 0`, the calculation `vault_utils::div_d(total_usd_value, self.total_shares)` returns `0 * DECIMALS / total_shares = 0`.

The mathematical utility performs division without validating the result is meaningful: [2](#0-1) 

**Exploit Path:**

In `execute_withdraw`, the zero ratio directly causes zero withdrawal amount: [3](#0-2) 

At line 1013, `usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio)` becomes `shares_to_withdraw * 0 / DECIMALS = 0`, resulting in `amount_to_withdraw = 0`.

**Why Protections Fail:**

The slippage check at line 1029 only verifies `amount_to_withdraw >= expected_amount`. If a user creates a withdraw request with `expected_amount = 0` (which has no validation), the check passes: [4](#0-3) 

No validation prevents `expected_amount = 0` in the request creation at line 901.

**Triggering Conditions:**

The vault's `total_usd_value` can become zero while shares exist through:
1. Oracle price reporting 0 for all assets (oracle failure/manipulation)
2. All asset values legitimately dropping to 0 (DeFi protocol exploit draining positions)
3. Assets borrowed during operations with stale value updates

The `get_total_usd_value` function sums asset values that could all be zero: [5](#0-4) 

### Impact Explanation

**Critical fund loss vulnerability:**
- Users who request withdrawals with `expected_amount = 0` successfully burn their shares but receive zero tokens
- Existing withdrawal requests with non-zero `expected_amount` become permanently unexecutable (DoS), as the check `0 >= expected_amount` fails
- All vault shares become effectively worthless when ratio drops to zero
- No recovery mechanism exists to restore share value once ratio crashes

This breaks the core vault invariant that shares represent proportional ownership of vault assets. The impact is complete loss of user funds held as vault shares.

### Likelihood Explanation

**Medium to High Likelihood:**

1. **Oracle Dependency:** Vault value depends on external oracle prices. Oracle failures/manipulations are documented attack vectors in DeFi (e.g., Synthetix oracle manipulation, Compound oracle failures).

2. **Legitimate Value Loss:** DeFi protocols have been exploited resulting in total position value loss (e.g., Suilend, Navi exploits would cause vault position values to drop to zero).

3. **No Protective Bounds:** Unlike the liquid staking module which has `MIN_STAKE_AMOUNT` checks preventing zero-value operations, the vault has no minimum share ratio validation.

4. **Reachable by Any User:** Any vault depositor can create withdrawal requests with arbitrary `expected_amount` values including zero.

The vulnerability is realistic and exploitable under documented DeFi failure modes without requiring admin compromise or impossible preconditions.

### Recommendation

**Add share ratio validation in `get_share_ratio`:**

```move
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
    
    // ADD THIS CHECK:
    assert!(total_usd_value > 0, ERR_ZERO_SHARE_RATIO);
    
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
    ...
}
```

**Additionally, add minimum expected amount validation in `request_withdraw`:**

```move
public(package) fun request_withdraw<PrincipalCoinType>(
    ...
    expected_amount: u64,
    ...
): u64 {
    ...
    // ADD THIS CHECK:
    assert!(expected_amount > MIN_WITHDRAW_AMOUNT, ERR_UNDER_MIN_AMOUNT);
    ...
}
```

This mirrors the external report's remediation: "Enforce the `weight_ratio > 0` constraint" by enforcing `share_ratio > 0` in Volo.

### Proof of Concept

**Setup:**
1. Vault has `total_shares = 1000` and `total_usd_value = 1000` (normal operation)
2. Alice deposits 100 tokens, receives 100 shares
3. Oracle failure causes all asset prices to report 0, or DeFi protocol exploit drains all positions
4. Vault now has `total_shares = 1100` but `total_usd_value = 0`

**Execution:**
1. Alice calls `request_withdraw(receipt_id, shares=100, expected_amount=0, recipient=alice)`
   - No validation blocks `expected_amount = 0`
   - Request created successfully

2. Operator calls `execute_withdraw(vault, clock, config, request_id, max_amount_received=0)`
   - Line 1006: `ratio = get_share_ratio() = 0 / 1100 = 0`
   - Line 1013: `usd_value_to_withdraw = mul_d(100, 0) = 100 * 0 / DECIMALS = 0`
   - Line 1014-1022: `amount_to_withdraw = 0 / price = 0`
   - Line 1029: `assert!(0 >= 0)` ✓ passes
   - Line 1030: `assert!(0 <= 0)` ✓ passes
   - Line 1033: Burns Alice's 100 shares
   - Line 1037: Returns `Balance<T>` with value 0

**Result:** Alice burns 100 shares, receives 0 tokens. The vulnerability is identical to the external report's `amountOut = 0` irrespective of `amountIn`.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L1005-1023)
```text
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

**File:** volo-vault/sources/utils.move (L22-30)
```text
// mul with decimals
public fun mul_d(v1: u256, v2: u256): u256 {
    v1 * v2 / DECIMALS
}

// div with decimals
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```
