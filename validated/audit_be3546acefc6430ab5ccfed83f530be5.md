### Title
Insolvent Lending Position Returns Zero Value, Masking Losses and Inflating Vault Share Ratio

### Summary
The Navi and Suilend adaptors incorrectly return 0 when lending positions become underwater (borrows exceed deposits), instead of properly handling the insolvency. This masks actual losses from vault accounting, inflates the total USD value calculation, corrupts the share ratio, bypasses loss tolerance checks, and allows users to withdraw more principal than they should receive.

### Finding Description

The external vulnerability involves an improper threshold check that returns 0 when a calculated value falls below a comparison threshold, unnecessarily reducing the legitimate calculated amount. The Volo analog manifests in the lending position adaptors.

**Root Cause in Volo:**

Both lending adaptors contain identical flawed logic when calculating position net value: [1](#0-0) [2](#0-1) 

When a lending position becomes insolvent (total borrowed value exceeds total supplied collateral value), instead of reverting the transaction or properly recording the negative equity, the adaptors return 0. This value is then stored in the vault's asset accounting: [3](#0-2) 

**Exploit Path:**

1. **Normal Operations**: Vault operator borrows Navi or Suilend lending positions during operations to deploy capital into lending protocols

2. **Position Becomes Underwater**: Due to market volatility, oracle price changes, or liquidation failures, the position's borrowed amount exceeds deposited collateral (total_borrow_usd > total_supply_usd)

3. **Value Update Call**: When the operator calls `update_navi_position_value` or `update_suilend_position_value`, the adaptor calculates the net position but incorrectly returns 0 instead of handling the insolvency

4. **Vault Accounting Corruption**: The 0 value is stored in the vault's `assets_value` table, omitting the actual loss from total calculations: [4](#0-3) 

5. **Share Ratio Inflation**: The inflated total USD value artificially increases the share ratio calculation: [5](#0-4) 

6. **Loss Tolerance Bypass**: The operation's loss tolerance check uses the corrupted total value, understating or completely missing the actual loss: [6](#0-5) 

7. **Withdrawal at Inflated Value**: Users withdraw based on the inflated share ratio, receiving more principal than their fair share: [7](#0-6) 

**Why Current Protections Fail:**

The health limiter checks health factor but does not prevent the adaptor from reporting 0: [8](#0-7) 

The health check is optional and separate from value reporting—an insolvent position can still report 0 value to the vault even if health checks are performed elsewhere.

### Impact Explanation

**Critical Severity with Multiple Impact Vectors:**

1. **Fund Drain**: Users can withdraw more principal than entitled because the share ratio doesn't reflect actual losses. Early withdrawers profit while later users absorb hidden losses.

2. **Accounting Corruption**: The vault's core invariant (`total_usd_value = sum(all_asset_values)`) is violated. The reported total value is artificially inflated by the amount of underwater positions.

3. **Loss Tolerance Bypass**: The per-epoch loss limit (`loss_tolerance`) is designed to prevent excessive losses per operation. By reporting 0 instead of negative values, actual losses are not counted against the tolerance, allowing unbounded losses to accumulate.

4. **Unfair Distribution**: The fundamental share-based accounting is corrupted—users' withdrawal amounts no longer correspond to their proportional ownership of vault assets.

### Likelihood Explanation

**High Likelihood - Realistic and Unblocked:**

1. **Realistic Market Conditions**: Lending positions can easily become underwater through:
   - Rapid market downturns (borrower collateral value drops)
   - Oracle price lag or manipulation
   - Liquidation mechanism failures during high volatility
   - Interest rate accrual pushing borrow amounts above collateral value

2. **Normal Operation Flow**: Value updates are part of standard vault operations—operators regularly call `update_navi_position_value` and `update_suilend_position_value` to refresh asset valuations during operation lifecycles.

3. **No Circuit Breakers**: The code contains no checks to:
   - Detect when position net value is negative
   - Revert transactions when insolvency is detected
   - Flag insolvent positions for manual intervention
   - Require liquidation before value updates

4. **Observable Externally**: The vulnerability is triggered by on-chain market conditions visible to all actors. Any user can observe when lending positions become underwater and time their withdrawals accordingly.

5. **Operator Incentivized**: Operators have incentive to continue reporting 0 values to avoid triggering loss tolerance limits that would prevent operations.

### Recommendation

**Immediate Fix - Revert on Insolvency:**

Modify both adaptors to revert when positions are underwater instead of returning 0:

In `navi_adaptor.move` and `suilend_adaptor.move`, replace the return 0 logic with an assertion:

```rust
// Replace lines 74-76 in navi_adaptor.move
assert!(total_supply_usd_value >= total_borrow_usd_value, INSOLVENCY_ERROR);
total_supply_usd_value - total_borrow_usd_value

// Replace lines 85-87 in suilend_adaptor.move  
assert!(total_deposited_value_usd >= total_borrowed_value_usd, INSOLVENCY_ERROR);
(total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
```

**Additional Safeguards:**

1. Add mandatory health factor verification before value updates in adaptors
2. Implement circuit breaker to pause vault operations when any position becomes insolvent
3. Add grace period mechanism to allow liquidation before position value reporting fails
4. Log insolvency events for off-chain monitoring and intervention

### Proof of Concept

**Step 1 - Initial Setup:**
- Vault has 1,000,000 USDC total value, 1,000,000 shares (1:1 ratio)
- User A holds 500,000 shares (50% ownership)
- Operator deploys 600,000 USDC to Navi lending: supplies 600,000 USDC, borrows 400,000 USDC worth of other assets

**Step 2 - Position Becomes Underwater:**
- Market crashes: borrowed asset value increases to 700,000 USDC
- Navi position is now underwater: 600,000 supply - 700,000 borrow = -100,000 USDC net value
- Actual vault total value: 400,000 free principal + (-100,000) Navi = 300,000 USDC

**Step 3 - Value Update Returns Zero:**
- Operator calls `update_navi_position_value`
- Adaptor calculates: `total_supply_usd_value (600,000) < total_borrow_usd_value (700,000)`
- Instead of recording -100,000 loss, returns 0
- Vault records: 400,000 free principal + 0 Navi = 400,000 USDC (inflated by 100,000)

**Step 4 - Share Ratio Inflated:**
- Share ratio becomes: 400,000 / 1,000,000 = 0.4 USD per share
- True ratio should be: 300,000 / 1,000,000 = 0.3 USD per share

**Step 5 - Loss Tolerance Bypassed:**
- Operation checks show 400,000 after vs 1,000,000 before = 600,000 loss
- Without the 0-return bug, would show: 300,000 after vs 1,000,000 before = 700,000 loss
- If loss tolerance is 60% (600,000), the operation passes when it should fail

**Step 6 - User A Withdraws at Inflated Value:**
- User A requests withdrawal of all 500,000 shares
- Receives: 500,000 shares × 0.4 = 200,000 USDC
- Should receive: 500,000 shares × 0.3 = 150,000 USDC
- User A extracts 50,000 USDC excess (50% of the hidden loss)

**Step 7 - Remaining Users Bear Full Loss:**
- Vault has 200,000 USDC free principal remaining
- Remaining 500,000 shares now backed by only 100,000 actual value (after accounting for -100,000 Navi position)
- Loss ratio: 0.2 USD per share instead of 0.3
- Remaining users lost additional value because User A withdrew at inflated ratio

This demonstrates fund drain, accounting corruption, and loss socialization to users who don't withdraw early.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L85-87)
```text
    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-49)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);

    emit(NaviHealthFactorVerified {
        account,
        health_factor,
        safe_check_hf: min_health_factor,
    });

    let is_healthy = health_factor > min_health_factor;

    // hf_normalized has 9 decimals
    // e.g. hf = 123456 (123456 * 1e27)
    //      hf_normalized = 123456 * 1e9
    //      hf = 0.5 (5 * 1e26)
    //      hf_normalized = 5 * 1e8 = 0.5 * 1e9
    //      hf = 1.356 (1.356 * 1e27)
    //      hf_normalized = 1.356 * 1e9
    let mut hf_normalized = health_factor / DECIMAL_E18;

    if (hf_normalized > DECIMAL_E9) {
        hf_normalized = DECIMAL_E9;
    };

    assert!(is_healthy, hf_normalized as u64);
}
```
