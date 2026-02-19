### Title
Denial of Service in Vault Operations Due to Unbounded Asset Type Iterations Exceeding Sui Dynamic Field Access Limit

### Summary
The Volo vault system contains an analogous vulnerability to the external report where unbounded loops over dynamic field accesses can cause denial-of-service. The `get_total_usd_value` function iterates over all asset types in the vault with multiple table accesses per iteration, and this function is called multiple times during critical operations like deposits and withdrawals. With no enforced limit on the number of asset types, the vault can reach Sui's 1,000 dynamic field access limit per transaction, rendering all deposit and withdraw operations inoperable and locking user funds in pending request states.

### Finding Description

The vulnerability exists in the `get_total_usd_value` function which is central to the vault's share calculation mechanism: [1](#0-0) 

This function loops over the entire `asset_types` vector and performs two table accesses per asset type:
1. `self.assets_value_updated.borrow(*asset_type)` - accesses the update timestamp table
2. `self.assets_value.borrow(*asset_type)` - accesses the USD value table

**Critical Execution Paths:**

During deposit execution, `get_total_usd_value` is called THREE times: [2](#0-1) 

Line 820 calls `get_total_usd_value` directly, line 821 calls `get_share_ratio` which internally calls `get_total_usd_value`: [3](#0-2) 

And line 841 calls `get_total_usd_value` again. This results in 3 × N × 2 = 6N table accesses per deposit, where N is the number of asset types.

**Root Cause - No Asset Limit:**

Assets are added via `set_new_asset_type` which has no enforcement of maximum asset count: [4](#0-3) 

Line 1364 pushes to the `asset_types` vector unboundedly. This function is called by both: [5](#0-4) 

And: [6](#0-5) 

**Exploit Calculation:**

With N asset types:
- Each deposit execution: 6N table accesses (dynamic field accesses on Sui)
- Sui enforces a maximum of 1,000 dynamic field accesses per transaction
- Therefore: 6N ≤ 1,000 → N ≤ 166.67
- With 167 or more asset types, all deposit operations fail with transaction limit exceeded

The same issue affects withdrawals which also call `get_share_ratio`: [7](#0-6) 

And operation value updates: [8](#0-7) 

### Impact Explanation

**Severity: CRITICAL**

Once the vault accumulates approximately 167+ asset types, the protocol enters a permanent denial-of-service state where:

1. **All deposit executions fail** - Operators cannot execute pending deposit requests, leaving user funds locked in the request buffer with no way to retrieve them except cancellation (which users must wait for locking period)

2. **All withdrawal executions fail** - Users cannot withdraw their vault shares, effectively locking all deposited capital

3. **All DeFi operations fail** - The `end_op_value_update_with_bag` function also calls `get_total_usd_value`, so operators cannot complete any DeFi strategy operations, freezing the vault's operational capability

4. **Irreversible without emergency measures** - Once assets are added to reach this threshold, there is no standard mechanism to remove them in bulk. Asset removal requires the vault to be in NORMAL status, but operations may leave it stuck in DURING_OPERATION status

This represents a complete protocol freeze affecting all users and all deposited capital in the affected vault.

### Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to manifest through natural protocol growth:

1. **Operator-Controlled Addition**: Assets are added by operators via capability-protected functions, but operators are expected to add diverse asset types as the protocol expands to support more DeFi strategies (Navi, Cetus, Suilend, Momentum positions, various coin types, receipts, etc.)

2. **No Warning System**: There is no on-chain check or warning when approaching the dangerous threshold. Operators adding the 167th asset type would unknowingly trigger the DoS

3. **Realistic Growth Path**: 
   - Principal coin type: 1 asset
   - Multiple stablecoin types (USDC, USDT, DAI, etc.): ~5-10 assets
   - Multiple DeFi protocol positions (each protocol × each pool): easily 50+ assets
   - Multiple receipt types: 20+ assets
   - As protocol expands to support more strategies: 100+ additional assets

4. **Preconditions Easily Met**: No attacker action required - normal protocol expansion naturally leads to this state. The operator capability is held by trusted operators, but they operate under the assumption that adding assets is safe protocol behavior

5. **Permanent Effect**: Once triggered, affects ALL users attempting deposits/withdrawals, not just specific transactions

### Recommendation

**Immediate Mitigation:**

1. **Implement Maximum Asset Type Limit**: Add a constant defining maximum allowed asset types (e.g., 100) and enforce it in `set_new_asset_type`:

```move
const MAX_ASSET_TYPES: u64 = 100; // Safe limit: 100 * 6 = 600 accesses per deposit

public(package) fun set_new_asset_type<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
) {
    self.check_version();
    self.assert_enabled();
    
    // Add limit check
    assert!(self.asset_types.length() < MAX_ASSET_TYPES, ERR_ASSET_LIMIT_EXCEEDED);
    
    assert!(!self.asset_types.contains(&asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);
    self.asset_types.push_back(asset_type);
    // ... rest of function
}
```

2. **Optimize Value Calculation**: Consider caching the total USD value and only recalculating when asset values are updated, rather than iterating over all assets multiple times per operation:

```move
struct Vault<phantom T> {
    // ... existing fields ...
    cached_total_usd_value: u256,
    cached_value_timestamp: u64,
    // ...
}
```

3. **Batch Asset Value Updates**: Allow asset values to be updated in batches to avoid the multiple calls to `get_total_usd_value` during deposits

**Long-term Solution:**

Refactor the asset value calculation to use an incremental approach where the total USD value is maintained as a running sum that gets updated when individual asset values change, rather than being recalculated from scratch by iterating over all assets.

### Proof of Concept

**Setup:**
1. Deploy a Vault with initial asset type (principal coin)
2. Operator adds 166 additional asset types via `add_new_coin_type_asset` and `add_new_defi_asset` calls
3. Total asset types = 167

**Execution:**
1. User calls `request_deposit` with 1000 USDC (succeeds)
2. Operator attempts to call `execute_deposit` for the pending request

**Result:**
- Transaction fails with "dynamic field access limit exceeded" error
- Calculation: 167 assets × 6 accesses per deposit = 1,002 dynamic field accesses > 1,000 limit
- User's deposit remains locked in request buffer
- Same failure occurs for ALL subsequent deposit and withdrawal attempts
- Vault is effectively frozen with no standard recovery path

**Affected Code Paths:**
- `operation::execute_deposit` → `vault::execute_deposit` → `get_total_usd_value` (3x) = DoS
- `operation::execute_withdraw` → `vault::execute_withdraw` → `get_share_ratio` → `get_total_usd_value` = DoS  
- `operation::end_op_value_update_with_bag` → `vault::get_total_usd_value` = DoS

The DoS is deterministic and reproducible once the asset count threshold is crossed.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L994-1050)
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

**File:** volo-vault/sources/volo_vault.move (L1353-1372)
```text
public(package) fun set_new_asset_type<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    // assert!(!self.assets.contains(asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);
    assert!(!self.asset_types.contains(&asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);

    self.asset_types.push_back(asset_type);
    self.assets_value.add(asset_type, 0);
    self.assets_value_updated.add(asset_type, 0);

    emit(NewAssetTypeAdded {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```

**File:** volo-vault/sources/volo_vault.move (L1461-1476)
```text
public(package) fun add_new_coin_type_asset<PrincipalCoinType, AssetType>(
    self: &mut Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_normal();
    assert!(
        type_name::get<AssetType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<AssetType>().into_string();
    set_new_asset_type(self, asset_type);

    // Add the asset to the assets table (initial as 0 balance)
    self.assets.add(asset_type, balance::zero<AssetType>());
}
```

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
