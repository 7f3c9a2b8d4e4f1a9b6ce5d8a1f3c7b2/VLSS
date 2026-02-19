### Title
Arithmetic Overflow in Fee Calculations Causing Deposit/Withdraw DoS

### Summary
The volo-vault module contains an arithmetic overflow vulnerability in fee calculations that mirrors the external report's pattern. When users deposit or withdraw large amounts, the fee calculation performs u64 * u64 multiplication without casting to u128, causing transaction aborts and protocol DoS. This is analogous to the external `node_capacity * n_shards` overflow vulnerability.

### Finding Description

The vulnerability exists in two critical fee calculation paths within the volo-vault module:

**Deposit Fee Calculation:** [1](#0-0) 

The deposit fee is calculated as `coin_amount * self.deposit_fee_rate / RATE_SCALING` where all operands are u64 types. [2](#0-1) 

**Withdraw Fee Calculation:** [3](#0-2) 

The withdraw fee uses identical arithmetic: `amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING`.

**Fee Rate Bounds:** [4](#0-3) 

Maximum fee rates are capped at 500 (5%), but this still allows overflow.

**Root Cause:** Both calculations multiply two u64 values without intermediate u128 casting. When `coin_amount` or `amount_to_withdraw` exceeds approximately `u64::MAX / 500 = 36,893,488,147,419,103`, the multiplication overflows and the transaction aborts.

**Exploit Path:**
1. User calls deposit via [5](#0-4)  with only a minimum amount check [6](#0-5) 
2. Operator executes deposit via [7](#0-6) 
3. Fee calculation at line 830 overflows
4. Transaction aborts, preventing deposits above threshold

**Why Protections Fail:** No upper bound validation exists on deposit amounts. The only check is `amount > 0`. Fee rate validation [8](#0-7)  only limits rates, not amounts.

**Correct Pattern in Codebase:** The liquid_staking module demonstrates the correct approach [9](#0-8)  by casting to u128 before multiplication, then casting result back to u64.

### Impact Explanation

**Severity: Medium-High**

**Concrete Impacts:**
1. **Protocol DoS:** Users cannot deposit or withdraw amounts exceeding the overflow threshold (~36.9M SUI equivalent)
2. **Availability Degradation:** High-value users or institutional deposits are blocked
3. **Cross-Asset Risk:** Tokens with different decimal schemes or price ratios may hit threshold more easily
4. **Accumulated Position Risk:** Users with large accumulated positions cannot withdraw

**Financial Impact:** While no direct fund loss occurs, the protocol becomes unusable for high-value operations, effectively locking large positions and preventing institutional adoption.

### Likelihood Explanation

**Likelihood: Medium**

**Realistic Trigger Conditions:**
1. **Feasible Deposit Amounts:** For SUI (9 decimals), threshold is 36.9M SUI. While high for individual deposits, this is achievable for:
   - Institutional investors
   - Treasury operations
   - Accumulated vault positions over time
   - Tokens with higher decimal places or different pricing

2. **No Admin Key Required:** Any user can trigger by depositing/withdrawing large amounts

3. **Preconditions Met:**
   - User has sufficient funds (realistic for whales/institutions)
   - Vault accepts the principal coin type
   - Fee rates are set (always true, defaults to 10bp)

4. **Executable Path:** Direct public entry via `user_entry::deposit()` → `vault.request_deposit()` → operator `execute_deposit()` → overflow abort

### Recommendation

Apply the same pattern used in liquid_staking module. Cast operands to u128 before multiplication:

**For deposit fee calculation (line 830):**
```move
let deposit_fee = (((coin_amount as u128) * (self.deposit_fee_rate as u128)) / (RATE_SCALING as u128)) as u64;
```

**For withdraw fee calculation (line 1040):**
```move
let fee_amount = (((amount_to_withdraw as u128) * (self.withdraw_fee_rate as u128)) / (RATE_SCALING as u128)) as u64;
```

This matches the proven safe pattern at [10](#0-9)  and [11](#0-10) 

### Proof of Concept

**Setup:**
1. Deploy volo-vault with SUI as principal coin type
2. Set deposit_fee_rate to maximum allowed (500 = 5%)
3. User has balance of 40,000,000,000,000,000 (40M SUI)

**Execution:**
1. User calls `deposit()` with `amount = 37,000,000,000,000,000` (37M SUI)
2. Request created successfully in `request_deposit()`
3. Operator calls `execute_deposit()`
4. At line 830: `37,000,000,000,000,000 * 500 = 18,500,000,000,000,000,000`
5. Result exceeds u64::MAX (18,446,744,073,709,551,615)
6. **Transaction aborts with arithmetic overflow**
7. Deposit request remains in buffer, user funds locked in buffered coin
8. Same scenario applies to withdrawals exceeding threshold

**Impact Demonstrated:** Protocol cannot process legitimate high-value deposits/withdrawals, causing operational DoS identical to the external report's overflow pattern.

### Citations

**File:** volo-vault/sources/volo_vault.move (L28-33)
```text
const RATE_SCALING: u64 = 10_000;

const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L110-111)
```text
    deposit_fee_rate: u64,
    withdraw_fee_rate: u64,
```

**File:** volo-vault/sources/volo_vault.move (L497-516)
```text
public(package) fun set_deposit_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_DEPOSIT_FEE_RATE, ERR_EXCEED_LIMIT);
    self.deposit_fee_rate = fee;
    emit(DepositFeeChanged { vault_id: self.vault_id(), fee: fee })
}

// Set the withdraw fee rate for the vault
public(package) fun set_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_WITHDRAW_FEE_RATE, ERR_EXCEED_LIMIT);
    self.withdraw_fee_rate = fee;
    emit(WithdrawFeeChanged { vault_id: self.vault_id(), fee: fee })
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

**File:** volo-vault/sources/volo_vault.move (L1040-1040)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/user_entry.move (L19-61)
```text
public fun deposit<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    mut coin: Coin<PrincipalCoinType>,
    amount: u64,
    expected_shares: u256,
    mut original_receipt: Option<Receipt>,
    clock: &Clock,
    ctx: &mut TxContext,
): (u64, Receipt, Coin<PrincipalCoinType>) {
    assert!(amount > 0, ERR_INVALID_AMOUNT);
    assert!(coin.value() >= amount, ERR_INSUFFICIENT_BALANCE);
    assert!(vault.vault_id() == reward_manager.vault_id(), ERR_VAULT_ID_MISMATCH);

    // Split the coin and request a deposit
    let split_coin = coin.split(amount, ctx);

    // Update receipt info (extract from Option<Receipt>)
    let ret_receipt = if (!option::is_some(&original_receipt)) {
        reward_manager.issue_receipt(ctx)
    } else {
        original_receipt.extract()
    };
    original_receipt.destroy_none();

    vault.assert_vault_receipt_matched(&ret_receipt);

    // If there is no receipt before, create a new vault receipt info record in vault
    let receipt_id = ret_receipt.receipt_id();
    if (!vault.contains_vault_receipt_info(receipt_id)) {
        vault.add_vault_receipt_info(receipt_id, reward_manager.issue_vault_receipt_info(ctx));
    };

    let request_id = vault.request_deposit(
        split_coin,
        clock,
        expected_shares,
        receipt_id,
        ctx.sender(),
    );

    (request_id, ret_receipt, coin)
}
```

**File:** liquid_staking/sources/stake_pool.move (L518-520)
```text
                (((new_total_supply - old_total_supply) as u128) 
                * (self.fee_config.reward_fee_bps() as u128) 
                / (BPS_MULTIPLIER as u128)) as u64
```

**File:** liquid_staking/sources/fee_config.move (L79-80)
```text
        // ceil(sui_amount * sui_stake_fee_bps / 10_000)
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
```

**File:** liquid_staking/sources/fee_config.move (L88-89)
```text
        // ceil(sui_amount * unstake_fee_bps / 10_000)
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
```
