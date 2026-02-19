### Title
Protocol Fee Underpayment Due to Floor Division in Liquid Staking and Vault Fee Calculations

### Summary
The Volo protocol uses floor division (truncation) when calculating protocol fees for liquid staking rewards, vault deposits, and vault withdrawals. This causes systematic underpayment of fees where fractional amounts are lost to rounding, resulting in cumulative protocol revenue loss. The vulnerability class matches the external report's finding that fee calculations should round up (ceiling division) to prevent protocol losses.

### Finding Description

**Vulnerability Classification**: Pricing/fee/valuation underpayment - specifically fee calculation rounding direction causing systematic protocol losses.

**Root Cause**: Integer division in Move truncates (rounds down) by default. When calculating protocol fees as percentages, floor division causes the protocol to receive less than the intended fee amount whenever there is a fractional component.

**Affected Locations**:

1. **Liquid Staking Reward Fee** - `liquid_staking/sources/fee_config.move`: [1](#0-0) 
   
   The `calculate_reward_fee()` function uses floor division at line 96: `/ BPS_MULTIPLIER` without the `+ 9999` adjustment used in other fee calculations in the same file. This is inconsistent with `calculate_stake_fee()` and `calculate_unstake_fee()` which properly use ceiling division. [2](#0-1) [3](#0-2) 

2. **Liquid Staking Reward Fee (Inline Implementation)** - `liquid_staking/sources/stake_pool.move`: [4](#0-3) 
   
   The `refresh()` function recalculates reward fees inline using floor division at line 520, bypassing the fee_config module's function entirely.

3. **Vault Deposit Fee** - `volo-vault/sources/volo_vault.move`: [5](#0-4) 
   
   Line 830 calculates deposit fees using floor division: `coin_amount * self.deposit_fee_rate / RATE_SCALING`.

4. **Vault Withdraw Fee** - `volo-vault/sources/volo_vault.move`: [6](#0-5) 
   
   Line 1040 calculates withdrawal fees using floor division: `amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING`.

**Why Protections Fail**: There are no protections against this issue. The code uses standard integer division which inherently rounds down. Unlike the stake/unstake fees in `fee_config.move` which add `9999` before division to achieve ceiling behavior, these calculations lack this adjustment.

**Exploit Path**:
- **Liquid Staking**: Any call to `stake_entry()`, `unstake_entry()`, or `rebalance()` triggers `refresh()` which calculates reward fees [7](#0-6) 
  
- **Vault Deposit**: Users call `deposit()` or `deposit_with_auto_transfer()`, operator calls `execute_deposit()` [8](#0-7) 
  
- **Vault Withdraw**: Users submit withdraw requests, operator calls `execute_withdraw()` [9](#0-8) 

### Impact Explanation

**Concrete Financial Impact**: Each fee calculation loses up to 1 unit (1 MIST for SUI, or smallest decimal unit for other tokens) per transaction when fractional amounts exist. 

**Scale of Loss**:
- **Liquid Staking**: Loss occurs every epoch (24 hours) when staking rewards are processed. With typical reward_fee_bps of 1000 (10%) and rewards in the millions of MIST, each epoch loses a fractional fee.
- **Vault Operations**: Loss occurs on every deposit and withdrawal. With typical fees of 10bp (0.1%) and transaction volumes potentially in the thousands per day, cumulative losses compound quickly.

**Example Calculation** (Liquid Staking Reward Fee):
- Reward amount: 1,234,567 MIST
- Reward fee (10%): Should be 123,456.7 MIST
- Floor division gives: 123,456 MIST (0.7 MIST lost)
- Ceiling division would give: 123,457 MIST

While individual losses appear small, they represent systematic protocol revenue reduction that accumulates across all transactions and epochs.

### Likelihood Explanation

**Likelihood: HIGH** - This vulnerability triggers automatically during normal protocol operations:

1. **Liquid Staking Reward Fees**: Triggered every epoch (every 24 hours) automatically when anyone calls stake, unstake, or rebalance operations. No special conditions required. [10](#0-9) 

2. **Vault Deposit Fees**: Triggered on every user deposit execution. Users can freely call deposit functions. [11](#0-10) 

3. **Vault Withdraw Fees**: Triggered on every user withdrawal execution.

**Preconditions**: None - these are normal user operations with no special requirements beyond standard protocol usage.

**Blocked by Existing Checks**: No existing checks prevent this rounding behavior. It is inherent to integer division.

### Recommendation

**Specific Code-Level Mitigations**:

1. **For `liquid_staking/sources/fee_config.move` line 96**, change:
   ```
   / BPS_MULTIPLIER
   ```
   to:
   ```
   + (BPS_MULTIPLIER - 1)) / BPS_MULTIPLIER
   ```
   This matches the pattern used in `calculate_stake_fee()` and `calculate_unstake_fee()`.

2. **For `liquid_staking/sources/stake_pool.move` lines 517-520**, either:
   - Use `fee_config.calculate_reward_fee()` after fixing it, OR
   - Apply ceiling division: `((reward * fee_bps + 9999) / 10_000)`

3. **For `volo-vault/sources/volo_vault.move` line 830**, change:
   ```
   let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;
   ```
   to:
   ```
   let deposit_fee = (coin_amount * self.deposit_fee_rate + RATE_SCALING - 1) / RATE_SCALING;
   ```

4. **For `volo-vault/sources/volo_vault.move` line 1040**, change:
   ```
   let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
   ```
   to:
   ```
   let fee_amount = (amount_to_withdraw * self.withdraw_fee_rate + RATE_SCALING - 1) / RATE_SCALING;
   ```

### Proof of Concept

**Scenario 1: Liquid Staking Reward Fee Loss**
1. Initial state: StakePool has 100,000 SUI staked, epoch rolls over with 1,234,567 MIST rewards
2. Admin sets `reward_fee_bps = 1000` (10%)
3. User calls `stake_entry()` which triggers `refresh()`
4. Calculation: `(1,234,567 * 1000) / 10,000 = 123,456` (floor division)
5. Protocol receives: 123,456 MIST
6. Expected with ceiling: `(1,234,567 * 1000 + 9999) / 10,000 = 123,457` MIST
7. **Loss: 1 MIST per epoch**

**Scenario 2: Vault Deposit Fee Loss**
1. User deposits 10,000,000 principal tokens
2. Vault has `deposit_fee_rate = 10` (10bp = 0.1%)
3. User calls `deposit()`, operator calls `execute_deposit()`
4. Calculation: `(10,000,000 * 10) / 10,000 = 10,000` (floor division)
5. Protocol receives: 10,000 tokens
6. Expected with ceiling: `(10,000,000 * 10 + 9999) / 10,000 = 10,000` tokens (in this case no loss)
7. With amount 10,000,001: floor gives 10,000, ceiling gives 10,001
8. **Loss: Up to 1 token per deposit with fractional fees**

**Scenario 3: Vault Withdraw Fee Loss**
1. User withdraws 5,555,555 tokens
2. Vault has `withdraw_fee_rate = 10` (10bp = 0.1%)
3. User submits withdraw request, operator calls `execute_withdraw()`
4. Calculation: `(5,555,555 * 10) / 10,000 = 5,555` (floor division)
5. Protocol receives: 5,555 tokens
6. Expected with ceiling: `(5,555,555 * 10 + 9999) / 10,000 = 5,556` tokens
7. **Loss: 1 token per withdrawal**

### Notes

The Suilend lending protocol dependency correctly implements ceiling division for borrow fees at line 453 of `reserve.move`, demonstrating awareness of this issue in third-party code but inconsistent application in Volo's own modules. [12](#0-11)

### Citations

**File:** liquid_staking/sources/fee_config.move (L74-81)
```text
    public(package) fun calculate_stake_fee(self: &FeeConfig, sui_amount: u64): u64 {
        if (self.stake_fee_bps == 0) {
            return 0
        };

        // ceil(sui_amount * sui_stake_fee_bps / 10_000)
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```

**File:** liquid_staking/sources/fee_config.move (L83-90)
```text
    public(package) fun calculate_unstake_fee(self: &FeeConfig, sui_amount: u64): u64 {
        if (self.unstake_fee_bps == 0) {
            return 0
        };

        // ceil(sui_amount * unstake_fee_bps / 10_000)
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```

**File:** liquid_staking/sources/fee_config.move (L92-101)
```text
    public(package) fun calculate_reward_fee(self: &FeeConfig, before_balance: u64, after_balance: u64): u64 {
        let reward_fee = if (after_balance > before_balance) {
                ((after_balance - before_balance) as u128) 
                * (self.reward_fee_bps() as u128)
                / BPS_MULTIPLIER
            } else {
                0
            };
        reward_fee as u64
    }
```

**File:** liquid_staking/sources/stake_pool.move (L219-265)
```text
    public fun stake(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ): Coin<CERT> {
        self.manage.check_version();
        self.manage.check_not_paused();

        self.refresh(metadata,system_state, ctx);
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let mut sui_balance = sui.into_balance();
        let sui_amount_in = sui_balance.value();

        // deduct fees
        let mint_fee_amount = self.fee_config.calculate_stake_fee(sui_balance.value());
        self.fees.join(sui_balance.split(mint_fee_amount));
        
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
        assert!(lst_mint_amount > 0, EZeroMintAmount);

        emit(StakeEventExt {
            sui_amount_in,
            lst_amount_out: lst_mint_amount,
            fee_amount: mint_fee_amount
        });

        emit_staked(ctx.sender(), sui_amount_in, lst_mint_amount);

        let lst = metadata.mint(lst_mint_amount, ctx);

        // invariant: lst_out / sui_in <= old_lst_supply / old_sui_supply
        // -> lst_out * old_sui_supply <= sui_in * old_lst_supply
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );

        self.join_to_sui_pool(sui_balance);
        lst
    }
```

**File:** liquid_staking/sources/stake_pool.move (L503-550)
```text
    public fun refresh(
        self: &mut StakePool, 
        metadata: &Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        ctx: &mut TxContext
    ): bool {
        self.manage.check_version();
        self.manage.check_not_paused();

        let old_total_supply = self.total_sui_supply();

        if (self.validator_pool.refresh(system_state, ctx)) { // epoch rolled over
            let new_total_supply = self.total_sui_supply();

            let reward_fee = if (new_total_supply > old_total_supply) {
                (((new_total_supply - old_total_supply) as u128) 
                * (self.fee_config.reward_fee_bps() as u128) 
                / (BPS_MULTIPLIER as u128)) as u64
            } else {
                0
            };

            self.accrued_reward_fees = self.accrued_reward_fees + reward_fee;

            let mut boosted_reward_amount = self.boosted_reward_amount;

            if (new_total_supply > old_total_supply) {
                // boosted_reward_amount = min(new_reward, boosted_balance, set_reward_amount)
                boosted_reward_amount = boosted_reward_amount.min(new_total_supply - old_total_supply).min(self.boosted_balance.value());
                let boosted_reward = self.boosted_balance.split(boosted_reward_amount);
                self.join_to_sui_pool(boosted_reward);
            } else {
                boosted_reward_amount = 0;
            };

            emit(EpochChangedEvent {
                old_sui_supply: old_total_supply,
                new_sui_supply: new_total_supply,
                boosted_reward_amount: boosted_reward_amount,
                lst_supply: total_lst_supply(metadata),
                reward_fee
            });

            return true
        };

        false
    }
```

**File:** volo-vault/sources/volo_vault.move (L820-850)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1030-1060)
```text
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L449-454)
```text
    public fun calculate_borrow_fee<P>(
        reserve: &Reserve<P>,
        borrow_amount: u64
    ): u64 {
        ceil(mul(decimal::from(borrow_amount), borrow_fee(config(reserve))))
    }
```
