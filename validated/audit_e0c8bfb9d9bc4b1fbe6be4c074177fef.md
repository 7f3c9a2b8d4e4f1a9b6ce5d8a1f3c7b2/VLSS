### Title
Event Emission Discrepancies in Deposit Operations - Incorrect Amount Logging

### Summary
Both the liquid staking and vault deposit functions emit events with user-provided amounts (including fees) instead of the actual amounts deposited into the protocol (after fee deduction). This mirrors the external vulnerability where events logged initial input values rather than the actual processed amounts, causing off-chain systems to track inflated deposit totals and creating accounting discrepancies.

### Finding Description

The external report identified events emitting user-provided amounts instead of actual processed amounts. Volo exhibits the same vulnerability class in two critical deposit flows:

**1. Liquid Staking Deposit (`stake_pool.move`)**

In the `stake` function, the flow is:
- User provides SUI coin (e.g., 100 SUI) [1](#0-0) 
- Deposit fee is calculated and deducted from the balance (e.g., 1 SUI fee) [2](#0-1) 
- LST amount is calculated based on remaining balance after fee (99 SUI) [3](#0-2) 
- The `StakedEvent` is emitted with the **original** `sui_amount_in` (100 SUI) [4](#0-3) 
- Only the remaining balance (99 SUI) is joined to the pool [5](#0-4) 

The event should emit `sui_balance.value()` (actual deposited amount after fee) instead of `sui_amount_in` (original amount including fee).

**2. Volo Vault Deposit (`volo_vault.move`)**

In the `execute_deposit` function:
- Original coin amount from request is retrieved (e.g., 1000 USDC) [6](#0-5) 
- Deposit fee is calculated and split from the balance [7](#0-6) 
- The remaining balance (after fee) is joined to `free_principal` [8](#0-7) 
- The `DepositExecuted` event emits `amount: coin_amount` (original amount **including** fee) [9](#0-8) 

The event should emit `coin_amount - deposit_fee` (actual deposited amount) instead of `coin_amount` (original amount including fee).

### Impact Explanation

**Concrete Protocol Impact:**

1. **Off-chain Accounting Corruption**: Indexers tracking total deposits will overcount by the cumulative fee amounts, creating persistent discrepancies between on-chain state and off-chain records.

2. **Analytics/Dashboard Misrepresentation**: Historical deposit volume charts and statistics will show inflated values, misleading users and investors about actual protocol TVL growth.

3. **Auditing Failures**: Third-party auditors or analytics platforms reconciling events with on-chain balances will detect mismatches, potentially flagging false accounting issues.

4. **User Confusion**: Users checking their transaction history via events will see their full deposit amount (including fee) without clear indication that fees were deducted, leading to support inquiries and trust issues.

The severity is **Medium** because while funds are not lost or stolen, the protocol's data integrity is compromised, affecting trust, reporting, and off-chain system reliability.

### Likelihood Explanation

**Guaranteed Exploitation:**

1. **Every Deposit Triggers**: The discrepancy occurs on every single deposit operation - both `stake` in liquid staking and `execute_deposit` in vault.

2. **No Special Conditions Required**: Any user with sufficient assets can trigger deposits following standard protocol flows.

3. **Persistent Over Time**: The accounting gap compounds with each deposit, creating larger cumulative discrepancies as protocol usage grows.

4. **Affects All Off-chain Consumers**: Any system listening to `StakedEvent` or `DepositExecuted` events will receive incorrect data - this includes official UIs, third-party analytics, portfolio trackers, and audit tools.

The likelihood is **100%** - this is not a potential vulnerability but an active discrepancy occurring in production on every deposit operation.

### Recommendation

**For Liquid Staking (`stake_pool.move`):**

Modify line 251 to emit the actual deposited amount after fee deduction:
```move
emit_staked(ctx.sender(), sui_balance.value(), lst_mint_amount);
```

Alternatively, capture the actual deposited amount before joining to pool:
```move
let actual_deposited = sui_balance.value();
self.join_to_sui_pool(sui_balance);
// ...
emit_staked(ctx.sender(), actual_deposited, lst_mint_amount);
```

**For Volo Vault (`volo_vault.move`):**

Modify the `DepositExecuted` event emission (line 855-862) to include the actual deposited amount:
```move
let actual_deposit_amount = coin_amount - deposit_fee;
emit(DepositExecuted {
    request_id: request_id,
    receipt_id: deposit_request.receipt_id(),
    recipient: deposit_request.recipient(),
    vault_id: self.id.to_address(),
    amount: actual_deposit_amount, // Use actual amount after fee
    shares: user_shares,
});
```

**Alternative**: Add a separate `fee_amount` field to both events (similar to `StakeEventExt`) so off-chain systems can calculate actual deposits while maintaining backward compatibility.

### Proof of Concept

**Scenario 1: Liquid Staking Deposit**

1. User calls `stake_entry` with 100 SUI
2. Stake fee rate is 10 bps (0.1%), so fee = 0.1 SUI
3. Actual deposited to pool: 99.9 SUI
4. LST minted based on 99.9 SUI
5. `StakedEvent` emits: `sui_amount: 100, cert_amount: X`
6. Off-chain indexer records: "User deposited 100 SUI"
7. **Reality**: Only 99.9 SUI entered the pool
8. **Discrepancy**: 0.1 SUI per deposit, compounds across all users

**Scenario 2: Vault Deposit**

1. User requests deposit of 1,000 USDC
2. Operator executes deposit, vault deposit fee rate is 10 bps (0.1%)
3. Deposit fee calculated: 1 USDC
4. Fee split to `deposit_withdraw_fee_collected`: 1 USDC
5. Actual added to `free_principal`: 999 USDC
6. `DepositExecuted` event emits: `amount: 1000`
7. Off-chain indexer records: "1000 USDC deposited to vault"
8. **Reality**: Only 999 USDC in vault's free_principal
9. **Discrepancy**: 1 USDC per 1000 deposited, accumulates over time

**Verification Path:**

Monitor on-chain events vs. actual balance changes:
- Track cumulative `StakedEvent.sui_amount` values
- Compare against actual `StakePool.validator_pool.total_sui_supply()`
- Discrepancy = cumulative fees collected
- Same pattern for vault: cumulative `DepositExecuted.amount` vs. actual vault balances

### Citations

**File:** liquid_staking/sources/stake_pool.move (L235-236)
```text
        let mut sui_balance = sui.into_balance();
        let sui_amount_in = sui_balance.value();
```

**File:** liquid_staking/sources/stake_pool.move (L239-240)
```text
        let mint_fee_amount = self.fee_config.calculate_stake_fee(sui_balance.value());
        self.fees.join(sui_balance.split(mint_fee_amount));
```

**File:** liquid_staking/sources/stake_pool.move (L242-242)
```text
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
```

**File:** liquid_staking/sources/stake_pool.move (L251-251)
```text
        emit_staked(ctx.sender(), sui_amount_in, lst_mint_amount);
```

**File:** liquid_staking/sources/stake_pool.move (L263-263)
```text
        self.join_to_sui_pool(sui_balance);
```

**File:** volo-vault/sources/volo_vault.move (L828-828)
```text
    let coin_amount = deposit_request.amount();
```

**File:** volo-vault/sources/volo_vault.move (L830-836)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L838-838)
```text
    self.free_principal.join(coin_balance);
```

**File:** volo-vault/sources/volo_vault.move (L855-862)
```text
    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });
```
