### Title
Missing Claim Functionality During Vault Emergency Shutdown

### Summary
Users cannot claim their `claimable_principal` (withdrawn funds) or earned rewards when the Volo Vault is set to `DISABLED` status (emergency shutdown). This directly mirrors the external report where users cannot harvest rewards during emergency state, resulting in user funds being locked indefinitely during critical incidents.

### Finding Description

The Volo Vault system implements a three-state status model: `VAULT_NORMAL_STATUS` (0), `VAULT_DURING_OPERATION_STATUS` (1), and `VAULT_DISABLED_STATUS` (2). [1](#0-0) 

When administrators detect an emergency, they can disable the vault via `set_enabled()`, which sets the vault to `DISABLED` status. [2](#0-1) 

**Critical Issue 1: Claimable Principal Locked**

The `claim_claimable_principal()` function, which allows users to claim their withdrawn funds, requires `assert_normal()` check. [3](#0-2) 

The `assert_normal()` function enforces that the vault status must equal `VAULT_NORMAL_STATUS` (0), meaning it rejects both `DISABLED` (2) and `DURING_OPERATION` (1) states. [4](#0-3) 

**How claimable_principal accumulates:**
When users request withdrawals without auto-transfer (recipient = `address::from_u256(0)`), the operator executes the withdrawal and adds the funds to `claimable_principal` instead of immediately transferring them. [5](#0-4) 

The receipt's claimable_principal balance is tracked per user. [6](#0-5) 

**Critical Issue 2: Rewards Locked**

The `claim_reward()` function requires `assert_enabled()` check, which blocks claiming when the vault is `DISABLED`. [7](#0-6) 

The `assert_enabled()` function rejects `DISABLED` status. [8](#0-7) 

**Root Cause:**
Both critical user fund recovery operations (`claim_claimable_principal` and `claim_reward`) are blocked during emergency shutdown, with no alternative emergency claim mechanism. This matches the external report's vulnerability class where harvest operations are blocked during emergency, locking user rewards.

**Why protections fail:**
The status checks were likely intended to prevent operations during unsafe conditions, but they inadvertently lock users out of claiming funds that are already owed to them and sitting idle in the vault.

### Impact Explanation

**Direct Fund Lockage:**
- Users with `claimable_principal` balance (from executed withdrawals) cannot access these funds during `DISABLED` state
- Users with `unclaimed_rewards` cannot claim their earned rewards during `DISABLED` state
- These are user-owned funds, not protocol-controlled assets

**Real-world Emergency Scenarios:**
1. Security incident detected (e.g., adaptor vulnerability, oracle manipulation)
2. Admin sets vault to `DISABLED` to prevent further damage
3. Users who have already withdrawn (funds in `claimable_principal`) or earned rewards cannot claim
4. If emergency is severe and vault cannot be safely re-enabled, user funds remain locked indefinitely

**Severity:** HIGH
- Direct denial of access to user funds
- No emergency recovery mechanism
- Funds may be permanently locked if vault cannot be re-enabled

### Likelihood Explanation

**HIGH Likelihood:**

1. **Emergency shutdowns are realistic:** Vaults may be disabled due to security incidents, oracle failures, critical bugs in adaptors, or external protocol exploits affecting integrated DeFi protocols (Navi, Suilend, Cetus, etc.)

2. **Users regularly have claimable balances:** 
   - The withdrawal flow explicitly supports non-auto-transfer mode where funds go to `claimable_principal`
   - Users accumulate rewards over time through the reward manager system
   - Both are normal operational states

3. **No alternative claim path:** The codebase provides no emergency claim function that bypasses status checks

4. **Entry points are user-callable:** Both `claim_claimable_principal()` and `claim_reward()` are accessible through public user entry functions. [9](#0-8) 

5. **Preconditions are trivial:** Users only need to have executed withdrawals or earned rewards before the emergency - no special state manipulation required

### Recommendation

Implement emergency claim functions that allow users to recover their `claimable_principal` and `unclaimed_rewards` even when the vault is in `DISABLED` status:

```
// Add emergency claim function for claimable_principal
public(package) fun emergency_claim_claimable_principal<T>(
    self: &mut Vault<T>,
    receipt_id: address,
    amount: u64,
): Balance<T> {
    self.check_version();
    // Only check version, NOT status
    // Allow claiming even when DISABLED
    
    let vault_receipt = self.receipts.borrow_mut(receipt_id);
    let claimable_amount = vault_receipt.claimable_principal();
    assert!(claimable_amount >= amount, ERR_INSUFFICIENT_CLAIMABLE_PRINCIPAL);
    assert!(self.claimable_principal.value() >= amount, ERR_INSUFFICIENT_CLAIMABLE_PRINCIPAL);
    
    vault_receipt.update_after_claim_principal(amount);
    
    emit(ClaimablePrincipalClaimed {
        vault_id: self.vault_id(),
        receipt_id: receipt_id,
        amount: amount,
    });
    
    self.claimable_principal.split(amount)
}

// Add emergency claim function for rewards
public fun emergency_claim_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &Vault<PrincipalCoinType>,
    receipt: &mut Receipt,
): Balance<RewardCoinType> {
    self.check_version();
    // Remove vault.assert_enabled() check
    // Only check vault receipt match and receipt status
    
    vault.assert_vault_receipt_matched(receipt);
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    
    let receipt_id = receipt.receipt_id();
    let vault_receipt = vault.vault_receipt_info(receipt_id);
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);
    
    let reward_type = type_name::get<RewardCoinType>();
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount = vault_utils::from_decimals(
        vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
    ) as u64;
    
    let vault_reward_balance = self.reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);
    
    emit(RewardClaimed {
        reward_manager_id: self.id.to_address(),
        vault_id: receipt.vault_id(),
        receipt_id: receipt.receipt_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    });
    
    vault_reward_balance.split(reward_amount)
}
```

Alternatively, modify the existing functions to check only `check_version()` instead of `assert_normal()`/`assert_enabled()`, since claiming already-owed funds should be allowed even during emergency states.

### Proof of Concept

**Scenario 1: Claimable Principal Lockage**

1. User requests withdrawal using `user_entry::withdraw()` with `recipient = address::from_u256(0)` (non-auto-transfer mode), creating withdraw request ID #1 with 1000 shares
2. Operator executes withdrawal via `operation::execute_withdraw()`, which converts shares to 950 principal tokens (after fees) and adds them to `vault.claimable_principal` and `receipt.claimable_principal = 950`
3. Emergency detected (e.g., adaptor exploit in Navi protocol integration)
4. Admin calls `manage::set_enabled(vault, false)`, setting vault status to `VAULT_DISABLED_STATUS` (2)
5. User attempts to claim their 950 tokens via `user_entry::claim_claimable_principal(vault, receipt, 950)`
6. Transaction aborts at `assert_normal()` with `ERR_VAULT_NOT_NORMAL` error
7. User's 950 tokens remain locked in vault's `claimable_principal` balance with no recovery mechanism

**Scenario 2: Rewards Lockage**

1. User has deposited 10,000 principal tokens and earned 500 reward tokens over multiple epochs
2. `receipt.unclaimed_rewards[REWARD_TYPE] = 500` (tracked in vault receipt info)
3. Emergency shutdown occurs (admin sets vault to `DISABLED`)
4. User attempts to claim rewards via `reward_manager::claim_reward<PRINCIPAL, REWARD>(reward_manager, vault, clock, receipt)`
5. Transaction aborts at `vault.assert_enabled()` with `ERR_VAULT_NOT_ENABLED` error  
6. User's 500 reward tokens remain locked in `reward_manager.reward_balances` with no claim mechanism

Both scenarios demonstrate direct analog to external report: users cannot "harvest" (claim) their owed funds/rewards during emergency state, resulting in indefinite fund lockage.

### Citations

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L1573-1596)
```text
public(package) fun claim_claimable_principal<T>(
    self: &mut Vault<T>,
    receipt_id: address,
    amount: u64,
): Balance<T> {
    self.check_version();
    self.assert_normal();

    let vault_receipt = self.receipts.borrow_mut(receipt_id);

    let claimable_amount = vault_receipt.claimable_principal();
    assert!(claimable_amount >= amount, ERR_INSUFFICIENT_CLAIMABLE_PRINCIPAL);
    assert!(self.claimable_principal.value() >= amount, ERR_INSUFFICIENT_CLAIMABLE_PRINCIPAL);

    vault_receipt.update_after_claim_principal(amount);

    emit(ClaimablePrincipalClaimed {
        vault_id: self.vault_id(),
        receipt_id: receipt_id,
        amount: amount,
    });

    self.claimable_principal.split(amount)
}
```

**File:** volo-vault/sources/operation.move (L474-478)
```text
    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
    }
```

**File:** volo-vault/sources/vault_receipt_info.move (L102-116)
```text
public(package) fun update_after_execute_withdraw(
    self: &mut VaultReceiptInfo,
    executed_withdraw_shares: u256,
    claimable_principal: u64,
) {
    self.status = NORMAL_STATUS;
    self.shares = self.shares - executed_withdraw_shares;
    self.pending_withdraw_shares = self.pending_withdraw_shares - executed_withdraw_shares;
    self.claimable_principal = self.claimable_principal + claimable_principal;
}

// Claim principal: claimable_principal ↓
public(package) fun update_after_claim_principal(self: &mut VaultReceiptInfo, amount: u64) {
    self.claimable_principal = self.claimable_principal - amount;
}
```

**File:** volo-vault/sources/reward_manager.move (L596-639)
```text
public fun claim_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt: &mut Receipt,
): Balance<RewardCoinType> {
    self.check_version();
    vault.assert_enabled();
    vault.assert_vault_receipt_matched(receipt);
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    let receipt_id = receipt.receipt_id();

    let vault_receipt = vault.vault_receipt_info(receipt_id);
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Update all reward buffers
    self.update_reward_buffers<PrincipalCoinType>(vault, clock);
    // Update the pending reward for the receipt
    self.update_receipt_reward(vault, receipt_id);

    let reward_type = type_name::get<RewardCoinType>();

    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;

    let vault_reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);

    emit(RewardClaimed {
        reward_manager_id: self.id.to_address(),
        vault_id: receipt.vault_id(),
        receipt_id: receipt.receipt_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    });

    vault_reward_balance.split(reward_amount)
}
```

**File:** volo-vault/sources/user_entry.move (L195-202)
```text
public fun claim_claimable_principal<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt: &mut Receipt,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.assert_vault_receipt_matched(receipt);
    vault.claim_claimable_principal(receipt.receipt_id(), amount)
}
```
