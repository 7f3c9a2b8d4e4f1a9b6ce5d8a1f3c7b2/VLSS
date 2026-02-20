# Audit Report

## Title
Missing Claim Functionality During Vault Emergency Shutdown

## Summary
Users cannot claim their `claimable_principal` (withdrawn funds) or earned rewards when the Volo Vault is set to `DISABLED` status during emergency shutdown, resulting in indefinite lockage of user-owned funds that are already owed to them.

## Finding Description

The Volo Vault implements a three-state status model: `VAULT_NORMAL_STATUS` (0), `VAULT_DURING_OPERATION_STATUS` (1), and `VAULT_DISABLED_STATUS` (2). [1](#0-0) 

When administrators detect an emergency, they can disable the vault via `set_enabled(false)`, which sets the vault status to `VAULT_DISABLED_STATUS`. [2](#0-1) 

**Critical Issue 1: Claimable Principal Locked**

The `claim_claimable_principal()` function requires an `assert_normal()` check. [3](#0-2) 

The `assert_normal()` function enforces that vault status must equal `VAULT_NORMAL_STATUS` (0), meaning it rejects both `DISABLED` (2) and `DURING_OPERATION` (1) states. [4](#0-3) 

Users' claimable principal balances accumulate when operators execute withdrawals with `recipient = address::from_u256(0)`. In this case, instead of immediately transferring funds, the system adds them to `claimable_principal` for later claiming. [5](#0-4) 

The user-callable entry point exists in the public interface. [6](#0-5) 

**Critical Issue 2: Rewards Locked**

The `claim_reward()` function requires an `assert_enabled()` check, which blocks claiming when the vault is `DISABLED`. [7](#0-6) 

The `assert_enabled()` function specifically rejects `VAULT_DISABLED_STATUS`. [8](#0-7) 

**Root Cause:**
Both critical user fund recovery operations are blocked during emergency shutdown, with no alternative emergency claim mechanism. The status checks were intended to prevent operations during unsafe conditions, but they inadvertently lock users out of claiming funds that are already owed to them and sitting idle in the vault.

## Impact Explanation

**HIGH Severity - Direct User Fund Lockage:**

1. Users with `claimable_principal` balance (from executed withdrawals) cannot access these funds during `DISABLED` state
2. Users with `unclaimed_rewards` cannot claim their earned rewards during `DISABLED` state  
3. These are user-owned funds already owed to them, not protocol-controlled assets

**Real-world Emergency Scenarios:**
- Security incident detected (adaptor vulnerability, oracle manipulation)
- Admin sets vault to `DISABLED` to prevent further damage
- Users who have already withdrawn or earned rewards cannot claim
- If emergency is severe and vault cannot be safely re-enabled, user funds remain locked indefinitely

This breaks the fundamental security guarantee that users can always access funds that are legitimately owed to them.

## Likelihood Explanation

**HIGH Likelihood:**

1. **Emergency shutdowns are realistic:** Vaults may be disabled due to security incidents, oracle failures, critical bugs in adaptors, or external protocol exploits affecting integrated DeFi protocols (Navi, Suilend, Cetus, Momentum)

2. **Users regularly have claimable balances:** The withdrawal flow explicitly supports non-auto-transfer mode where funds go to `claimable_principal`, and users accumulate rewards over time through the reward manager system

3. **No alternative claim path:** The codebase provides no emergency claim function that bypasses status checks

4. **Preconditions are trivial:** Users only need to have executed withdrawals or earned rewards before the emergency - no special state manipulation required

## Recommendation

Implement emergency claim functions that allow users to access their `claimable_principal` and `unclaimed_rewards` even when the vault is in `DISABLED` status:

```move
// Emergency claim for claimable principal - bypasses status checks
public fun emergency_claim_claimable_principal<T>(
    self: &mut Vault<T>,
    receipt_id: address,
    amount: u64,
): Balance<T> {
    self.check_version();
    // Only check vault is not during operation, allow DISABLED
    self.assert_not_during_operation();
    
    let vault_receipt = self.receipts.borrow_mut(receipt_id);
    let claimable_amount = vault_receipt.claimable_principal();
    assert!(claimable_amount >= amount, ERR_INSUFFICIENT_CLAIMABLE_PRINCIPAL);
    assert!(self.claimable_principal.value() >= amount, ERR_INSUFFICIENT_CLAIMABLE_PRINCIPAL);
    
    vault_receipt.update_after_claim_principal(amount);
    self.claimable_principal.split(amount)
}

// Emergency claim for rewards - bypasses status checks  
public fun emergency_claim_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt: &mut Receipt,
): Balance<RewardCoinType> {
    self.check_version();
    // Only check vault is not during operation, allow DISABLED
    vault.assert_not_during_operation();
    vault.assert_vault_receipt_matched(receipt);
    
    let receipt_id = receipt.receipt_id();
    let vault_receipt = vault.vault_receipt_info(receipt_id);
    
    // Update rewards if vault is enabled, skip if disabled
    if (vault.status() != VAULT_DISABLED_STATUS) {
        self.update_reward_buffers<PrincipalCoinType>(vault, clock);
        self.update_receipt_reward(vault, receipt_id);
    };
    
    let reward_type = type_name::get<RewardCoinType>();
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount = vault_utils::from_decimals(
        vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
    ) as u64;
    
    let vault_reward_balance = self.reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);
    
    vault_reward_balance.split(reward_amount)
}
```

## Proof of Concept

```move
#[test]
fun test_funds_locked_during_emergency_shutdown() {
    // Setup vault in NORMAL status
    let mut scenario = test_scenario::begin(ADMIN);
    let vault = setup_vault(&mut scenario);
    
    // User deposits and requests withdrawal without auto-transfer
    scenario.next_tx(USER);
    let receipt = request_deposit(&mut vault, 1000);
    
    scenario.next_tx(OPERATOR);
    execute_deposit(&mut vault, &receipt);
    
    scenario.next_tx(USER);
    request_withdraw_no_auto_transfer(&mut vault, &receipt, 500);
    
    // Operator executes - funds go to claimable_principal
    scenario.next_tx(OPERATOR);
    execute_withdraw(&mut vault, &receipt); // Adds to claimable_principal
    
    // User earns rewards
    scenario.next_tx(OPERATOR);
    add_rewards(&mut vault, 100);
    
    // EMERGENCY: Admin disables vault
    scenario.next_tx(ADMIN);
    vault.set_enabled(false); // Status = DISABLED
    
    // USER CANNOT CLAIM THEIR OWN FUNDS
    scenario.next_tx(USER);
    let result = vault.claim_claimable_principal(receipt.receipt_id(), 500);
    // FAILS with ERR_VAULT_NOT_NORMAL
    
    scenario.next_tx(USER);  
    let reward_result = reward_manager.claim_reward(&mut vault, &clock, &receipt);
    // FAILS with ERR_VAULT_NOT_ENABLED
    
    // User funds are indefinitely locked
    test_scenario::end(scenario);
}
```

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

**File:** volo-vault/sources/volo_vault.move (L1573-1579)
```text
public(package) fun claim_claimable_principal<T>(
    self: &mut Vault<T>,
    receipt_id: address,
    amount: u64,
): Balance<T> {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/operation.move (L474-478)
```text
    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
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

**File:** volo-vault/sources/reward_manager.move (L596-605)
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
```
