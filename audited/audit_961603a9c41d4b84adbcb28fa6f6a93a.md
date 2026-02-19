### Title
Public AccountCap Exposure Enables Complete Bypass of Vault Locking Window and Withdrawal Security

### Summary
The vault's `get_defi_asset` function is public and returns references to stored DeFi assets including NaviAccountCap. Any attacker can obtain this reference and call the public `incentive_v3::withdraw_with_account_cap` function to withdraw all funds from the vault's Navi lending positions, completely bypassing the 12-hour locking window, withdrawal request system, share burning, fee collection, and all vault security mechanisms.

### Finding Description

The vulnerability exists due to the combination of two public functions that should not be publicly accessible together: [1](#0-0) 

This function is declared as `public fun` with no authorization checks, allowing anyone to obtain a reference to any DeFi asset stored in the vault, including the NaviAccountCap. [2](#0-1) 

This function is also `public fun` and accepts an AccountCap reference to perform withdrawals from Navi lending positions. It calls the underlying lending protocol's withdraw function and returns the withdrawn Balance directly to the caller. [3](#0-2) 

The lending core's withdraw function extracts the owner address from the AccountCap and withdraws funds from that owner's positions, returning the Balance to the caller. [4](#0-3) 

The base withdrawal executes the state changes and returns the Balance, which flows back to the original caller who can then convert it to a Coin and keep the funds.

The vault's intended withdrawal flow requires checking the locking window: [5](#0-4) [6](#0-5) 

However, this check is completely bypassed when using the AccountCap directly.

### Impact Explanation

**Fund Theft**: An attacker can drain 100% of the funds deposited into Navi lending positions through the vault's NaviAccountCap without any authorization or share burning. If the vault has $1M in Navi positions, all $1M can be stolen.

**Bypassed Protections**:
- Locking window (12 hours) completely bypassed - instant withdrawal possible
- Withdrawal request system bypassed - no request ID needed
- Share accounting bypassed - attacker doesn't need to own any vault shares
- Fee collection bypassed - no withdrawal fees charged
- Recipient tracking bypassed - funds go directly to attacker

**Affected Parties**: All vault depositors lose their proportional share of Navi position value, while the vault's share supply remains unchanged, leading to severe undercollateralization.

**Severity**: CRITICAL - Direct theft of custody with no special privileges required.

### Likelihood Explanation

**Attacker Capabilities**: Any external user with basic blockchain interaction capability can execute this attack. No operator role, admin privileges, or vault shares required.

**Attack Complexity**: Trivially simple - two public function calls:
1. Call `vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type)` to get AccountCap reference
2. Call `incentive_v3::withdraw_with_account_cap(...)` with that reference to withdraw funds

**Feasibility**: 100% - Both functions are publicly callable with no authorization checks. The AccountCap is stored in the vault's assets Bag and accessible via the deterministic asset_type key.

**Detection**: The attack would appear as normal Navi withdrawals in the lending protocol, making it difficult to prevent or detect until vault reconciliation reveals missing funds.

**Probability**: HIGH - The exploit is straightforward with guaranteed success once Navi positions exist in the vault.

### Recommendation

**Immediate Fix**: Change `get_defi_asset` visibility to `public(package)`:

```move
public(package) fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType
```

**Additional Protections**:
1. Create a separate internal-only function for adaptor value queries that maintains `public` visibility
2. Add explicit checks in adaptors that AccountCap references are only used for read-only value calculations, never for fund movement
3. Consider wrapping the NaviAccountCap in a vault-specific struct that restricts its usage to authorized contexts

**Invariant Check**: Add assertion that DeFi asset references obtained for value calculations are never used to transfer value out of positions.

**Test Cases**:
1. Test that external users cannot access DeFi assets via `get_defi_asset`
2. Test that only authorized operations can borrow DeFi assets
3. Test that withdrawal attempts with stolen AccountCap references fail
4. Regression test ensuring adaptors still function for value queries

### Proof of Concept

**Initial State**:
- Vault has NaviAccountCap stored with asset_type = `parse_key<NaviAccountCap>(0)`
- Vault has $100,000 deposited into Navi lending positions via the AccountCap
- Attacker has no vault shares and no special privileges

**Attack Sequence**:
1. Attacker calls `vault.get_defi_asset<SUI, NaviAccountCap>("NaviAccountCap_0")` → receives `&NaviAccountCap`
2. Attacker calls `incentive_v3::withdraw_with_account_cap<SUI>(clock, oracle, storage, pool, asset_id, 100000_000000000, incentive_v2, incentive_v3, &account_cap)` → receives `Balance<SUI>` worth $100,000
3. Attacker calls `balance.into_coin(ctx)` → converts to `Coin<SUI>`
4. Attacker calls `transfer::public_transfer(coin, attacker_address)` → keeps the stolen funds

**Expected Result**: Transaction should revert with authorization error

**Actual Result**: Transaction succeeds, attacker receives $100,000 in SUI, vault's Navi positions are drained, but vault's share supply and user receipts remain unchanged, causing severe undercollateralization.

**Success Condition**: Attacker's wallet balance increases by $100,000 while vault state shows no corresponding share burn or withdrawal record.

### Citations

**File:** volo-vault/sources/volo_vault.move (L694-703)
```text
public fun check_locking_time_for_withdraw<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    receipt_id: address,
    clock: &Clock,
): bool {
    self.check_version();

    let receipt = self.receipts.borrow(receipt_id);
    self.locking_time_for_withdraw + receipt.last_deposit_time() <= clock.timestamp_ms()
}
```

**File:** volo-vault/sources/volo_vault.move (L1451-1456)
```text
public fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType {
    self.assets.borrow<String, AssetType>(asset_type)
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L853-869)
```text
    public fun withdraw_with_account_cap<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap
    ): Balance<CoinType> {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        lending::withdraw_with_account_cap<CoinType>(clock, oracle, storage, pool, asset, amount, account_cap)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L216-248)
```text
    fun base_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        user: address
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let normal_withdraw_amount = pool::normal_amount(pool, amount);
        let normal_withdrawable_amount = logic::execute_withdraw<CoinType>(
            clock,
            oracle,
            storage,
            asset,
            user,
            (normal_withdraw_amount as u256)
        );

        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
        let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
        emit(WithdrawEvent {
            reserve: asset,
            sender: user,
            to: user,
            amount: withdrawable_amount,
        });

        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L494-504)
```text
    public(friend) fun withdraw_with_account_cap<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        account_cap: &AccountCap
    ): Balance<CoinType> {
        base_withdraw(clock, oracle, storage, pool, asset, amount, account::account_owner(account_cap))
    }
```

**File:** volo-vault/sources/user_entry.move (L124-148)
```text
public fun withdraw<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    shares: u256,
    expected_amount: u64,
    receipt: &mut Receipt,
    clock: &Clock,
    _ctx: &mut TxContext,
): u64 {
    vault.assert_vault_receipt_matched(receipt);
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
    assert!(shares > 0, ERR_INVALID_AMOUNT);

    let request_id = vault.request_withdraw(
        clock,
        receipt.receipt_id(),
        shares,
        expected_amount,
        address::from_u256(0),
    );

    request_id
}
```
