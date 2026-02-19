### Title
Missing Pool Identity Validation Enables Cross-Pool Contamination During Lending Operations

### Summary
The Navi lending protocol's core operations (deposit, borrow, withdraw, repay) validate only CoinType matching but do not validate that the provided Pool object corresponds to the specified asset ID in the Storage object. This missing validation, which uses the `invalid_pool()` error only in flash loans, allows mismatched Storage/Pool combinations to corrupt accounting during protocol upgrades or multi-deployment scenarios, breaking the critical invariant that Storage accounting must match Pool custody.

### Finding Description

The `invalid_pool()` error (error code 1504) is defined but only enforced in flash loan operations, not in core lending operations. [1](#0-0) 

Flash loan operations properly validate pool identity: [2](#0-1) [3](#0-2) 

However, core lending operations only validate CoinType matching, not Pool object identity: [4](#0-3) [5](#0-4) 

The ReserveData structure contains no pool_id or UID reference to cryptographically link a reserve to its corresponding Pool object: [6](#0-5) 

When operations execute (e.g., deposit, borrow), they accept Storage, Pool, and asset parameters separately without validating their correspondence: [7](#0-6) [8](#0-7) 

In the Volo vault context, operators borrow NaviAccountCap and call Navi lending operations directly: [9](#0-8) 

Operators then invoke Navi operations by passing Storage and Pool as separate shared object references: [10](#0-9) 

During protocol upgrades or when multiple deployments exist (testnet/mainnet), operators could reference mismatched Storage/Pool combinations. For example:
- Storage_V2 with Pool_V1 (both for SUI)
- The validation would pass (CoinType matches: SUI == SUI)
- Accounting updates in Storage_V2, but funds move in/out of Pool_V1
- Storage_V2 accounting becomes misaligned with Pool_V2 custody

### Impact Explanation

**Direct Fund Impact:**
When cross-pool contamination occurs, Storage accounting diverges from actual Pool custody. Users attempting to withdraw based on Storage_V2's accounting will fail because Pool_V2 lacks the corresponding funds. Deposits to Pool_V1 based on Storage_V2 accounting create untracked liabilities. This breaks the fundamental protocol invariant that reserves must be fully backed by pool custody.

**Magnitude:**
- Users lose ability to withdraw their legitimately deposited funds (DoS)
- Protocol accounting corruption requires manual intervention/migration to fix
- Affects all users of the contaminated Storage/Pool pair
- Can drain pool funds if exploited systematically during migration periods

**Affected Parties:**
- All users with deposits/borrows in the affected reserve
- Volo vault users whose operations route through contaminated Navi instances
- Protocol operators who must halt operations and migrate state

### Likelihood Explanation

**Feasibility Conditions:**
This vulnerability manifests when multiple Storage/Pool instances coexist, which occurs during:
1. Protocol version upgrades (V1→V2 migration)
2. Testnet and mainnet parallel deployments
3. Multiple protocol forks or instances on Sui

**Attacker Capabilities:**
No malicious intent required. Volo vault operators with valid OperatorCap credentials can trigger contamination through:
- Using outdated deployment scripts referencing old object IDs
- Accidental copy-paste errors in object ID parameters
- Confusion between testnet/mainnet object addresses

**Execution Path:**
1. Operator calls `start_op_with_bag` to borrow NaviAccountCap from vault
2. Operator calls `take_shared<Storage>()` and `take_shared<Pool<CoinType>>()` with mismatched object IDs
3. Operator invokes `incentive_v3::deposit_with_account_cap(storage_A, pool_B, asset, ...)`
4. Validation passes (CoinType matches)
5. Accounting updates in storage_A, funds deposit to pool_B
6. Contamination complete

**Detection Difficulty:**
Contamination is not immediately visible. Only discovered when:
- Users attempt withdrawals and transactions fail
- Auditors notice accounting discrepancies
- Pool balances don't reconcile with Storage records

**Probability:**
MEDIUM - Not exploitable in steady-state single-deployment scenarios, but inevitable during migration windows when old and new objects coexist on-chain. Given Sui's immutable shared objects, old Pool/Storage instances remain accessible indefinitely.

### Recommendation

**Code-Level Mitigation:**

1. Store pool UID in ReserveData during init_reserve:
```move
struct ReserveData has store {
    id: u8,
    pool_id: address, // ADD: Pool object UID
    oracle_id: u8,
    coin_type: String,
    // ... rest of fields
}
```

2. Add pool validation to lending operations in validation.move:
```move
public fun validate_pool_match<CoinType>(
    storage: &Storage, 
    pool: &Pool<CoinType>, 
    asset: u8
) {
    let pool_id = object::uid_to_address(pool::uid(pool));
    let expected_pool_id = storage::get_pool_id(storage, asset);
    assert!(pool_id == expected_pool_id, error::invalid_pool());
}
```

3. Call validation in all lending operations (deposit, borrow, withdraw, repay): [11](#0-10) 

Add after line 16:
```move
validate_pool_match<CoinType>(storage, pool, asset);
```

**Invariant Enforcement:**
Add assertion in navi_adaptor position value calculation to verify Storage/Pool consistency before vault operations proceed.

**Test Cases:**
- Attempt deposit with Storage_A + Pool_B (different instances, same CoinType) - should abort with invalid_pool
- Verify pool_id stored in ReserveData matches actual Pool UID
- Integration test simulating migration scenario with old/new Storage/Pool objects

### Proof of Concept

**Initial State:**
- Protocol V1 deployed: Storage_V1 (ID: 0xAAA), Pool_SUI_V1 (ID: 0xBBB), asset 0 = SUI
- Protocol V2 deployed: Storage_V2 (ID: 0xCCC), Pool_SUI_V2 (ID: 0xDDD), asset 0 = SUI
- Volo vault holds NaviAccountCap_V1 (for Storage_V1)
- Storage_V1 has 1000 SUI tracked in accounting
- Pool_SUI_V1 custody: 1000 SUI
- Storage_V2 has 0 SUI tracked in accounting  
- Pool_SUI_V2 custody: 0 SUI

**Attack Sequence:**
1. Operator borrows NaviAccountCap_V1 from vault via `start_op_with_bag`
2. Operator mistakenly calls:
   ```move
   let storage_v2 = test_scenario::take_shared<Storage>(0xCCC);
   let pool_sui_v1 = test_scenario::take_shared<Pool<SUI>>(0xBBB);
   incentive_v3::deposit_with_account_cap<SUI>(
       clock, 
       &mut storage_v2,  // Wrong Storage!
       &mut pool_sui_v1, // Wrong Pool!
       0,                // asset ID
       500 SUI,
       ...
       account_cap_v1
   );
   ```
3. Validation passes (type_name::get<SUI>() == storage_v2.get_coin_type(0))
4. Storage_V2 accounting: 0 → 500 SUI (tracked supply increases)
5. Pool_SUI_V1 custody: 1000 → 1500 SUI (actual funds deposited)
6. Storage_V1 accounting: 1000 SUI (unchanged, now wrong)
7. Pool_SUI_V2 custody: 0 SUI (unchanged, should have 500)

**Result:**
- Storage_V2 shows 500 SUI supply but Pool_SUI_V2 is empty
- Users cannot withdraw from Storage_V2 (insufficient balance in Pool_SUI_V2)
- Pool_SUI_V1 has unexpected 500 SUI excess
- Cross-pool contamination achieved

**Success Condition:**
Transaction succeeds without `invalid_pool` error, accounting diverges from custody across Storage/Pool pairs.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/error.move (L9-9)
```text
    public fun invalid_pool(): u64 {1504}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L148-150)
```text
        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L176-178)
```text
        let Receipt {user, asset, amount, pool, fee_to_supplier, fee_to_treasury} = _receipt;
        assert!(user == _user, error::invalid_user());
        assert!(pool == object::uid_to_address(pool::uid(_pool)), error::invalid_pool());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L15-33)
```text
    public fun validate_deposit<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        // e.g. Pool total collateral of 100ETH
        let (supply_balance, _) = storage::get_total_supply(storage, asset);
        let (current_supply_index, _) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);

        // e.g. The pool has a maximum collateral capacity of 10000 ETH
        let supply_cap_ceiling = storage::get_supply_cap_ceiling(storage, asset);

        // e.g. estimate_supply
        let estimate_supply = (scale_supply_balance + amount) * ray_math::ray();

        // e.g. supply_cap_ceiling >= estimate_supply?
        assert!(supply_cap_ceiling >= estimate_supply, error::exceeded_maximum_deposit_cap());
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L56-58)
```text
    public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L43-67)
```text
    struct ReserveData has store {
        id: u8, // reserve index
        oracle_id: u8, // The id from navi oracle, update from admin
        coin_type: String, // The coin type, like 0x02::sui::SUI
        is_isolated: bool, // THe isolated of the reserve, update from admin
        supply_cap_ceiling: u256, // Total supply limit of reserve, update from admin
        borrow_cap_ceiling: u256, // Total borrow percentage of reserve, update from admin
        current_supply_rate: u256, // Current supply rates, update from protocol
        current_borrow_rate: u256, // Current borrow rates, update from protocol
        current_supply_index: u256, // The supply exchange rate, update from protocol
        current_borrow_index: u256, // The borrow exchange rate, update from protocol
        supply_balance: TokenBalance, // The total amount deposit inside the pool
        borrow_balance: TokenBalance, // The total amount borrow inside the pool
        last_update_timestamp: u64, // Last update time for reserve, update from protocol
        // Loan-to-value, used to define the maximum amount of assets that can be borrowed against a given collateral
        ltv: u256,
        treasury_factor: u256, // The fee ratio, update from admin
        treasury_balance: u256, // The fee balance, update from protocol
        borrow_rate_factors: BorrowRateFactors, // Basic Configuration, rate and multiplier etc.
        liquidation_factors: LiquidationFactors, // Liquidation configuration
        // Reserved fields, no use for now
        reserve_field_a: u256,
        reserve_field_b: u256,
        reserve_field_c: u256,
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L176-191)
```text
    fun base_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        user: address,
        deposit_balance: Balance<CoinType>,
    ) {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let deposit_amount = balance::value(&deposit_balance);
        pool::deposit_balance(pool, deposit_balance, user);

        let normal_deposit_amount = pool::normal_amount(pool, deposit_amount);
        logic::execute_deposit<CoinType>(clock, storage, asset, user, (normal_deposit_amount as u256));
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

**File:** volo-vault/sources/operation.move (L118-123)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L798-813)
```text
    public fun deposit_with_account_cap<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap
    ) {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        lending::deposit_with_account_cap<CoinType>(clock, storage, pool, asset, deposit_coin, account_cap);
    }
```
