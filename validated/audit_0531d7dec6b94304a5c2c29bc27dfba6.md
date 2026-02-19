# Audit Report

## Title
Unsupported Coin Types in Navi Positions Cause Vault DoS via Oracle Price Lookup Failure

## Summary
The Navi adaptor's position valuation logic fails to validate that coin types held in Navi positions are supported by the vault's oracle configuration. When operators deposit unsupported coin types into Navi during operations, subsequent value update calls abort with `ERR_AGGREGATOR_NOT_FOUND`, causing a permanent denial-of-service that blocks all deposits, withdrawals, and operation completions.

## Finding Description

The vulnerability stems from a mis-scoped operator privilege combined with missing validation in the asset valuation flow.

**Root Cause:** The `calculate_navi_position_value` function iterates through all Navi protocol reserves and attempts to fetch prices for any asset with a non-zero balance, without validating whether the vault's oracle supports that asset type. [1](#0-0) 

The function retrieves coin types directly from Navi storage and immediately calls the oracle's `get_asset_price` function for any reserve with a non-zero balance. The oracle enforces strict validation with a hard abort: [2](#0-1) 

**Trigger Mechanism:** Operators can borrow the `NaviAccountCap` during vault operations: [3](#0-2) 

With this capability, operators can call Navi protocol functions including `deposit_with_account_cap` to deposit ANY coin type that Navi supports: [4](#0-3) 

**Impact Propagation:** Once an unsupported coin type has a non-zero balance in the Navi position, all operations requiring value updates become blocked:

1. **Deposit Execution** requires `get_total_usd_value`: [5](#0-4) 

2. **Total USD Value Calculation** requires all assets to be updated within `MAX_UPDATE_INTERVAL`: [6](#0-5) 

3. **MAX_UPDATE_INTERVAL is set to 0**, requiring immediate updates: [7](#0-6) 

4. **Operation Completion** also requires `get_total_usd_value`: [8](#0-7) 

**Catch-22 Recovery Problem:** To remove the problematic Navi position, an operation must complete successfully. But operation completion requires updating all asset values, which fails due to the unsupported coin type. The vault enters a permanent stuck state.

## Impact Explanation

**Critical Severity - Complete Vault DoS:**

1. **All Deposit Execution Blocked**: Users cannot execute pending deposits because `execute_deposit` requires calling `get_total_usd_value`, which aborts when trying to update the Navi position value.

2. **All Operation Completion Blocked**: Operators cannot complete any operations that involve Navi positions because `end_op_value_update_with_bag` requires `get_total_usd_value`, creating the same abort condition.

3. **Permanent State Lock**: The vault cannot recover because removing the problematic position requires completing an operation, which requires value updates, which abort on the unsupported coin type.

4. **User Fund Lock**: All depositors with pending deposits are unable to execute their deposits or cancel requests within the standard timeout window, as both paths require vault state updates.

The vulnerability breaks the core vault invariant that "all assets must be priceable by the configured oracle." This is a systemic DoS that affects the entire vault and all its users.

## Likelihood Explanation

**High Likelihood - Mis-Scoped Operator Privileges:**

This vulnerability has high likelihood because it stems from a **privilege scope design flaw** rather than requiring malicious behavior:

1. **Operator Error (Legitimate)**: An honest operator using the `NaviAccountCap` during operations may deposit a coin type that Navi supports but the vault's oracle doesn't, especially when:
   - Navi adds new reserve support before the vault updates its oracle configuration
   - Multiple vaults use different oracle configurations
   - Operators work across multiple protocols and make honest mistakes

2. **Low Attack Complexity**: Triggering the DoS requires only:
   - Valid `OperatorCap` (normal operation requirement)
   - One call to Navi's `deposit_with_account_cap` during operation window
   - Minimal amount (even 1 unit) of any unsupported coin type

3. **No Validation Layer**: The system has zero validation to prevent this:
   - No whitelist of allowed coin types in Navi operations
   - No validation against oracle configuration before Navi interactions
   - No graceful failure handling in the valuation flow

4. **Protocol Evolution Risk**: As Navi protocol evolves and adds new coin type support, any operator interaction could inadvertently create positions in newly-supported but oracle-unsupported assets.

This is fundamentally about **mis-scoped operator privileges** - operators should not be able to break vault invariants (all assets must be oracle-priceable) even with their legitimate capabilities. The lack of validation makes this a design vulnerability rather than requiring malicious intent.

## Recommendation

Implement validation to ensure operators can only interact with Navi using coin types supported by the vault's oracle configuration:

**Solution 1: Whitelist Validation in Navi Adaptor**
```move
// Add to navi_adaptor.move
public fun validate_coin_type_supported(
    config: &OracleConfig,
    coin_type: String,
) {
    assert!(
        vault_oracle::is_coin_type_supported(config, coin_type),
        ERR_UNSUPPORTED_COIN_TYPE
    );
}

// Add to oracle.move
public fun is_coin_type_supported(
    config: &OracleConfig,
    coin_type: String,
): bool {
    config.aggregators.contains(coin_type)
}
```

**Solution 2: Graceful Handling in Position Valuation**
```move
// Modify calculate_navi_position_value to skip unsupported coins
while (i > 0) {
    let (supply, borrow) = storage.get_user_balance(i - 1, account);
    let coin_type = storage.get_coin_type(i - 1);
    
    if (supply == 0 && borrow == 0) {
        i = i - 1;
        continue
    };
    
    // Skip if oracle doesn't support this coin type
    if (!vault_oracle::is_coin_type_supported(config, coin_type)) {
        i = i - 1;
        continue
    };
    
    let price = vault_oracle::get_asset_price(config, clock, coin_type);
    // ... rest of logic
}
```

**Solution 3: Pre-Operation Validation**
Add checks before operators can borrow `NaviAccountCap` to ensure all existing Navi positions use supported coin types, preventing the vault from entering operations with unsupported assets.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault_oracle::ERR_AGGREGATOR_NOT_FOUND)]
fun test_unsupported_coin_dos() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with oracle supporting only SUI
    setup_vault_with_sui_oracle(&mut scenario, &mut clock);
    
    // Operator starts operation and borrows NaviAccountCap
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let operator_cap = scenario.take_from_sender<OperatorCap>();
        let operation = scenario.take_shared<Operation>();
        
        let (mut defi_assets, tx, tx_check, _, _) = operation::start_op_with_bag<SUI, USDC, MockObligation>(
            &mut vault,
            &operation,
            &operator_cap,
            &clock,
            vector[0], // Navi account cap ID
            vector[type_name::get<NaviAccountCap>()],
            0,
            0,
            scenario.ctx()
        );
        
        // Operator deposits USDC into Navi (unsupported by oracle)
        let navi_cap = defi_assets.remove<String, NaviAccountCap>(
            vault_utils::parse_key<NaviAccountCap>(0)
        );
        let mut storage = scenario.take_shared<Storage>();
        let mut usdc_pool = scenario.take_shared<Pool<USDC>>();
        let usdc_coin = coin::mint_for_testing<USDC>(100, scenario.ctx());
        
        lending::deposit_with_account_cap(
            &clock,
            &mut storage,
            &mut usdc_pool,
            USDC_RESERVE_ID,
            usdc_coin,
            &navi_cap
        );
        
        defi_assets.add(vault_utils::parse_key<NaviAccountCap>(0), navi_cap);
        
        // Return assets and complete operation
        operation::end_op_with_bag(&mut vault, &operation, &operator_cap, defi_assets, tx, balance::zero(), balance::zero());
        
        test_scenario::return_shared(storage);
        test_scenario::return_shared(usdc_pool);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        scenario.return_to_sender(operator_cap);
    };
    
    // Attempt to execute deposit - will abort with ERR_AGGREGATOR_NOT_FOUND
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let config = scenario.take_shared<OracleConfig>();
        let mut storage = scenario.take_shared<Storage>();
        
        // This call will abort because USDC is not in oracle config
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L43-63)
```text
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/oracle.move (L126-129)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
```

**File:** volo-vault/sources/operation.move (L118-124)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };
```

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L483-492)
```text
    public(friend) fun deposit_with_account_cap<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        account_cap: &AccountCap
    ) {
        base_deposit(clock, storage, pool, asset, account::account_owner(account_cap), coin::into_balance(deposit_coin))
    }
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L806-820)
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
```

**File:** volo-vault/sources/volo_vault.move (L1254-1266)
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
```
