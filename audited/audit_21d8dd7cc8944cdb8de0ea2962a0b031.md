# Audit Report

## Title
Vault Accepts Deposit Requests Without Oracle Configuration, Causing Operational DoS

## Summary
The vault system allows users to submit deposit requests immediately after vault creation, before oracle aggregators are configured for the principal asset. This causes operators to be unable to execute these deposits, temporarily locking user funds in the deposit buffer for at least 5 minutes until cancellation is possible.

## Finding Description

When a vault is created, it is automatically initialized with `VAULT_NORMAL_STATUS`, which allows deposit requests to be accepted immediately. [1](#0-0) 

The principal asset type is added during vault creation with `assets_value_updated` initialized to 0. [2](#0-1) [3](#0-2) 

The `request_deposit` function only validates that the vault is in NORMAL status via `assert_normal()`, but does NOT verify whether oracle aggregators are configured for the asset. [4](#0-3)  Users' coins are immediately placed into the `deposit_coin_buffer`. [5](#0-4) 

When operators attempt to execute deposits via `execute_deposit`, the function calls `get_total_usd_value(clock)` which enforces that all asset values must have been updated within `MAX_UPDATE_INTERVAL`. [6](#0-5) [7](#0-6) 

Since `MAX_UPDATE_INTERVAL` is set to 0, the assertion requires `now - last_update_time <= 0`. [8](#0-7)  For newly created vaults where `assets_value_updated` is 0, this becomes `now - 0 <= 0`, which always fails since `now > 0`, causing an abort with `ERR_USD_VALUE_NOT_UPDATED`.

Even if the timestamp check somehow passed, the subsequent call to `update_free_principal_value` would fail when attempting to retrieve the oracle price. [9](#0-8)  The function `get_asset_price` requires an aggregator to exist and asserts on its presence. [10](#0-9)  Without a configured aggregator, this aborts with `ERR_AGGREGATOR_NOT_FOUND`.

Users must wait for the default locking period before they can cancel their deposits and recover their funds. [11](#0-10)  This is enforced in the `cancel_deposit` function. [12](#0-11) 

The test infrastructure confirms that oracle configuration must occur after vault creation but before deposit execution for the system to function correctly. [13](#0-12) 

## Impact Explanation

This vulnerability causes **operational DoS with temporary fund lock**:

1. Users can deposit funds into a newly created vault before oracle configuration is complete
2. Their principal coins become locked in the `deposit_coin_buffer` 
3. Operators cannot execute these deposits, resulting in transaction aborts
4. Users must wait 5 minutes (300,000 milliseconds) before they can cancel and recover their funds
5. This creates operational disruption, poor user experience, and potential loss of confidence in the protocol

While no permanent fund loss occurs, the temporary lock represents a meaningful disruption to protocol operations and degrades user experience during the critical vault initialization phase.

## Likelihood Explanation

The likelihood is **HIGH** due to:

- **Public Entry Point**: `request_deposit` is accessible via the public `user_entry::deposit` function to any user
- **Immediate Vulnerability Window**: Vaults are created in NORMAL status by default, accepting deposits without additional configuration steps
- **Natural Initialization Sequence**: Administrators may reasonably create a vault first, then configure oracle feeds, but users can deposit during this gap
- **No Privilege Required**: Any user with funds can trigger this by simply attempting to deposit into a newly created vault
- **Confirmed by Tests**: The test infrastructure shows oracle configuration as a separate step after vault creation, confirming this sequence is possible

The vulnerability is particularly likely during production deployments where vault initialization may take multiple transactions across different time periods.

## Recommendation

Implement one of the following mitigations:

**Option 1**: Add oracle configuration validation to `request_deposit`:
```move
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig, // Add oracle config parameter
    // ... other parameters
): u64 {
    self.check_version();
    self.assert_normal();
    
    // Validate oracle is configured before accepting deposits
    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();
    assert!(
        config.aggregators.contains(principal_asset_type),
        ERR_ORACLE_NOT_CONFIGURED
    );
    
    // ... rest of function
}
```

**Option 2**: Create vaults in DISABLED status and require explicit enabling after oracle configuration:
```move
public fun create_vault<PrincipalCoinType>(_: &AdminCap, ctx: &mut TxContext) {
    // ...
    let mut vault = Vault<PrincipalCoinType> {
        // ...
        status: VAULT_DISABLED_STATUS, // Change from VAULT_NORMAL_STATUS
        // ...
    };
    // ...
}
```

Then require administrators to call `set_enabled(true)` only after oracle configuration is complete.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_USD_VALUE_NOT_UPDATED)]
public fun test_deposit_execution_fails_without_oracle_config() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault system but DO NOT configure oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // User successfully requests deposit (no oracle check here)
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault,
            &mut reward_manager,
            coin,
            1_000_000_000,
            2_000_000_000,
            option::none(),
            &clock,
            s.ctx(),
        );
        
        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Operator attempts to execute deposit WITHOUT oracle configured
    // This will ABORT with ERR_USD_VALUE_NOT_UPDATED
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        operation::execute_deposit(
            &operation,
            &cap,
            &mut vault,
            &mut reward_manager,
            &clock,
            &config,
            0, // request_id
            2_000_000_000, // max_shares_received
        ); // This aborts!
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(reward_manager);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

**File:** volo-vault/sources/volo_vault.move (L36-36)
```text
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L429-429)
```text
        status: VAULT_NORMAL_STATUS,
```

**File:** volo-vault/sources/volo_vault.move (L454-454)
```text
    vault.set_new_asset_type(type_name::get<PrincipalCoinType>().into_string());
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L752-752)
```text
    self.request_buffer.deposit_coin_buffer.add(current_deposit_id, coin);
```

**File:** volo-vault/sources/volo_vault.move (L780-781)
```text
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
```

**File:** volo-vault/sources/volo_vault.move (L820-820)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L839-839)
```text
    update_free_principal_value(self, config, clock);
```

**File:** volo-vault/sources/volo_vault.move (L1265-1266)
```text
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L1365-1366)
```text
    self.assets_value.add(asset_type, 0);
    self.assets_value_updated.add(asset_type, 0);
```

**File:** volo-vault/sources/oracle.move (L129-129)
```text
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
```

**File:** volo-vault/tests/deposit/deposit.test.move (L1740-1763)
```text
    // Set mock aggregator and price (1SUI = 2U)
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        // Set SUI price to 2
        vault_oracle::set_aggregator(
            &mut oracle_config,
            &clock,
            sui_asset_type,
            9,
            MOCK_AGGREGATOR_SUI,
        );

        clock::set_for_testing(&mut clock, 1000);
        vault_oracle::set_current_price(
            &mut oracle_config,
            &clock,
            sui_asset_type,
            2 * ORACLE_DECIMALS,
        );

        test_scenario::return_shared(oracle_config);
    };
```
