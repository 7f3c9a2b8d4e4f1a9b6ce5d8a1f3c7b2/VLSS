# Audit Report

## Title
Circular Receipt Dependencies Between Same-Type Vaults Cause Permanent DoS

## Summary
A commented-out type-safety check in `update_receipt_value()` allows two vault instances with identical principal coin types to hold receipts from each other. Combined with the zero-tolerance staleness requirement (`MAX_UPDATE_INTERVAL = 0`), this creates an unresolvable circular dependency that permanently disables all critical operations in both vaults.

## Finding Description

The `receipt_adaptor::update_receipt_value` function contains a commented-out assertion that would prevent same-type vault circular dependencies: [1](#0-0) 

The developer comment incorrectly assumes Move's borrow checker prevents the vulnerability by disallowing the same vault object to be passed twice. However, Move's borrow checker only prevents passing the **same object instance** as both `&mut` and `&` parameters. It does **not** prevent passing two **different object instances with the same generic type parameter** (e.g., `VaultA<USDC>` at address 0x123 and `VaultB<USDC>` at address 0x456).

**Root Cause Chain**:

When updating receipt values, the function invokes:
- `get_receipt_value()` at [2](#0-1) 
- Which calls `vault.get_share_ratio(clock)` at [3](#0-2) 
- Which calls `self.get_total_usd_value(clock)` at [4](#0-3) 

The `get_total_usd_value` function enforces strict staleness requirements for ALL vault assets: [5](#0-4) 

With `MAX_UPDATE_INTERVAL` set to zero: [6](#0-5) 

This requires `now - last_update_time <= 0`, meaning all assets must be updated in the **current transaction** at the **current timestamp**.

**Circular Dependency Deadlock**:

When `VaultA<USDC>` holds `receiptB` (from `VaultB<USDC>`) and `VaultB<USDC>` holds `receiptA` (from `VaultA<USDC>`):

1. To update VaultA's `receiptB` value, the system must call `update_receipt_value<USDC, USDC>(vaultA, vaultB, ...)`
2. This internally calls `vaultB.get_total_usd_value(clock)`
3. VaultB's total USD calculation checks ALL its assets, including `receiptA` from VaultA
4. Since `receiptA` hasn't been updated in the current transaction, `last_update_time < current_timestamp`
5. The assertion `now - last_update_time <= 0` fails → transaction aborts with `ERR_USD_VALUE_NOT_UPDATED`
6. Attempting to update VaultB's `receiptA` first encounters the symmetric problem
7. Neither vault can update its receipt value first, creating permanent deadlock

## Impact Explanation

Both vaults become permanently unable to update their receipt asset values, blocking all critical operations that require fresh total USD values:

**Deposit Execution** requires `get_total_usd_value(clock)`: [7](#0-6) [8](#0-7) 

**Withdrawal Execution** requires `get_share_ratio(clock)` which internally calls `get_total_usd_value`: [9](#0-8) 

**Operation Start** requires `get_total_usd_value(clock)`: [10](#0-9) 

**Operation End** requires `get_total_usd_value(clock)`: [11](#0-10) 

All users with funds deposited in either affected vault lose access to deposits, withdrawals, redemptions, and DeFi operations. The vaults are effectively bricked with no automatic recovery mechanism. Manual administrative removal of receipts may be possible via `remove_defi_asset_support`, but this requires vault to be in NORMAL status, which cannot be achieved if any operation was started.

## Likelihood Explanation

**Entry Point**: Operators can add receipts as DeFi assets using the public function: [12](#0-11) 

**Feasible Preconditions**:
1. Operator possesses legitimate `OperatorCap` (trusted role, not a compromise)
2. Two or more vaults exist with identical principal coin types (e.g., multiple `Vault<USDC>` instances for different strategies)
3. Operator adds receipt from VaultB to VaultA's assets via `add_new_defi_asset`
4. Operator adds receipt from VaultA to VaultB's assets via `add_new_defi_asset`

**Execution Practicality**: The circular dependency triggers immediately upon the first attempt to update receipt values after both cross-references are established. No complex attack choreography is required.

**Economic Rationality**: This scenario could occur unintentionally during legitimate vault composability setup (e.g., constructing vault-of-vaults architectures for layered yield strategies). The presence of the commented-out check indicates developers anticipated this risk but incorrectly concluded Move's type system provided adequate protection.

**Probability Assessment**: Medium to High - any operator configuring cross-vault composability features with same-type vaults would encounter this issue during normal operations.

## Recommendation

Uncomment and enforce the type-safety check in `update_receipt_value`:

```move
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Enforce type safety: prevent circular dependencies between same-type vaults
    assert!(
        type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
        ERR_NO_SELF_VAULT,
    );
    
    receipt_vault.assert_normal();
    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);
    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

This prevents `VaultA<USDC>` from holding receipts from `VaultB<USDC>`, eliminating circular dependency scenarios. Vault-of-vault structures remain possible using different principal types (e.g., `Vault<SUI>` holding receipts from `Vault<USDC>`).

## Proof of Concept

```move
#[test]
public fun test_circular_receipt_deadlock() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Initialize two USDC vaults
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<USDC_TEST_COIN>(&mut scenario); // VaultA
    scenario.next_tx(OWNER);
    init_vault::init_create_vault<USDC_TEST_COIN>(&mut scenario); // VaultB
    
    // Setup oracle
    scenario.next_tx(OWNER);
    let mut oracle_config = scenario.take_shared<OracleConfig>();
    test_helpers::set_aggregators(&mut scenario, &mut clock, &mut oracle_config);
    test_helpers::set_prices(&mut scenario, &mut clock, &mut oracle_config, 
        vector[1 * ORACLE_DECIMALS]);
    
    // Create receiptA from VaultA and receiptB from VaultB
    scenario.next_tx(OWNER);
    let mut vault_a = scenario.take_shared<Vault<USDC_TEST_COIN>>();
    let receipt_a = receipt::create_receipt(vault_a.vault_id(), scenario.ctx());
    scenario.return_shared(vault_a);
    
    scenario.next_tx(OWNER);
    let mut vault_b = scenario.take_shared<Vault<USDC_TEST_COIN>>();
    let receipt_b = receipt::create_receipt(vault_b.vault_id(), scenario.ctx());
    scenario.return_shared(vault_b);
    
    // Operator adds receiptB to VaultA
    scenario.next_tx(OWNER);
    let mut vault_a = scenario.take_shared<Vault<USDC_TEST_COIN>>();
    let operation = scenario.take_shared<Operation>();
    let cap = scenario.take_from_sender<OperatorCap>();
    operation::add_new_defi_asset<USDC_TEST_COIN, Receipt>(
        &operation, &cap, &mut vault_a, 0, receipt_b
    );
    
    // Operator adds receiptA to VaultB
    let mut vault_b = scenario.take_shared<Vault<USDC_TEST_COIN>>();
    operation::add_new_defi_asset<USDC_TEST_COIN, Receipt>(
        &operation, &cap, &mut vault_b, 0, receipt_a
    );
    
    // Attempt to update VaultA's receipt value - WILL FAIL
    // Because it requires VaultB.get_total_usd_value(), which requires
    // VaultB's receiptA (from VaultA) to be updated, creating circular deadlock
    receipt_adaptor::update_receipt_value<USDC_TEST_COIN, USDC_TEST_COIN>(
        &mut vault_a, &vault_b, &oracle_config, &clock, 
        vault_utils::parse_key<Receipt>(0)
    ); // ABORTS with ERR_USD_VALUE_NOT_UPDATED
    
    // All subsequent operations on both vaults are permanently blocked
}
```

### Citations

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L23-28)
```text
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L33-33)
```text
    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L49-49)
```text
    let share_ratio = vault.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L825-825)
```text

```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1006)
```text
    let ratio = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1266)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L1308-1308)
```text
    let total_usd_value = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L565-574)
```text
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```
