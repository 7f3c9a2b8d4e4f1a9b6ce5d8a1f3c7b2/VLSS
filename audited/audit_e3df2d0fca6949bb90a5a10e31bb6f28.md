### Title
Navi Position Valuation DoS via Unsupported Asset Injection

### Summary
An attacker can permanently DoS vault operations by depositing unsupported assets into the vault's Navi lending account. When the vault attempts to calculate the Navi position value, the oracle lookup will abort for unsupported coin types, preventing the vault from completing operations. This attack costs minimal funds (1 unit of any token), is repeatable, and blocks all vault functionality including deposits, withdrawals, and strategy execution.

### Finding Description

The vulnerability exists in the Navi position valuation flow: [1](#0-0) 

The `calculate_navi_position_value` function iterates through all reserves in Navi storage. For any reserve where the vault's account has a non-zero balance (lines 58-61 skip only if both supply and borrow are zero), it attempts to fetch the asset price from the oracle at line 63: [2](#0-1) 

The oracle's `get_asset_price` function will abort if the asset type is not registered: [3](#0-2) 

The abort occurs at line 129 with `ERR_AGGREGATOR_NOT_FOUND` when the asset_type is not in the aggregators table.

**Attack Vector**: The Navi protocol allows anyone to deposit assets on behalf of any user address via a public entry function: [4](#0-3) 

This function is publicly accessible and allows the caller to specify any `user` address to receive the deposit. The underlying deposit function only validates that the amount is non-zero: [5](#0-4) 

**Impact Chain**: The position value update is mandatory during vault operations. After returning borrowed assets, the vault enforces that all borrowed asset types have their values updated: [6](#0-5) 

This check at lines 1215-1218 ensures every borrowed asset type (including the NaviAccountCap) has been updated. If the update fails due to the oracle abort, operations cannot complete: [7](#0-6) 

### Impact Explanation

**Direct Operational Impact**: The vault becomes unable to complete any operations, effectively freezing all functionality:
- Deposit requests cannot be processed
- Withdrawal requests cannot be executed  
- Strategy rebalancing operations fail
- All user funds remain locked in the vault

**Affected Parties**: 
- All vault depositors lose access to their funds
- Protocol loses all operational capability
- Revenue generation stops entirely

**Severity Justification**: This is a HIGH severity issue because:
1. Complete DoS of core protocol functionality
2. All user funds effectively locked (not stolen, but inaccessible)
3. No privileged access required to execute
4. Recovery is difficult and attacker can immediately re-grief

### Likelihood Explanation

**Attacker Capabilities**: Any external user with minimal funds can execute this attack by:
1. Identifying a coin type supported by Navi but not registered in the vault's oracle config
2. Querying the vault's NaviAccountCap to obtain the account owner address (the vault is a shared object)
3. Calling `entry_deposit_on_behalf_of_user` with 1 unit of the unsupported coin type

**Attack Complexity**: Very low - requires only:
- One transaction with minimal gas
- 1 unit of any unsupported token (attacker can withdraw later with interest)
- No special permissions or complex setup

**Economic Rationality**: Highly favorable to attacker:
- Cost: Negligible (1 unit of token + gas, funds recoverable)
- Benefit: Complete protocol DoS
- Repeatable: Can re-execute after each recovery attempt
- Multiple attack vectors: Can use different unsupported coins simultaneously

**Feasibility Conditions**: All preconditions are standard:
- Navi protocol's public deposit function is working as designed
- Vault's oracle config intentionally doesn't include all possible Navi assets
- No authentication check on deposit-on-behalf functionality

### Recommendation

**Primary Fix**: Add a try-catch pattern or skip unsupported assets in `calculate_navi_position_value`:

```move
// In calculate_navi_position_value, modify the price lookup:
if (supply == 0 && borrow == 0) {
    i = i - 1;
    continue
};

// Add check: skip if price feed not available
if (!vault_oracle::has_price_feed(config, coin_type)) {
    i = i - 1;
    continue
};

let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

Add a helper function to oracle.move:
```move
public fun has_price_feed(config: &OracleConfig, asset_type: String): bool {
    config.aggregators.contains(asset_type)
}
```

**Alternative Fix**: Restrict Navi deposit-on-behalf functionality by adding an allowlist, though this requires coordination with the Navi protocol team.

**Validation**: Add test cases covering:
1. Vault operations succeed when Navi account has unsupported assets with zero balance
2. Vault operations succeed when Navi account has small amounts of unsupported assets  
3. Oracle lookups don't abort the entire valuation process

### Proof of Concept

**Required Initial State**:
- Vault deployed with NaviAccountCap as DeFi asset
- Oracle config has price feeds for standard assets (USDC, SUI, etc.)
- Oracle config does NOT have price feed for TOKEN_X (some obscure Navi-supported asset)

**Attack Sequence**:

1. **Discovery Phase**:
   - Query vault object to find NaviAccountCap dynamic field
   - Read AccountCap.owner address (e.g., `0xABC...`)

2. **Attack Execution**:
   - Call `incentive_v3::entry_deposit_on_behalf_of_user<TOKEN_X>`:
     - storage: Navi storage object
     - pool: TOKEN_X pool object
     - asset: TOKEN_X asset ID
     - deposit_coin: Coin<TOKEN_X> with value 1
     - amount: 1
     - user: `0xABC...` (vault's Navi account address)
     - incentive_v2/v3: incentive objects

3. **Verify DoS**:
   - Operator attempts to complete any vault operation
   - Calls `navi_adaptor::update_navi_position_value`
   - Function iterates to TOKEN_X reserve (non-zero balance)
   - Oracle lookup aborts: `ERR_AGGREGATOR_NOT_FOUND`
   - Entire operation fails, vault stuck

**Expected Result**: Operation completes successfully  
**Actual Result**: Transaction aborts with `ERR_AGGREGATOR_NOT_FOUND`, vault operations permanently blocked until manual intervention

**Success Condition**: Vault cannot complete any operations requiring position value updates, effectively DoS'd with cost of 1 token unit to attacker.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
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

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L815-831)
```text
    public entry fun entry_deposit_on_behalf_of_user<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        user: address,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_on_behalf_of_user<CoinType>(clock, storage, pool, asset, user, deposit_coin, amount, ctx);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L15-17)
```text
    public fun validate_deposit<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());
```

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
}
```

**File:** volo-vault/sources/operation.move (L299-354)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
```
