### Title
Unrestricted Public Access to Asset Value Update Functions During Vault Operations Enables Loss Tolerance Bypass and Share Manipulation

### Summary
The `update_cetus_position_value()` function and all similar adaptor value update functions are declared as `public fun`, allowing any external caller to update asset valuations via Programmable Transaction Blocks (PTBs) even during active vault operations. Since these functions only enforce `assert_enabled()` rather than `assert_normal()`, attackers can manipulate asset values while the vault is in `VAULT_DURING_OPERATION_STATUS`, bypassing loss tolerance checks and affecting share ratio calculations that impact all vault participants.

### Finding Description

**Location:** The vulnerability exists in multiple files with identical access control failures: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Root Cause:** All these functions are declared as `public fun` (not `public(package)` or `entry`), making them callable by any external address through PTBs. They call `finish_update_asset_value()` which only enforces the `assert_enabled()` check: [6](#0-5) 

The critical flaw is in the vault status check at `assert_enabled()`: [7](#0-6) 

This check only prevents calls when status is `VAULT_DISABLED_STATUS` (value 2), but **allows both** `VAULT_NORMAL_STATUS` (0) **and** `VAULT_DURING_OPERATION_STATUS` (1): [8](#0-7) 

**Why Protection Fails:** During vault operations, the status is set to `VAULT_DURING_OPERATION_STATUS`: [9](#0-8) 

At this point, the operator captures `total_usd_value_before` for later loss verification: [10](#0-9) 

However, because the update functions only check `assert_enabled()`, an attacker can call them mid-operation to directly modify the vault's `assets_value` table. When the operation completes, these manipulated values are used to calculate `total_usd_value_after` and verify losses: [11](#0-10) 

### Impact Explanation

**Direct Security Integrity Impact:**
- **Loss Tolerance Bypass**: By inflating asset values before `end_op_value_update_with_bag` is called, an attacker can make actual losses appear smaller than they are, bypassing the per-epoch loss tolerance check that would otherwise abort the transaction.

**Share Manipulation Impact:**
- The manipulated `total_usd_value` directly affects share ratio calculations used in all deposits and withdrawals
- Share ratio = `total_usd_value / total_shares`, so inflated values give users fewer shares for deposits or more funds for withdrawals
- This creates direct financial harm to vault participants

**Affected Parties:**
- All vault depositors and withdrawers during and after the attack
- The vault's economic integrity and fair share pricing mechanism
- Loss tolerance enforcement becomes meaningless

**Severity Justification:**
This is HIGH severity because:
1. It bypasses a critical security control (loss tolerance) designed to protect vault participants
2. It has measurable financial impact through share ratio manipulation
3. The attack is trivial to execute (single PTB call)
4. No special privileges are required

### Likelihood Explanation

**Reachable Entry Point:**
All affected functions are `public fun` and directly callable via PTBs by any address. No entry function wrapper is needed - PTBs can directly invoke public Move functions.

**Attacker Capabilities:**
An untrusted external attacker needs only:
1. Ability to observe when vault enters `VAULT_DURING_OPERATION_STATUS` (observable on-chain)
2. Access to oracle config and pool/storage objects (all shared objects)
3. Ability to submit a PTB transaction

**Execution Practicality:**
The attack is straightforward:
1. Monitor vault status changes via events or state queries
2. When vault enters operation mode, immediately call any update function via PTB
3. The function executes with current oracle prices, updating vault's asset values
4. Operation completes with manipulated valuation data

**Economic Rationality:**
- Attack cost: One transaction gas fee (~0.01 SUI)
- Benefit: Can hide losses or manipulate share ratios worth potentially significant value
- No special timing beyond monitoring vault status
- Repeatable on every operation

**Detection/Operational Constraints:**
- The attack leaves no special traces - it looks like a legitimate value update
- Operators cannot prevent external calls to public functions
- The vault has no mechanism to distinguish operator-initiated vs attacker-initiated updates during operations

### Recommendation

**Immediate Fix:**
Replace `assert_enabled()` with `assert_normal()` in all value update functions to prevent calls during operations:

```move
// In cetus_adaptor.move, navi_adaptor.move, suilend_adaptor.move:
public fun update_[adaptor]_position_value<...>(...) {
    // Change from implicit assert_enabled() to explicit assert_normal()
    vault.assert_normal(); // Add before get_defi_asset call
    ...
}

// In volo_vault.move:
public fun update_free_principal_value<PrincipalCoinType>(...) {
    self.check_version();
    self.assert_normal(); // Change from assert_enabled()
    ...
}

public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(...) {
    self.check_version();
    self.assert_normal(); // Change from assert_enabled()
    ...
}
```

**Alternative/Additional Mitigation:**
Consider changing all adaptor update functions from `public fun` to `public(package) fun` if they should only be called from controlled operation flows. However, this may break legitimate use cases if external value updates are intended.

**Invariant to Add:**
Assert in `finish_update_asset_value()` that if `op_value_update_record.value_update_enabled` is true, only borrowed assets should be updated:

```move
if (self.status() == VAULT_DURING_OPERATION_STATUS) {
    assert!(
        !self.op_value_update_record.value_update_enabled ||
        self.op_value_update_record.asset_types_borrowed.contains(&asset_type),
        ERR_UNAUTHORIZED_VALUE_UPDATE_DURING_OP
    );
}
```

**Test Cases:**
1. Test that `update_cetus_position_value()` aborts when vault is in `VAULT_DURING_OPERATION_STATUS`
2. Test that only operator-controlled flows can update values during operations
3. Test that value updates succeed when vault is in `VAULT_NORMAL_STATUS`

### Proof of Concept

**Initial State:**
- Vault has a Cetus position asset worth 1000 USD
- Vault is in `VAULT_NORMAL_STATUS`
- Operator holds valid `OperatorCap`

**Attack Sequence:**

1. **Operator starts operation:**
   - Calls `start_op_with_bag()` with Cetus position borrowed
   - Vault status → `VAULT_DURING_OPERATION_STATUS`
   - `total_usd_value_before` = 1000 USD (captured)

2. **Attacker exploits mid-operation:**
   ```
   PTB {
     let vault = shared_object(VAULT_ID);
     let oracle_config = shared_object(ORACLE_CONFIG_ID);
     let clock = shared_object(CLOCK_ID);
     let pool = shared_object(CETUS_POOL_ID);
     
     cetus_adaptor::update_cetus_position_value(
       vault,
       oracle_config, 
       clock,
       asset_type_string,
       pool
     );
   }
   ```
   - **Expected:** Transaction aborts due to operation in progress
   - **Actual:** Transaction succeeds, `assets_value[cetus_position]` updated with current price

3. **Operator completes operation:**
   - Real position value dropped to 800 USD (200 USD loss)
   - But attacker's update set it to 950 USD
   - Calls `end_op_value_update_with_bag()`
   - `total_usd_value_after` calculated as 950 USD
   - Loss check: `1000 - 950 = 50 USD` < tolerance limit
   - **Operation succeeds despite 200 USD actual loss**

**Success Condition:**
An operation that should fail loss tolerance validation (200 USD loss > tolerance) succeeds because attacker-manipulated values (50 USD apparent loss) pass the check.

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
```

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L1130-1154)
```text
public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();
    assert!(
        type_name::get<CoinType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<CoinType>().into_string();
    let now = clock.timestamp_ms();

    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

    finish_update_asset_value(self, asset_type, coin_usd_value, now);
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
```

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L178-193)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
