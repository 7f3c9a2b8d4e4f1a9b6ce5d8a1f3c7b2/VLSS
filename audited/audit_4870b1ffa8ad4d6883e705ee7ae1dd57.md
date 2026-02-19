### Title
Oracle Manipulation via Unauthorized Asset Value Updates Enables Fund Theft

### Summary
The `update_navi_position_value()` function in the Navi adaptor is publicly callable without any validation of which `OracleConfig` is being used. An attacker can deploy a malicious `OracleConfig` with manipulated prices, call this function to update the vault's asset valuations with fake prices, and then deposit or withdraw in the same transaction to steal funds through share ratio manipulation.

### Finding Description

The vulnerability exists in the Navi adaptor's value update function: [1](#0-0) 

This public function accepts an `OracleConfig` parameter from the caller with no validation that it is the correct/official oracle. The function:

1. Retrieves the Navi position from the vault
2. Calculates USD value using prices from the caller-provided `OracleConfig`
3. Updates the vault's asset value storage via `finish_update_asset_value()` [2](#0-1) 

The root cause is that the vault system has no stored reference to an approved `OracleConfig`. The oracle is always passed as a parameter: [3](#0-2) 

The `OracleConfig` creation happens only during module initialization, but anyone can deploy their own oracle module: [4](#0-3) 

Since the `OracleConfig` is a shared object that can be created by anyone publishing the module, and the vault accepts any `OracleConfig` reference, an attacker can:
1. Deploy a malicious oracle module with fake prices
2. Pass their malicious `OracleConfig` to `update_navi_position_value()`
3. The vault's asset values get updated with manipulated prices

The vault's deposit/withdrawal flow requires asset values to be updated in the same transaction (MAX_UPDATE_INTERVAL = 0): [5](#0-4) [6](#0-5) 

This means the attacker can update values with fake prices and immediately exploit them before anyone can correct the values.

### Impact Explanation

**Direct Fund Theft via Share Ratio Manipulation:**

When an attacker deflates asset prices:
- `total_usd_value` becomes artificially low
- `share_ratio = total_usd_value / total_shares` becomes low
- Attacker deposits and receives `new_shares = usd_deposited / share_ratio` → receives MORE shares than deserved
- When values are later corrected, those inflated shares represent stolen value from existing shareholders

When an attacker inflates asset prices before withdrawal:
- `total_usd_value` becomes artificially high  
- `share_ratio` becomes high
- Attacker withdraws and receives `amount = shares * share_ratio` → receives MORE principal than entitled
- This directly steals principal from the vault

**Quantified Impact:**
- If attacker sets prices to 10% of real value and holds 1000 shares:
  - Normal withdrawal at $100/share = $100,000
  - Later with corrected prices at $1000/share = $1,000,000
  - Net theft: $900,000 from other users

**Affected Parties:**
- All vault depositors lose proportional value
- Vault's principal balance is drained
- Protocol reputation damage

### Likelihood Explanation

**Attacker Capabilities (Minimal):**
- Can deploy Move modules on Sui mainnet (standard capability)
- Can call public functions (standard capability)
- No special permissions required

**Attack Complexity (Low):**
1. Deploy oracle module with fake prices (1 transaction)
2. Call `update_navi_position_value(vault, malicious_oracle, navi_storage, asset_type)` (atomic in same tx)
3. Call `execute_deposit` or `execute_withdraw` (atomic in same tx)

**Execution Practicality:**
- All steps executable under Sui Move semantics
- No special timing requirements (atomic transaction)
- Storage parameter can be the legitimate Navi Storage
- Only OracleConfig needs to be malicious

**Economic Rationality:**
- Cost: Gas fees for module deployment + transaction (~1-10 SUI)
- Profit: Proportional to vault size (potentially millions)
- Risk: Low (atomic transaction, no detection before execution)
- ROI: Extremely favorable

**Detection/Operational Constraints:**
- No on-chain detection mechanism
- Attack completes atomically before response possible
- Off-chain monitoring would need to track all OracleConfig deployments

This attack is highly practical and economically rational for any vault with significant TVL.

### Recommendation

**Immediate Mitigation:**

1. **Store approved OracleConfig reference in vault:**

Add an `oracle_config_id: address` field to the Vault struct and validate it in all update functions:

```move
// In Vault struct
oracle_config_id: address,

// In update functions
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    // ... other params
) {
    // Add validation
    assert!(object::id_address(config) == vault.oracle_config_id, ERR_INVALID_ORACLE);
    // ... rest of function
}
```

2. **Add similar validation for external protocol objects:**

For Navi Storage, Cetus Pools, and Suilend Markets, consider either:
- Storing approved object IDs in the vault
- Making update functions `public(package)` and creating controlled wrappers
- Adding admin-controlled allowlists for external protocol objects

3. **Add oracle staleness checks:**

Verify that prices in the OracleConfig are recent and from trusted Switchboard aggregators.

**Test Cases:**

```move
#[test]
#[expected_failure(abort_code = ERR_INVALID_ORACLE)]
fun test_update_with_wrong_oracle() {
    // Create official oracle
    let official_oracle = init_oracle();
    // Create malicious oracle
    let malicious_oracle = create_fake_oracle();
    // Try to update with wrong oracle
    update_navi_position_value(vault, malicious_oracle, ...); // Should abort
}
```

### Proof of Concept

**Initial State:**
- Official vault with $1,000,000 TVL, 1000 total_shares (share_ratio = $1000)
- Attacker has 100 shares worth $100,000
- Official OracleConfig has correct prices (SUI = $2, etc.)

**Attack Execution (Single Transaction):**

Step 1: Deploy malicious oracle module
```move
// Attacker deploys their own oracle module
module attacker::fake_oracle {
    fun init(ctx: &mut TxContext) {
        let config = OracleConfig { /* ... */ };
        // Set fake prices: SUI = $0.02 (100x deflated)
        transfer::share_object(config);
    }
}
```

Step 2: Update vault values with fake oracle
```move
// In same transaction
navi_adaptor::update_navi_position_value(
    &mut official_vault,
    &attacker_malicious_oracle, // Fake prices
    &official_navi_storage,      // Real balances
    parse_key<NaviAccountCap>(0)
);
// Vault now thinks Navi position worth $10,000 instead of $1,000,000
```

Step 3: Execute deposit with deflated values
```move
// Total USD value now artificially low at ~$10,000
// Share ratio = $10,000 / 1000 shares = $10/share
vault::execute_deposit(/* attacker deposits $100,000 */);
// Attacker receives 10,000 shares instead of 100 shares
```

**Expected Result (Without Fix):**
- Attacker gains 10,000 shares for $100,000 deposit
- When values corrected, attacker's 10,000 shares worth ~$10,000,000
- Net theft: ~$9,900,000 from existing shareholders

**Actual Result (With Fix):**
- Transaction aborts at validation: `assert!(oracle_id == vault.oracle_config_id)`
- No value manipulation possible
- Vault protected

### Citations

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L1174-1187)
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

**File:** volo-vault/sources/oracle.move (L84-94)
```text
fun init(ctx: &mut TxContext) {
    let config = OracleConfig {
        id: object::new(ctx),
        version: VERSION,
        aggregators: table::new(ctx),
        update_interval: MAX_UPDATE_INTERVAL,
        dex_slippage: DEFAULT_DEX_SLIPPAGE,
    };

    transfer::share_object(config);
}
```
