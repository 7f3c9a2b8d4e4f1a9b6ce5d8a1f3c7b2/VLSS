### Title
Switchboard Aggregator Version Incompatibility Causes Permanent DoS of Oracle Price Updates

### Summary
If the Switchboard aggregator module upgrades its VERSION constant from 1 to 2 without coordinated updates to all action modules, newly created aggregators will permanently fail all action operations (set_authority, set_configs, submit_result, delete) until the action modules are updated. This causes critical oracle price feeds to become stale, triggering a complete DoS of all Volo vault operations that depend on oracle prices.

### Finding Description

The Switchboard aggregator system implements version checking across all modules but lacks a version migration mechanism:

**Aggregator Version Definition:** [1](#0-0) 

The version is set immutably at creation: [2](#0-1) 

**Action Module Version Checks:**
All action modules enforce strict version matching. For example, `aggregator_set_authority_action`: [3](#0-2) [4](#0-3) 

The same pattern exists in all other action modules: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

**Critical Issue:** There is NO function to update the version field on existing aggregators, and no version migration mechanism exists (verified by searching the entire codebase).

**Impact Path to Volo Vault:**
The vault relies on Switchboard aggregators for price feeds: [11](#0-10) 

Oracles must call `aggregator_submit_result_action::run()` to submit new price data. If this fails due to version mismatch, prices become stale. The vault enforces staleness checks: [12](#0-11) [13](#0-12) 

Stale prices cause all vault operations to fail: [14](#0-13) 

### Impact Explanation

**Concrete Harm:**
1. All newly created Switchboard aggregators (with version=2) become permanently unusable for price submissions
2. Existing aggregator prices become stale within 1 minute (MAX_UPDATE_INTERVAL)
3. All vault operations requiring oracle prices fail with ERR_PRICE_NOT_UPDATED
4. Complete DoS of: deposits, withdrawals, vault operations, and any function calling `get_asset_price()` or `get_normalized_asset_price()`

**Affected Parties:**
- All Volo vault users unable to deposit/withdraw funds
- All vault operators unable to execute operations
- All protocols integrating with the vault

**Severity Justification:**
HIGH - This causes complete operational failure of the vault's core functionality (deposits, withdrawals, operations) until the action modules are updated, potentially lasting hours or days depending on upgrade coordination.

### Likelihood Explanation

**Feasibility Conditions:**
- Switchboard team upgrades aggregator module to VERSION=2
- Action modules are not updated simultaneously
- New aggregators are created with version=2

**Probability Reasoning:**
This is a realistic operational risk because:
1. The codebase shows multiple historical package upgrades have occurred [15](#0-14) 

2. There's no automated coupling between aggregator module upgrades and action module updates
3. No version migration function exists to update existing aggregators
4. The design requires manual coordination across 5+ separate modules

**Complexity:** Low - This occurs naturally through normal upgrade processes without coordination

**Detection:** May not be detected until production deployment when oracles attempt to submit prices

### Recommendation

**Immediate Mitigations:**
1. Add a version migration function to the aggregator module:
```move
public(package) fun migrate_version(aggregator: &mut Aggregator, new_version: u8) {
    aggregator.version = new_version;
}
```

2. Add a dynamic version check that supports a version range:
```move
const MIN_SUPPORTED_AGGREGATOR_VERSION: u8 = 1;
const MAX_SUPPORTED_AGGREGATOR_VERSION: u8 = 2;
assert!(
    aggregator.version() >= MIN_SUPPORTED_AGGREGATOR_VERSION && 
    aggregator.version() <= MAX_SUPPORTED_AGGREGATOR_VERSION,
    EInvalidAggregatorVersion
);
```

**Long-term Solutions:**
1. Implement an upgrade coordination script that updates all related modules atomically
2. Add deployment tests that verify version compatibility across all modules
3. Document the upgrade sequence requirements in the package documentation
4. Consider removing version checks for backward-compatible changes

**Test Cases:**
- Test aggregator creation with version=2 against action modules expecting version=1
- Test vault operations when aggregator prices become stale due to submission failures
- Test version migration function if implemented

### Proof of Concept

**Initial State:**
- Switchboard aggregator module deployed with VERSION=1
- All action modules deployed with EXPECTED_AGGREGATOR_VERSION=1
- Vault configured with existing aggregators

**Attack Sequence:**
1. Switchboard team upgrades aggregator module: `const VERSION: u8 = 2`
2. New aggregator created via `aggregator_init_action::run()` → creates aggregator with version=2
3. Vault admin adds new aggregator: `vault_manage::add_switchboard_aggregator()`
4. Oracle attempts to submit price: `aggregator_submit_result_action::run()` → **FAILS with EInvalidAggregatorVersion**
5. 60 seconds pass
6. Any vault user attempts deposit/withdrawal → **FAILS with ERR_PRICE_NOT_UPDATED**

**Expected Result:** Oracle price submissions succeed, vault operations continue normally

**Actual Result:** Oracle submissions fail permanently, vault experiences complete DoS after 60 seconds

**Success Condition:** Vault operations fail indefinitely until action modules are upgraded to expect version=2

**Notes:**
This is an operational vulnerability caused by lack of version migration mechanisms and upgrade coordination requirements. While not exploitable by untrusted users, it represents a critical design flaw that can cause extended production outages.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L10-10)
```text
const VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L216-216)
```text
        version: VERSION,
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_authority_action.move (L6-6)
```text
const EXPECTED_AGGREGATOR_VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_authority_action.move (L20-20)
```text
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L6-6)
```text
const EXPECTED_AGGREGATOR_VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L41-41)
```text
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L13-13)
```text
const EXPECTED_AGGREGATOR_VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L57-57)
```text
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_delete_action.move (L6-6)
```text
const EXPECTED_AGGREGATOR_VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_delete_action.move (L18-18)
```text
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);
```

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
```

**File:** volo-vault/sources/oracle.move (L135-135)
```text
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/oracle.move (L254-254)
```text
    let current_result = aggregator.current_result();
```

**File:** volo-vault/sources/oracle.move (L259-259)
```text
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/Move.mainnet.toml (L10-23)
```text
# Old version:
# First Publish: 0x0b884dbc39d915f32a82cc62dabad75ca3efd3c568c329eba270b03c6f58cbd8
# Second Publish: 0x1b03b77082cdb9d6b3febc6294f36d999d8556583616fadc84199a8e66371d60
# Third Publish: 0xbd22434e506314abc0cd981447fbf42139fa04aa09b5a8a7d7789826883e8e0a
# AdminCap: 0xe10be54c1686c5d5e6ccd74b7589a7362e7d075d6e4c513c8af379fdaf4c5f36
# State: 0x90a2829005435005300abaf7ce8115814b38c8d42a6de5aaf311774c60603b68
# UpgradeCap: 0xda0d1de2ce8afde226f66b1963c3f6afc929ab49eaeed951c723a481499e31e9

# New version:
# First Publish: 0xc3c7e6eb7202e9fb0389a2f7542b91cc40e4f7a33c02554fec11c4c92f938ea3
# Second Publish: 0xe6717fb7c9d44706bf8ce8a651e25c0a7902d32cb0ff40c0976251ce8ac25655
# AdminCap: 0xf02428df77e94f22df093b364d7e2b47cacb96a1856f49f5e1c4927705d50050
# State: 0x93d2a8222bb2006d16285ac858ec2ae5f644851917504b94debde8032664a791
# UpgradeCap: 0xe4b73392789cbda0420785a98eae24a4eef3a263317247c16fd1d192c1db2b93
```
