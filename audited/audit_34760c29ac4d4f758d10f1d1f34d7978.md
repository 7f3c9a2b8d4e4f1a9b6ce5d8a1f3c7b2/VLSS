### Title
Missing OracleHolder Instance Validation in Supra Oracle Integration

### Summary
The oracle system's `update_single_price` function accepts any `OracleHolder` object of the correct type from the Supra oracle package without validating which specific instance is being used. Unlike the Pyth integration which validates the price feed identifier, the Supra integration has no mechanism to ensure callers are using the legitimate/official OracleHolder, allowing an attacker to potentially reference a compromised, test, or deprecated OracleHolder instance to manipulate price data.

### Finding Description

The vulnerability exists in the oracle price update mechanism that integrates with Supra oracle: [1](#0-0) 

The `update_single_price` function is declared as a **public function** (not entry, but callable via Programmable Transaction Blocks in Sui), accepting `supra_oracle_holder: &OracleHolder` as a parameter. This function is callable by any external user without capability requirements.

When processing Supra oracle data, the system extracts the configured `pair_id` and queries the provided OracleHolder: [2](#0-1) 

**Critical Gap**: There is NO validation to ensure the `OracleHolder` being used is the legitimate/official one. Compare this with Pyth integration which explicitly validates the price feed identifier: [3](#0-2) 

For Pyth, line 177 asserts that the identifier extracted from `PriceInfoObject` matches the configured `pair_id`, preventing use of wrong price feeds. **No equivalent check exists for Supra**.

The `OracleHolder` type is imported from an external package: [4](#0-3) 

While Sui Move's type system ensures the object must be of type `SupraOracle::SupraSValueFeed::OracleHolder` from the correct package address, it does NOT validate which specific instance of that type is being used. The SupraOracle package dependency is resolved from git without a pinned `published-at` address: [5](#0-4) 

**Root Cause**: The oracle configuration stores only the `pair_id` (which asset pair to query), but does NOT store or validate the OracleHolder object ID itself: [6](#0-5) 

The `OracleProviderConfig` contains `pair_id` but has no field for whitelisting specific OracleHolder object instances.

### Impact Explanation

**Direct Impact**: An attacker who can reference a compromised, test, or deprecated `OracleHolder` instance can inject manipulated price data into the protocol's oracle system. This leads to:

1. **Vault Asset Misvaluation**: Manipulated prices affect `total_usd_value` calculations used for loss tolerance checks and share pricing
2. **Liquidation Manipulation**: In the integrated Navi lending protocol, false prices can trigger improper liquidations or prevent legitimate ones
3. **Operation Value Fraud**: Vault operations rely on oracle prices for `update_free_principal_value` and `update_coin_type_asset_value` checks

**Affected Parties**: All vault depositors and protocol users who rely on oracle-dependent operations.

**Severity Justification**: While the five-layer validation pipeline provides some protection (freshness checks, range bounds, historical consistency), these only validate price properties, not data source authenticity. If an attacker controls the OracleHolder being queried, they control the raw price data that enters the validation pipeline. An attacker staying within configured bounds (e.g., within `maximum_effective_price` and `minimum_effective_price`) while gradually manipulating prices could bypass these checks.

### Likelihood Explanation

**Attacker Capabilities**: An untrusted user with ability to:
1. Call public functions via Programmable Transaction Blocks (PTBs) in Sui
2. Reference shared objects by their object IDs in transactions
3. Discover object IDs on-chain (publicly visible)

**Attack Complexity**: MEDIUM
- Attacker must identify a different `OracleHolder` instance they can leverage
- Oracle providers like Supra typically deploy multiple holders for different purposes (production, testnet, different asset pairs, deprecated versions during upgrades)
- If any non-official OracleHolder is accessible on mainnet, it can be referenced

**Feasibility Conditions**:
- **Highly Probable**: Oracle providers commonly have multiple shared object instances for different feeds/environments
- No on-chain mechanism prevents referencing any OracleHolder of the correct type
- The function has no capability requirements (unlike `update_token_price` which requires `OracleFeederCap`)

**Detection/Operational Constraints**: 
- Cross-source validation only helps if BOTH primary and secondary sources are from different, legitimate providers
- If Supra is used as both primary and secondary, or if secondary is disabled, the cross-validation layer is ineffective
- Events are emitted but price manipulation within bounds may not trigger alerts

**Probability Reasoning**: While an attacker cannot create a completely fake OracleHolder (struct privacy enforced by Move), the absence of instance-level validation creates a realistic attack vector if multiple OracleHolder objects exist on-chain.

### Recommendation

**Immediate Fix**: Add OracleHolder object ID validation similar to Pyth's pair_id check:

1. Extend `OracleProviderConfig` to store the expected `OracleHolder` object ID for Supra providers:
```
struct OracleProviderConfig has store {
    provider: OracleProvider,
    enable: bool,
    pair_id: vector<u8>,
    expected_holder_id: Option<address>, // New field for Supra
}
```

2. In `get_price_from_adaptor`, validate the OracleHolder object ID:
```
if (provider == provider::supra_provider()) {
    let supra_pair_id = oracle::adaptor_supra::vector_to_pair_id(pair_id);
    
    // Add validation
    let holder_id = object::id_to_address(&object::id(supra_oracle_holder));
    let expected_holder_id = config::get_expected_holder_id(oracle_provider_config);
    assert!(holder_id == expected_holder_id, error::invalid_oracle_holder());
    
    let (price, timestamp) = oracle::adaptor_supra::get_price_to_target_decimal(supra_oracle_holder, supra_pair_id, target_decimal);
    return (price, timestamp)
}
```

3. Add administrative functions to set/update the expected OracleHolder ID per feed configuration

**Alternative**: Make `update_single_price` a friend function instead of public, and create a proper entry function wrapper that performs OracleHolder validation before calling it.

**Test Cases**:
- Attempt to call with wrong OracleHolder object ID (should fail)
- Verify legitimate OracleHolder with correct ID works
- Test administrative functions for updating expected holder IDs
- Ensure backward compatibility if holder IDs need to change (e.g., during Supra upgrades)

### Proof of Concept

**Initial State**:
1. Protocol deployed with Supra oracle configured as primary price source
2. Legitimate `OracleHolder` instance at address `0xLEGIT...` contains correct prices
3. Alternative `OracleHolder` instance at address `0xFAKE...` exists (could be test/deprecated/compromised)

**Attack Steps**:

1. Attacker discovers the alternative OracleHolder object ID `0xFAKE...` by scanning on-chain objects or using a test instance
2. Attacker constructs a PTB calling `oracle_pro::update_single_price`:
   ```
   PTB:
   - Input: supra_oracle_holder = shared_object(0xFAKE...)
   - Call: update_single_price(clock, oracle_config, price_oracle, 0xFAKE..., pyth_price_info, feed_address)
   ```
3. The function accepts the fake OracleHolder (type check passes)
4. System queries pair_id from the fake holder, receives manipulated price
5. If price is within configured bounds, it passes validation and updates `PriceOracle`

**Expected Result**: Transaction should abort with "invalid oracle holder" error

**Actual Result**: Transaction succeeds, manipulated price is stored in PriceOracle, affecting all downstream oracle consumers

**Success Condition**: Protocol accepts price data from an OracleHolder that is NOT the intended official instance, demonstrating lack of instance-level validation.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-54)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L169-172)
```text
        if (provider == provider::supra_provider()) {
            let supra_pair_id = oracle::adaptor_supra::vector_to_pair_id(pair_id);
            let (price, timestamp) = oracle::adaptor_supra::get_price_to_target_decimal(supra_oracle_holder, supra_pair_id, target_decimal);
            return (price, timestamp)
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L175-179)
```text
        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_supra.move (L4-4)
```text
    use SupraOracle::SupraSValueFeed::{Self as supra, OracleHolder};
```

**File:** volo-vault/local_dependencies/protocol/oracle/Move.toml (L11-14)
```text
[dependencies.SupraOracle]
git = "https://github.com/naviprotocol/supra-oracle.git"
subdir = "supra_holder"
rev = "main"
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_provider.move (L6-10)
```text
    struct OracleProviderConfig has store {
        provider: OracleProvider,
        enable: bool,
        pair_id: vector<u8>,
    }
```
