### Title
Unbounded min_attestations Configuration Enables Complete Oracle System DoS

### Summary
The `set_configs()` function in the Switchboard queue schema lacks upper bound validation for the `min_attestations` parameter. A queue authority can set `min_attestations` to a value exceeding the number of available guardian oracles, permanently preventing any oracle from accumulating sufficient attestations to become enabled. This causes a complete denial of service of the Volo vault's price oracle system, blocking all pricing-dependent operations.

### Finding Description

The vulnerability exists in the queue configuration system across multiple files: [1](#0-0) 

The `set_configs()` function directly assigns the `min_attestations` parameter without any upper bound validation. The only validation occurs in the action wrapper: [2](#0-1) 

This validation only enforces `min_attestations > 0` (line 35) with no upper bound check against the actual number of available guardian oracles in the queue.

**Root Cause**: The protocol never validates that `min_attestations` is achievable given the current set of guardian oracles. The `Queue` struct maintains an `existing_oracles` table but never compares `min_attestations` against the count of available guardians.

**Why Existing Protections Fail**:
1. No tracking of guardian oracle count in the Queue struct
2. No comparison between `min_attestations` and actual guardian availability
3. The error constant `EInvalidMinAttestations` only triggers for zero values

**Execution Path to DoS**:

Step 1 - Oracle attestation requirement: [3](#0-2) 

Oracles are only enabled when `valid_attestation_count >= queue.min_attestations()`. If `min_attestations` exceeds available guardians, this condition can never be satisfied.

Step 2 - Oracle submission validation: [4](#0-3) 

Only enabled oracles (with `expiration_time_ms > current_time`) can submit price updates to aggregators. Non-enabled oracles fail this check.

Step 3 - Vault price staleness check: [5](#0-4) 

The Volo vault's `get_asset_price()` function enforces a staleness check (line 135). Without oracle updates, prices become stale beyond the `update_interval` (default 60 seconds), causing all price queries to revert with `ERR_PRICE_NOT_UPDATED`.

### Impact Explanation

**Concrete Harm**:
- Complete denial of service of the Volo vault's oracle price system
- All vault operations requiring asset pricing become permanently unavailable, including:
  - Deposit/withdrawal processing that needs USD valuation
  - Operation execution requiring asset price verification
  - Health factor checks in DeFi adaptor operations
  - Loss tolerance calculations based on USD values

**Quantified Damage**:
- 100% operational DoS of pricing-dependent vault functions
- Within 60 seconds of the last valid price update, all `get_asset_price()` calls revert
- No automatic recovery mechanism exists - requires reconfiguration of the external Switchboard queue

**Affected Parties**:
- All Volo vault users unable to deposit, withdraw, or interact with operations
- Protocol operations frozen due to missing price data
- DeFi integrations (Navi, Suilend, Cetus) cannot execute due to missing valuations

**Severity Justification**: HIGH
- Critical operational dependency on oracle pricing
- Complete system DoS with no fallback mechanism
- Affects core vault functionality and all user interactions
- Can occur via misconfiguration or malicious queue authority action

### Likelihood Explanation

**Attacker Capabilities**:
- Requires control of the Switchboard queue authority (external to Volo admin)
- Can be triggered by a single transaction
- Could occur through compromise of queue authority OR accidental misconfiguration

**Attack Complexity**: LOW
- Single function call with one parameter set incorrectly
- No complex state manipulation required
- Example: `queue_set_configs_action::run(..., min_attestations: 1000000, ...)`

**Feasibility Conditions**:
- Queue authority access (realistic for external dependency)
- No technical barriers to execution
- Misconfiguration is a realistic scenario given lack of validation

**Detection/Operational Constraints**:
- Effect is immediate and obvious (oracle system stops functioning)
- However, by the time detected, damage is done
- Recovery requires queue authority to reconfigure with valid parameters

**Probability Reasoning**:
- Misconfiguration risk: MEDIUM (no validation prevents operator error)
- Malicious attack risk: LOW to MEDIUM (depends on queue authority security)
- Overall likelihood: MEDIUM (feasible through multiple realistic scenarios)

### Recommendation

**Code-Level Mitigation**:

Add upper bound validation in the queue configuration validation function: [2](#0-1) 

Modify the validation to include:
```move
public fun validate(
    queue: &Queue,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    ctx: &TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(min_attestations > 0, EInvalidMinAttestations);
    
    // NEW: Add upper bound check against available oracles
    let oracle_count = queue.existing_oracles().length();
    assert!(min_attestations <= oracle_count, EMinAttestationsExceedsOracles);
    
    assert!(oracle_validity_length_ms > 0, EInvalidOracleValidityLength);
}
```

**Invariant Checks to Add**:
1. `min_attestations <= count(existing_oracles)` enforced at configuration time
2. Consider adding a reasonable maximum threshold (e.g., `min_attestations <= MAX_REASONABLE_ATTESTATIONS`)
3. Track and expose oracle count in Queue struct for validation

**Test Cases to Prevent Regression**:
1. Test setting `min_attestations` equal to oracle count (should pass)
2. Test setting `min_attestations` greater than oracle count (should fail)
3. Test setting `min_attestations` to extreme values like `u64::MAX` (should fail)
4. Integration test verifying oracles can still be enabled after configuration changes

Apply the same validation to `guardian_queue_init_action` and `oracle_queue_init_action` initialization functions.

### Proof of Concept

**Required Initial State**:
- Switchboard guardian queue with N guardians (e.g., 10 guardians)
- Oracle queue referencing the guardian queue
- Volo vault configured to use Switchboard aggregators for pricing

**Transaction Steps**:

1. **Misconfigure Queue** (as queue authority):
   ```
   Call: queue_set_configs_action::run(
       queue: &mut queue_object,
       name: "Oracle Queue",
       fee: 0,
       fee_recipient: authority_address,
       min_attestations: 1000000,  // Far exceeds available guardians
       oracle_validity_length_ms: valid_value,
       ctx: &mut tx_context
   )
   ```
   
   **Expected**: Transaction succeeds (validation only checks > 0)
   **Actual**: Transaction succeeds, `min_attestations` set to 1,000,000

2. **Attempt Oracle Attestation** (as guardian):
   Multiple guardians attempt to attest an oracle, accumulating attestations.
   
   **Expected**: Oracle becomes enabled after receiving 1,000,000 attestations
   **Actual**: With only 10 guardians, maximum 10 attestations possible. Oracle never reaches enabled state.

3. **Attempt Price Update** (as oracle):
   ```
   Call: aggregator_submit_result_action::run(...)
   ```
   
   **Expected**: Price update succeeds
   **Actual**: Reverts with `EOracleInvalid` - oracle expiration_time_ms check fails

4. **Vault Price Query** (any user):
   After 60+ seconds without updates:
   ```
   Call: vault_oracle::get_asset_price(config, clock, asset_type)
   ```
   
   **Expected**: Returns current price
   **Actual**: Reverts with `ERR_PRICE_NOT_UPDATED` - price staleness check fails

**Success Condition**: Complete DoS of oracle price system confirmed when all price queries revert and vault operations dependent on pricing become unavailable.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L180-193)
```text
public(package) fun set_configs(
    queue: &mut Queue,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
) {
    queue.name = name;
    queue.fee = fee;
    queue.fee_recipient = fee_recipient;
    queue.min_attestations = min_attestations;
    queue.oracle_validity_length_ms = oracle_validity_length_ms;
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_configs_action.move (L27-37)
```text
public fun validate(
    queue: &Queue,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    ctx: &TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(min_attestations > 0, EInvalidMinAttestations);
    assert!(oracle_validity_length_ms > 0, EInvalidOracleValidityLength);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-123)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L62-63)
```text
    // verify that the oracle is up
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
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
