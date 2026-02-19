### Title
Oracle Expiration Deadlock Prevents Attestation Recovery and Causes Vault Operation DoS

### Summary
The Switchboard oracle attestation system contains a critical flaw where expired oracles cannot receive new attestations due to an expiration check that blocks all attestation attempts. This creates a deadlock state requiring admin intervention to recover, and during the recovery period, vault deposit/withdrawal operations fail due to stale price data, causing operational DoS.

### Finding Description

The vulnerability exists in the oracle attestation validation flow. When an oracle expires (or is newly created), it enters a state where it cannot receive attestations through the normal decentralized mechanism.

**Root Cause:**

In the attestation validation function, there is a check that prevents attestations to expired oracles: [1](#0-0) 

This check requires `oracle.expiration_time_ms() > clock.timestamp_ms()`, blocking attestations to any oracle where the expiration time has passed.

**Why This Creates a Deadlock:**

New oracles are initialized with `expiration_time_ms = 0`: [2](#0-1) 

The `expiration_time_ms` field is only updated when `enable_oracle` is called, which happens either:
1. When enough attestations accumulate to meet the threshold (requires passing the expiration check first)
2. Via admin override through the queue authority [3](#0-2) [4](#0-3) 

This creates a circular dependency: expired oracles need attestations to be re-enabled, but cannot receive attestations because they are expired.

**Impact on Price Submission:**

Once an oracle expires, it cannot submit new price data to aggregators because price submissions also check oracle expiration: [5](#0-4) 

This causes aggregator prices to become stale, which cascades to vault operations.

**Impact on Vault Operations:**

The Volo vault relies on these Switchboard aggregator prices for critical operations. When prices become stale, vault operations fail: [6](#0-5) 

Vault adaptors for Cetus, Navi, and Momentum all require fresh oracle prices for valuation: [7](#0-6) 

### Impact Explanation

**Operational DoS Impact:**
- When an oracle expires, all vault deposit and withdrawal operations become blocked because they require fresh oracle prices for asset valuation
- The staleness check enforces a 1-minute maximum update interval, so the DoS begins within minutes of oracle expiration
- All DeFi adaptor operations (Cetus CLMM, Navi lending, Momentum positions) fail as they require price validation

**User Impact:**
- Users cannot deposit assets into the vault
- Users cannot execute pending withdrawal requests
- Protocol operators cannot perform rebalancing operations
- The vault essentially becomes frozen until admin intervention

**Admin Dependency:**
- The only recovery mechanism is for the queue authority to manually call the override function to reset the oracle expiration
- This breaks the decentralized attestation model and creates a critical operational dependency

**Severity Justification:**
This is a High severity issue because:
1. It causes complete operational DoS of vault functions
2. It can occur naturally through network delays or guardian unavailability
3. It requires privileged admin intervention to recover
4. Users' funds become temporarily inaccessible during the deadlock period

### Likelihood Explanation

**Feasibility:**
This vulnerability has HIGH likelihood of occurrence because:

1. **Natural Occurrence**: Oracle expiration can happen naturally if guardians experience temporary network issues, are offline for maintenance, or experience delays in attestation submission. The typical `oracle_validity_length_ms` of 10 hours means any gap in attestations longer than this period triggers the deadlock.

2. **No Attack Required**: An attacker doesn't need to perform any active exploit - they can simply observe when an oracle is approaching expiration and wait for natural expiration to cause the DoS.

3. **Reachable Entry Point**: The attestation function is a public entry point that anyone can observe failing once the oracle expires.

4. **Timing Windows**: If guardians are slow to attest (due to network congestion, high gas costs, or coordination issues), the oracle can expire before new attestations arrive, especially during periods of high blockchain activity.

**Attack Complexity**: TRIVIAL
- Requires only passive observation of oracle expiration
- No special privileges or resources needed
- No complex transaction sequencing required

**Operational Constraints**: MINIMAL
- The Volo vault depends on continuous price updates for normal operation
- Any interruption in the attestation flow (network issues, guardian downtime) can trigger this
- The 10-hour validity window is relatively short compared to potential maintenance or network issue durations

### Recommendation

**Immediate Mitigation:**

1. **Remove or Modify Expiration Check for Attestations**: The expiration check in `oracle_attest_action.move` line 67 should be removed or modified to allow attestations to expired oracles. The attestation validity should be based on the attestation's own timestamp and signature verification, not the oracle's current expiration status.

```move
// Remove this check or replace with guardian validation
// assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);

// Instead, verify the guardian itself is valid:
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

2. **Implement Grace Period**: Add a grace period after oracle expiration during which attestations can still be accepted to allow for recovery without admin intervention.

3. **Automatic Re-enablement**: When attestations reach the minimum threshold on an expired oracle, automatically re-enable it rather than requiring it to already be valid.

**Long-term Improvements:**

1. **Sliding Expiration Window**: Update the expiration time with each attestation addition (not just when reaching threshold), ensuring that active oracles with continuous attestations never expire.

2. **Add Monitoring**: Implement events that warn when oracle expiration is approaching without sufficient fresh attestations.

3. **Fallback Mechanism**: Implement a secondary price source or fallback mechanism for the vault when primary oracle becomes unavailable.

**Test Cases:**

1. Test that oracles can receive attestations after expiration
2. Test that new oracles (with expiration_time_ms = 0) can receive their first attestation
3. Test recovery flow when all guardians stop attesting temporarily
4. Test vault operations continue during oracle expiration recovery period

### Proof of Concept

**Initial State:**
- Oracle exists with `min_attestations = 3` and `oracle_validity_length_ms = 36000000` (10 hours)
- Oracle was previously attested and has `expiration_time_ms = T`
- Current time advances to `T + 1` (oracle is now expired)

**Exploitation Steps:**

1. **Oracle Expires**: Wait for `clock.timestamp_ms()` to exceed the oracle's `expiration_time_ms`

2. **Guardian Attempts Attestation**: 
   - Guardian calls `oracle_attest_action::run()` with valid signature and recent timestamp
   - Expected: Attestation should be added and oracle should accumulate valid attestations
   - Actual: Transaction fails at line 67 with `EGuardianInvalid` error

3. **Price Submission Fails**:
   - Any attempt to submit price updates via `aggregator_submit_result_action::run()` fails
   - Check at line 63 fails: `assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid)`

4. **Vault Operations Fail**:
   - User attempts to execute deposit or withdrawal via vault operations
   - Vault tries to get asset prices via `vault_oracle::get_asset_price()`
   - Aggregator prices are stale (no updates since oracle expired)
   - Transaction aborts with `ERR_PRICE_NOT_UPDATED` error

5. **Recovery Requires Admin**:
   - Only the queue authority can call `queue_override_oracle_action::run()` to manually set a new expiration time
   - Until admin intervention, the oracle remains in deadlock state and vault remains DoS'd

**Success Condition**: 
The vulnerability is confirmed when an expired oracle cannot accept new attestations despite guardians being willing and able to attest, requiring manual admin override to restore functionality.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L67-67)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-123)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L78-78)
```text
        expiration_time_ms: 0,
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L113-122)
```text
public(package) fun enable_oracle(
    oracle: &mut Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
) {
    oracle.secp256k1_key = secp256k1_key;
    oracle.mr_enclave = mr_enclave;
    oracle.expiration_time_ms = expiration_time_ms;
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L63-63)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```
