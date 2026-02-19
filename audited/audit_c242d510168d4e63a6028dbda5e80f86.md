### Title
Oracle Attestation Timestamp Replay Attack Enables Stale Key Re-attestation

### Summary
The Switchboard oracle attestation mechanism validates that attestation timestamps are within 10 hours of current time, but only filters stored attestations to keep those within 10 minutes. This mismatch allows attackers to replay expired attestations (10 minutes to 10 hours old) to re-enable oracles with old or compromised keys, potentially enabling price manipulation in the Volo vault's Switchboard-based price feeds.

### Finding Description

The vulnerability exists in the oracle attestation flow across two modules:

**Validation Phase** [1](#0-0) 

The `validate()` function checks that the attestation timestamp is at most 10 hours old, where `ATTESTATION_VALIDITY_MS = 1000 * 60 * 60 * 10` (10 hours) [2](#0-1) 

**Storage Phase** [3](#0-2) 

The `add_attestation()` function filters existing attestations to keep only those where `a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms`, where `ATTESTATION_TIMEOUT_MS = 1000 * 60 * 10` (10 minutes) [4](#0-3) 

**Root Cause:** The newly added attestation is pushed to `valid_attestations` without checking its own timestamp freshness. Immediately after, `valid_attestation_count()` counts all attestations including the stale one [5](#0-4) 

**Exploitation Path:**
1. Attacker monitors blockchain for attestation transactions and extracts guardian signatures
2. When legitimate operators attempt key rotation (e.g., from K1 to K2), attacker replays old signatures for K1
3. Replayed attestations with timestamps between 10 minutes and 10 hours old pass validation
4. Each replay replaces the guardian's current attestation (due to `a.guardian_id != attestation.guardian_id` filter)
5. The stale attestations are immediately counted toward the threshold
6. Oracle gets enabled with the old key K1 instead of the new key K2 [6](#0-5) 

The `generate_attestation_msg()` function creates a deterministic hash including the timestamp [7](#0-6)  but does not validate freshness - this validation happens in the caller, which has an overly permissive 10-hour window.

### Impact Explanation

**Direct Impact on Volo Protocol:**
The Volo vault depends on Switchboard aggregators for asset pricing [8](#0-7) . If attackers can keep oracles enabled with compromised keys through replay attacks:

1. **Price Manipulation:** Oracles with compromised keys can submit malicious price updates to aggregators [9](#0-8) 
2. **Vault Valuation Corruption:** Manipulated aggregator prices affect vault asset valuations [10](#0-9) 
3. **Fund Theft:** Incorrect prices lead to wrong share calculations in deposits/withdrawals, enabling attackers to extract value
4. **Prevention of Security Updates:** Legitimate key rotations can be blocked by continuously replaying old attestations

**Severity Justification:** HIGH - While the attack requires specific preconditions (access to recent guardian signatures and compromised keys), the impact includes direct fund theft through price manipulation and prevention of security updates. The 10-hour replay window is significantly larger than the 10-minute intended freshness window.

### Likelihood Explanation

**Attacker Capabilities:**
- Monitor blockchain transactions to extract guardian signatures from past attestations
- No need to compromise guardians - only need to observe and replay their public signatures
- Can execute attacks within the 10-hour window after signatures are broadcasted

**Attack Complexity:** MEDIUM
- Requires monitoring blockchain for attestation transactions
- Needs the old secp256k1_key's private key to exploit fully (submit malicious prices)
- Must coordinate replay timing to race legitimate attestations

**Feasibility Conditions:**
1. Guardian signatures for a compromised key exist within the last 10 hours
2. Attacker possesses or obtains the private key for the old secp256k1_key
3. Sufficient replayed attestations reach threshold before legitimate ones

**Detection Constraints:**
- Replays appear as valid transactions on-chain
- Difficult to distinguish from legitimate re-attestations
- Event emissions don't reveal the age of the underlying attestation timestamp

**Probability Assessment:** The vulnerability is exploitable when key compromises occur, as the 10-hour window provides ample opportunity to replay signatures before they become unusable. This makes the attack PRACTICAL for motivated adversaries targeting high-value vaults.

### Recommendation

**1. Enforce Strict Timestamp Freshness in Validation:**
```
// In oracle_attest_action.move, line 73, replace:
assert!(timestamp_seconds * 1000 + ATTESTATION_VALIDITY_MS >= clock.timestamp_ms(), ETimestampInvalid);

// With:
const ATTESTATION_FRESHNESS_MS: u64 = 1000 * 60 * 10; // Match the 10-minute storage timeout
assert!(timestamp_seconds * 1000 + ATTESTATION_FRESHNESS_MS >= clock.timestamp_ms(), ETimestampInvalid);
assert!(timestamp_seconds * 1000 <= clock.timestamp_ms(), ETimestampInFuture); // Prevent future timestamps
```

**2. Add Freshness Check in add_attestation:**
```
// In oracle.move, before push_back at line 104:
assert!(attestation.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms, EAttestationExpired);
```

**3. Implement Nonce-Based Replay Protection:**
Add a nonce or sequence number to attestations that increments with each guardian signature, preventing replay of any previous attestation regardless of timestamp.

**4. Test Cases:**
- Test replaying attestations with timestamps 11 minutes old (should fail)
- Test that replacing a guardian's attestation requires a newer timestamp
- Test that multiple guardians cannot have their attestations replayed simultaneously to reach threshold

### Proof of Concept

**Initial State:**
- Oracle O requires 3 attestations (min_attestations = 3)
- At time T0=100, guardians G1, G2, G3 sign attestations for oracle O with key K1
- Oracle O is enabled with K1

**Attack Execution at T1=130 (30 minutes later):**

1. Legitimate operator initiates key rotation to K2:
   - Guardian G1 signs attestation: `(oracle_key, queue_key, mr_enclave, slothash, K2, T1=130)`
   - Calls `oracle_attest_action::run()` with G1's signature

2. Attacker monitors blockchain, extracts old signatures from G2, G3 at T0=100

3. Attacker replays attestations:
   - Calls `oracle_attest_action::run()` with G2's old signature `(oracle_key, queue_key, mr_enclave, slothash, K1, T0=100)`
   - Validation passes: `100 * 1000 + 36000000 >= 130 * 1000` ✓
   - `add_attestation()` adds attestation despite being 30 minutes old
   - Repeats with G3's old signature

4. Result check:
   - `valid_attestation_count(K1)` returns 2 (G2, G3)
   - `valid_attestation_count(K2)` returns 1 (G1)
   - Attacker replays G1's old K1 signature, replacing the K2 attestation
   - `valid_attestation_count(K1)` returns 3
   - Oracle O is enabled with old key K1 instead of new key K2

**Expected:** Oracle enabled with new key K2 after legitimate rotation  
**Actual:** Oracle enabled with old key K1 through replayed attestations  
**Success Condition:** Attacker successfully prevents key rotation and maintains oracle with potentially compromised key

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L41-41)
```text
const ATTESTATION_VALIDITY_MS: u64 = 1000 * 60 * 60 * 10;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L72-73)
```text
    // check that the timestamp is a maximum of 10 minutes old (and not in the future)
    assert!(timestamp_seconds * 1000 + ATTESTATION_VALIDITY_MS >= clock.timestamp_ms(), ETimestampInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-123)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L4-4)
```text
const ATTESTATION_TIMEOUT_MS: u64 = 1000 * 60 * 10; // 10 minutes
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L100-105)
```text
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L107-111)
```text
public(package) fun valid_attestation_count(oracle: &Oracle, secp256k1_key: vector<u8>): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key
    })
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L132-154)
```text
public fun generate_attestation_msg(
    oracle_key: vector<u8>, 
    queue_key: vector<u8>,
    mr_enclave: vector<u8>,
    slothash: vector<u8>,
    secp256k1_key: vector<u8>,
    timestamp: u64,
): vector<u8> {
    let mut hasher = new();
    assert!(oracle_key.length() == 32, EWrongOracleIdLength);
    assert!(queue_key.length() == 32, EWrongQueueLength);
    assert!(mr_enclave.length() == 32, EWrongMrEnclaveLength);
    assert!(slothash.length() == 32, EWrongSlothashLength);
    assert!(secp256k1_key.length() == 64, EWrongSec256k1KeyLength);
    hasher.push_bytes(oracle_key);
    hasher.push_bytes(queue_key);
    hasher.push_bytes(mr_enclave);
    hasher.push_bytes(slothash);
    hasher.push_bytes(secp256k1_key);
    hasher.push_u64_le(timestamp);
    let Hasher { buffer } = hasher;
    buffer
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L63-63)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```
