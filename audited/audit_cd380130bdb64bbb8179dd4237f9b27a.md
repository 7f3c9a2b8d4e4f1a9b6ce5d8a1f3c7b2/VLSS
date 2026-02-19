### Title
Incorrect Expiration Validation in Oracle Attestation Allows Complete DoS of Attestation Mechanism

### Summary
The `oracle_attest_action::validate()` function incorrectly checks the oracle's expiration time instead of the guardian's expiration time at line 67. This logic error completely breaks the oracle attestation flow by preventing any new oracle from being attested (since new oracles have `expiration_time_ms = 0`), and simultaneously fails to validate that guardian oracles are not expired.

### Finding Description [1](#0-0) 

The validation function checks `oracle.expiration_time_ms() > clock.timestamp_ms()` when it should check `guardian.expiration_time_ms() > clock.timestamp_ms()`. The error message is `EGuardianInvalid` and the comment states "check that the guardian is valid", confirming the intent is to validate the guardian, not the oracle being attested.

**Root Cause:**
The function signature clearly distinguishes between the oracle being attested (`oracle: &mut Oracle`) and the guardian performing the attestation (`guardian: &Oracle`). Line 67 validates the wrong object.

**Why Protections Fail:**
1. **New Oracle DoS**: When oracles are created via `oracle_init_action`, they initialize with `expiration_time_ms = 0` [2](#0-1) 

2. The attestation check at line 67 becomes `assert!(0 > current_timestamp)`, which always fails with `EGuardianInvalid`.

3. **Expired Guardian Bypass**: If an oracle is manually enabled via privileged override to have a future expiration, an expired guardian can then attest to it since only the oracle's expiration is checked, not the guardian's.

**Execution Path:** [3](#0-2) 

The `run()` entry point calls `validate()`, which aborts on line 67 for new oracles.

### Impact Explanation

**Operational DoS Impact:**
- The entire oracle attestation mechanism is broken and non-functional
- New oracles cannot be attested through the intended decentralized guardian validation process
- Forces reliance on centralized `queue_override_oracle_action` (requires queue authority privileges) [4](#0-3) 

**Security Integrity Impact:**
- Guardian expiration validation is completely bypassed
- Compromised or malicious expired guardians could attest to oracles (in non-standard scenarios where oracles are pre-enabled)
- Undermines the TEE attestation security model

**Volo Protocol Impact:**
- Volo vault depends on Switchboard oracles for asset price feeds [5](#0-4) 
- If oracle attestation is broken, price feed initialization is centralized
- Affects vault asset valuation, share calculations, and loss tolerance checks

**Severity:** Critical - completely breaks an intended security mechanism while simultaneously introducing a security bypass.

### Likelihood Explanation

**Reachable Entry Point:**
The bug is in a public entry function accessible to any user attempting oracle attestation. [6](#0-5) 

**Attack Complexity:** 
- **For DoS**: Zero complexity - simply calling the attestation function as designed triggers the bug
- **For expired guardian bypass**: Requires oracle to be pre-enabled via override (non-standard but possible)

**Feasibility:**
- The bug is deterministic and always present in the code
- The TypeScript SDK includes attestation functionality, indicating intended usage [7](#0-6) 

**Current State:**
Production deployments appear to work around this bug by using privileged overrides exclusively, as evidenced by guardian setup scripts. [8](#0-7) 

**Probability:** High for operational DoS (100% failure rate for attestation attempts), Medium for security bypass (requires non-standard setup).

### Recommendation

**Code-Level Fix:**
Change line 67 to validate the guardian's expiration instead of the oracle's:

```move
// check that the guardian is valid
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**Additional Validation:**
Add explicit checks to ensure:
1. Guardian oracles have valid (non-zero, future) expiration times
2. Oracle being attested can have zero expiration (new oracle case)
3. Document expected state transitions for attestation flow

**Test Cases:**
1. Test attesting to a newly created oracle with expiration_time_ms = 0
2. Test that expired guardians cannot attest (currently not tested)
3. Test full attestation flow from initialization to oracle enablement
4. Add integration tests for guardian rotation scenarios

### Proof of Concept

**Initial State:**
1. Guardian oracle exists with `expiration_time_ms = future_date` (enabled via override)
2. New regular oracle created via `oracle_init_action::run()` with `expiration_time_ms = 0`

**Exploitation Steps:**
1. Call `oracle_attest_action::run()` with:
   - `oracle`: address of new oracle (expiration = 0)
   - `guardian`: address of guardian oracle  
   - Valid signature from guardian
   - Current clock time

**Expected Result:** 
Attestation should succeed if guardian is valid and not expired

**Actual Result:**
Transaction aborts with `EGuardianInvalid` because line 67 checks:
```
assert!(0 > clock.timestamp_ms(), EGuardianInvalid)  // Always false
```

**Success Condition:**
The attestation fails 100% of the time for new oracles, proving the mechanism is completely broken.

**Notes:**
This vulnerability exists in the Switchboard on-demand oracle module that Volo vault depends on for price feeds. While production deployments may work around this by using privileged overrides, the bug fundamentally breaks the intended decentralized attestation security model and should be fixed to prevent future issues.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L66-67)
```text
    // check that the guardian is valid
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L135-164)
```text
public entry fun run(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    timestamp_seconds: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    signature: vector<u8>,
    clock: &Clock,
) {
    validate(
        oracle,
        queue,
        guardian,
        timestamp_seconds,
        mr_enclave,
        secp256k1_key,
        signature,
        clock,
    );
    actuate(
        oracle,
        queue,
        guardian,
        timestamp_seconds,
        mr_enclave,
        secp256k1_key,
        clock,
    );
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L73-83)
```text
    let oracle = Oracle {
        id,
        oracle_key,
        queue,
        queue_key,
        expiration_time_ms: 0,
        secp256k1_key: vector::empty(),
        valid_attestations: vector::empty(),
        mr_enclave: vector::empty(),
        version: VERSION,
    };
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L42-43)
```text
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(expiration_time_ms > 0, EInvalidExpirationTime);
```

**File:** volo-vault/sources/oracle.move (L1-10)
```text
module volo_vault::vault_oracle;

use std::ascii::String;
use std::u64::pow;
use sui::clock::Clock;
use sui::event::emit;
use sui::table::{Self, Table};
use switchboard::aggregator::Aggregator;

// ---------------------  Constants  ---------------------//
```

**File:** volo-vault/local_dependencies/switchboard_sui/sui-sdk/src/oracle/index.ts (L202-214)
```typescript
      tx.moveCall({
        target: `${switchboardAddress}::oracle_attest_action::run`,
        arguments: [
          tx.object(this.address),
          tx.object(oracleData.queue),
          tx.object(guardianId),
          tx.pure.u64(message.timestamp),
          tx.pure.vector("u8", Array.from(fromHex(mrEnclave))),
          tx.pure.vector("u8", Array.from(fromHex(secp256k1Key))),
          tx.pure.vector("u8", signature),
          tx.object(SUI_CLOCK_OBJECT_ID),
        ],
      });
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/scripts/ts/mainnet_guardian_queue_override.ts (L128-133)
```typescript
      queue.overrideOracleTx(guardianTx, {
        oracle: o.id, // sui guardian id
        secp256k1Key: toHex(guardian.enclave.secp256K1Signer),
        mrEnclave: toHex(guardian.enclave.mrEnclave),
        expirationTimeMs: Date.now() + 1000 * 60 * 60 * 24 * 365 * 5,
      });
```
