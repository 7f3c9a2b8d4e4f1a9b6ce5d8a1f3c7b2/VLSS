### Title
Hash Collision in Two's Complement Conversion Enables Oracle Price Manipulation

### Summary
The `push_i128()` function in Switchboard's hash utility creates identical hashes for certain negative and positive value pairs due to two's complement arithmetic, allowing attackers to substitute oracle-signed prices with vastly different values while maintaining cryptographically valid signatures. Combined with the vault's extraction of only unsigned magnitudes from Decimal values, this enables massive price manipulation that bypasses oracle integrity controls.

### Finding Description

The vulnerability exists in the two's complement conversion logic: [1](#0-0) 

When `neg == true`, the function computes `u128::max_value!() - value + 1` to represent negative values in two's complement. This creates hash collisions where `(value=x, neg=true)` produces the identical hash as `(value=2^128-x, neg=false)`.

For example:
- Input A: `value=1, neg=true` (representing -1) → computes `u128::max_value!() - 1 + 1 = u128::max_value!()`
- Input B: `value=u128::max_value!(), neg=false` → uses value directly = `u128::max_value!()`
- Both serialize to identical bytes and produce the same SHA2-256 hash

This hash is used for oracle signature verification: [2](#0-1) 

The signature verification passes because the hash matches, but the aggregator stores the full Decimal (with both value and neg): [3](#0-2) 

However, when the vault extracts prices, it only reads the unsigned magnitude, completely ignoring the `neg` flag: [4](#0-3) 

The `.value()` accessor only returns the `u128` magnitude: [5](#0-4) 

### Impact Explanation

**Direct Fund Impact**: An attacker can manipulate vault asset valuations by substituting oracle-signed prices with drastically different values. For any small or negative value `x` that an oracle legitimately signs, the attacker can substitute `2^128 - x`, which produces an identical cryptographic signature but represents a vastly larger price.

**Concrete Example**: 
- Oracle signs `-1` (value=1, neg=true, representing -0.000000000000000001 with 18 decimals)
- Attacker submits `u128::max_value!()` (340282366920938463463374607431768211455, representing ≈3.4×10^20 with 18 decimals)
- Signature verification passes (identical hash)
- Vault treats price as ~340 trillion trillion, causing catastrophic mispricing

**Quantified Damage**: 
- Asset prices can be inflated by up to 10^38 times their actual value
- Enables theft through mispriced deposits/withdrawals, adaptor operations, and share accounting
- Breaks fundamental oracle integrity invariant
- Affects all users and vault operations dependent on asset valuation

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is exploitable through the public `aggregator_submit_result_action::run()` function: [6](#0-5) 

**Attacker Capabilities**: An untrusted attacker only needs to:
1. Monitor oracle price feed updates on-chain
2. Intercept or replay oracle signatures with substituted values that produce identical hashes
3. Submit the manipulated update through the standard entry function

**Execution Practicality**: 
- No special privileges required
- Attack works against any oracle update where `value` fits certain mathematical relationships
- Move runtime will not detect this as the arithmetic is valid and signature verification passes
- No economic constraints prevent exploitation

**Feasibility Conditions**:
- Requires oracle to sign values that have hash-colliding counterparts within u128 range
- Most exploitable with small positive values or any negative values (which map to large positive values)
- Oracle infrastructure does not currently validate against this attack vector

**Detection Constraints**: The attack is difficult to detect because:
- Signature verification succeeds cryptographically
- No on-chain validation checks for value/neg consistency
- Mispricing may not be immediately obvious until operations execute

### Recommendation

**Immediate Fix**: Add strict bounds validation to prevent hash collisions:

1. In `push_i128()` and `push_i128_le()`, add validation:
   - Assert that if `neg == true`, then `value <= 2^127` (maximum valid negative magnitude)
   - Assert that if `neg == false`, then `value <= 2^127 - 1` (maximum valid positive value)
   - Reject `(value=0, neg=true)` as invalid (represents -0, which should be normalized to +0)

2. In the vault's `get_current_price()` function, add explicit negative value rejection:
   - Check `current_result.result().neg() == false` before using the price
   - Abort with clear error if negative prices are detected
   - Document that Volo vault only supports positive oracle prices

3. Add comprehensive test cases:
   - Test hash collision scenarios with boundary values
   - Verify signature verification fails for value/neg substitutions
   - Test vault rejects negative prices from aggregator
   - Add integration tests covering the full oracle→vault flow

**Invariant to Enforce**: Oracle prices used by the vault must be strictly positive and within the valid signed 128-bit integer range, with cryptographic hashes that uniquely identify both magnitude and sign.

### Proof of Concept

**Initial State**:
- Switchboard oracle has signing authority for an aggregator
- Vault depends on this aggregator for asset price feeds
- Oracle legitimately signs a small or negative price update

**Attack Sequence**:

1. **Oracle Signs Legitimate Update**:
   - Oracle signs message with `value=1, neg=true` (representing -0.000000000000000001)
   - Message hash via `push_i128_le(1, true)` = bytes of `u128::max_value!()`
   - Oracle produces valid signature over this hash

2. **Attacker Intercepts and Substitutes**:
   - Attacker observes the signature on-chain or via mempool
   - Attacker creates new transaction with same signature but different parameters
   - Substitutes: `value=u128::max_value!(), neg=false`

3. **Submission to Aggregator**:
   - Calls `aggregator_submit_result_action::run()` with substituted values
   - Hash computed via `push_i128_le(u128::max_value!(), false)` = bytes of `u128::max_value!()` (identical)
   - Signature verification passes (`ecdsa_k1::secp256k1_ecrecover` succeeds)
   - Validation checks pass (timestamp, staleness, fee)

4. **Vault Reads Manipulated Price**:
   - Vault calls `get_current_price()` on aggregator
   - Extracts price via `.value()` = `u128::max_value!()`
   - Treats as positive price ≈ 3.4×10^38 (base units)

**Expected Result**: Oracle signature should only validate for the exact signed parameters `(1, true)`.

**Actual Result**: Oracle signature validates for completely different value `(u128::max_value!(), false)`, enabling price manipulation from near-zero to astronomical values.

**Success Condition**: Attacker successfully submits an oracle update with manipulated price that passes signature verification and gets stored in the aggregator, causing vault to use the inflated price for asset valuation and enabling theft through mispriced operations.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L68-80)
```text
public fun push_i128(self: &mut Hasher, value: u128, neg: bool) {

    let signed_value: u128 = if (neg) {
        // Get two's complement by subtracting from 2^128
        u128::max_value!() - value + 1
    } else {
        value
    };

    let mut bytes = bcs::to_bytes(&signed_value);
    vector::reverse(&mut bytes);
    self.buffer.append(bytes);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L72-91)
```text
    let update_msg = hash::generate_update_msg(
        value,
        oracle.queue_key(),
        aggregator.feed_hash(),
        x"0000000000000000000000000000000000000000000000000000000000000000",
        aggregator.max_variance(),
        aggregator.min_responses(),
        timestamp_seconds,
    );

    // recover the pubkey from the signature
    let recovered_pubkey_compressed = ecdsa_k1::secp256k1_ecrecover(
        &signature, 
        &update_msg, 
        1,
    );
    let recovered_pubkey = ecdsa_k1::decompress_pubkey(&recovered_pubkey_compressed);

    // check that the recovered pubkey is valid
    assert!(hash::check_subvec(&recovered_pubkey, &oracle.secp256k1_key(), 1), ERecoveredPubkeyInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L112-117)
```text
    aggregator.add_result(
        value, 
        timestamp_ms, 
        oracle.id(), 
        clock,
    );
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L133-147)
```text
public entry fun run<T>(
    aggregator: &mut Aggregator,
    queue: &Queue,
    value: u128,
    neg: bool,
    timestamp_seconds: u64,
    oracle: &Oracle,
    signature: vector<u8>,
    clock: &Clock,
    fee: Coin<T>,
) {
    let value = decimal::new(value, neg);
    validate<T>(aggregator, queue, oracle, timestamp_seconds, &value, signature, clock, &fee);
    actuate(aggregator, queue, value, timestamp_seconds, oracle, clock, fee);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L26-28)
```text
public fun value(num: &Decimal): u128 {
    num.value
}
```
