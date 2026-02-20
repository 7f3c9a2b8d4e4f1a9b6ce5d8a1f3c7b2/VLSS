# Audit Report

## Title
Hash Collision in Two's Complement Conversion Enables Oracle Price Manipulation

## Summary
A mathematical collision in Switchboard's two's complement hash implementation allows attackers to replay oracle signatures with manipulated price values, enabling complete vault drainage. The vulnerability chain exploits: (1) hash collisions in `push_i128()`, (2) signature verification using the colliding hash, and (3) the vault extracting only unsigned magnitudes while ignoring sign bits.

## Finding Description

The vulnerability consists of three exploitable components that work together to bypass cryptographic signature verification and manipulate oracle prices:

**1. Mathematical Hash Collision**

The `push_i128()` function implements two's complement conversion that creates predictable collisions. [1](#0-0) 

When `neg == true`, it computes `u128::max_value!() - value + 1`. This enables collision attacks where:
- Oracle signs: `(value=X, neg=false)` → hash contains `X`
- Attacker submits: `(value=u128::max_value!() - X + 1, neg=true)` → hash contains `u128::max_value!() - (u128::max_value!() - X + 1) + 1 = X`
- Both produce identical hashes despite representing vastly different values

**2. Unauthenticated Entry Point with Signature Bypass**

The aggregator update function is publicly accessible without authentication requirements. [2](#0-1) 

The signature verification generates the message hash from attacker-controlled `value` and `neg` parameters. [3](#0-2) 

Due to the hash collision, the cryptographic signature verification succeeds even though the attacker has substituted collision values, and the manipulated `Decimal` with massive magnitude is stored in the aggregator.

**3. Sign-Blind Price Extraction**

The Decimal structure contains both `value` and `neg` fields. [4](#0-3) 

However, the accessor function only returns the magnitude field. [5](#0-4) 

The vault oracle extracts prices using only this magnitude, completely ignoring the sign bit. [6](#0-5) 

This extracted price is then used in critical vault operations including withdrawal calculations [7](#0-6)  and principal value updates. [8](#0-7) 

**Attack Execution:**
1. Monitor on-chain oracle signatures (publicly observable)
2. For oracle-signed `(X, false)`, compute collision `(u128::max_value!() - X + 1, true)`
3. Call `aggregator_submit_result_action::run()` with collision parameters and replayed signature
4. Signature verification passes due to identical hash
5. Aggregator stores `Decimal { value: u128::max_value!() - X + 1, neg: true }`
6. Vault reads via `.value()` and interprets as positive price of `u128::max_value!() - X + 1`
7. Execute deposits at inflated prices to mint excessive shares, or withdrawals to drain vault

## Impact Explanation

**Critical Fund Loss**: This vulnerability enables complete vault drainage through price manipulation. The impact severity is critical because:

- **Deposit Exploitation**: Attacker deposits minimal amounts at artificially inflated prices, receives disproportionate shares representing the majority of vault value
- **Withdrawal Exploitation**: Attacker withdraws at manipulated exchange rates, receiving far more principal than entitled, draining vault reserves
- **Universal Applicability**: Works against any Switchboard-fed price, affecting all vault assets and operations
- **Share Dilution**: Legitimate depositors' shares become worthless as attacker extracts value at manipulated rates

**Quantified Damage:**
- Price inflation magnitude: Up to 10^38x (difference between value=1 and u128::max_value!())
- Example: Legitimate $0.10 price becomes ~$34 undecillion
- Single manipulated price feed enables complete vault drainage
- No economic barriers or detection mechanisms exist

## Likelihood Explanation

**High Likelihood**: This vulnerability is trivially exploitable with minimal barriers:

1. **No Authentication**: Public entry point requires no special privileges beyond gas fees
2. **Observable Attack Surface**: Oracle signatures are publicly visible on-chain for monitoring
3. **Deterministic Collision**: Mathematical relationship is predictable, requiring no brute-force attempts
4. **No Detection**: Signature verification succeeds legitimately, providing no indication of manipulation
5. **Broad Applicability**: Collision works for any oracle-signed value with the mathematical relationship
6. **Economic Feasibility**: Only requires transaction gas fees, with potential returns of millions of dollars

**Preconditions** (all trivially met):
- Vault uses Switchboard aggregators (confirmed in production code)
- Oracle signs price updates (normal operational behavior)
- Attacker observes on-chain signatures (publicly available transaction data)
- Sufficient staleness window for transaction submission (configurable per aggregator)

The vulnerability requires no special knowledge, insider access, or external dependencies beyond observing public blockchain data.

## Recommendation

Implement three-layer defense:

1. **Hash Function Fix**: Modify `push_i128()` to include the sign bit explicitly in the hash computation, preventing collision between positive and negative values with the same magnitude.

2. **Sign Validation**: Add explicit validation in `aggregator_submit_result_action::validate()` to reject negative price values, as negative prices are economically meaningless for asset pricing.

3. **Vault Oracle Protection**: Implement sign checking in `vault_oracle::get_current_price()` to assert that all price decimals have `neg == false`, providing defense-in-depth even if upstream validations fail.

Example fix for the vault oracle:
```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    // ... existing staleness checks ...
    let result = current_result.result();
    assert!(!result.neg(), ERR_NEGATIVE_PRICE); // Add this check
    result.value() as u256
}
```

## Proof of Concept

```move
#[test]
fun test_hash_collision_oracle_manipulation() {
    // Setup: Oracle signs legitimate price (value=100, neg=false)
    let oracle_value = 100u128;
    let oracle_neg = false;
    
    // Compute collision parameters
    let collision_value = u128::max_value!() - oracle_value + 1;
    let collision_neg = true;
    
    // Verify hash collision
    let mut hasher1 = hash::new();
    hasher1.push_i128(oracle_value, oracle_neg);
    let hash1 = hasher1.finalize();
    
    let mut hasher2 = hash::new();
    hasher2.push_i128(collision_value, collision_neg);
    let hash2 = hasher2.finalize();
    
    assert!(hash1 == hash2, 0); // Hashes collide
    
    // Verify vault extracts only magnitude
    let manipulated_decimal = decimal::new(collision_value, collision_neg);
    let extracted_price = manipulated_decimal.value();
    
    // Price is interpreted as massive positive value instead of negative
    assert!(extracted_price == collision_value, 1);
    assert!(extracted_price > oracle_value * 1000000000000000000, 2); // 10^18x inflation
}
```

## Notes

This vulnerability represents a critical breakdown in the trust model where cryptographic signature verification is bypassed through mathematical collision rather than cryptographic weakness. The combination of hash collision, public entry points, and sign-blind price extraction creates a complete attack path from signature observation to fund extraction.

The vulnerability affects the Switchboard oracle integration specifically, but similar patterns should be audited in any system that uses signed integer representations in hash computations while later treating them as unsigned values. The defense-in-depth approach recommended ensures protection even if individual layers fail.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L72-80)
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L8-8)
```text
public struct Decimal has copy, drop, store { value: u128, neg: bool }
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L26-28)
```text
public fun value(num: &Decimal): u128 {
    num.value
}
```

**File:** volo-vault/sources/oracle.move (L261-261)
```text
    current_result.result().value() as u256
```

**File:** volo-vault/sources/volo_vault.move (L1015-1022)
```text
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```
