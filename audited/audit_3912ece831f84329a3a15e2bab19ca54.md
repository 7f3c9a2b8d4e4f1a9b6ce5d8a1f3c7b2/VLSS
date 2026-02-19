### Title
Cross-Contract Migration Fee Theft via Unvalidated Recipient Parameter

### Summary
The `take_unclaimed_fees` function in the migration module accepts an arbitrary `recipient` address parameter without validation, allowing migration fees to be redirected to any address. Since `MigrationCap` has the `store` ability and all migration functions are `public fun`, a malicious contract can accept the capability and call `take_unclaimed_fees` to steal protocol fees intended for the legitimate migration recipient.

### Finding Description

The vulnerability exists in the `take_unclaimed_fees` function which is designed to extract unclaimed protocol fees during the v1 to v2 migration: [1](#0-0) 

**Root Cause:**

1. **Capability has `store` ability**: The `MigrationCap` struct is defined with both `key` and `store` abilities: [2](#0-1) 

This allows the capability to be transferred to or wrapped by other contracts, unlike the legacy `OwnerCap` which only has `key`: [3](#0-2) 

2. **Public visibility enables cross-contract calls**: All migration functions are declared as `public fun` (not `entry`), making them callable from any other contract: [4](#0-3) [5](#0-4) 

3. **No recipient validation**: The `recipient` parameter in `take_unclaimed_fees` accepts any address without validation. The function extracts `collected_rewards` from the v1 native pool (accumulated protocol fees): [6](#0-5) 

And transfers them to the provided recipient address with no authorization check beyond possessing the MigrationCap.

**Execution Path:**

A malicious contract can create a public entry function that:
1. Accepts a `MigrationCap` as a parameter (possible due to `store` ability)
2. Calls `take_unclaimed_fees` with the attacker's address as the `recipient`
3. Steals all unclaimed protocol fees from the v1 system

The one-time `fees_taken` flag provides no protection against the initial theft: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**
- Complete theft of all accumulated protocol fees from the v1 liquid staking system
- These fees represent the protocol's collected revenue that should go to the legitimate protocol treasury
- The `collected_rewards` field tracks protocol fees that have accumulated over the lifetime of the v1 system

**Affected Parties:**
- The protocol loses all v1 accumulated fees
- The legitimate migration recipient (intended protocol treasury) receives nothing
- Users are not directly affected, but protocol sustainability is compromised

**Severity Justification:**
This is a **High** severity issue because:
1. It enables direct theft of protocol funds with no technical barriers once the cap is obtained
2. The loss is total and irreversible (one-time operation that cannot be repeated correctly)
3. The vulnerability violates the "Authorization & Enablement" critical invariant by allowing unauthorized fee redirection

### Likelihood Explanation

**Attacker Capabilities:**
An attacker must deploy a malicious contract that appears to provide legitimate migration assistance services, such as:
- "Automated migration helper"
- "Multi-step migration coordinator"
- "Gas-optimized migration wrapper"

**Attack Complexity:**
The attack requires:
1. **Social Engineering**: The legitimate MigrationCap holder must be convinced to pass the capability to the malicious contract
2. **Contract Deployment**: Attacker deploys a malicious contract with a public entry function
3. **Single Transaction**: Once the cap is obtained, theft occurs in a single transaction call to `take_unclaimed_fees`

**Feasibility Conditions:**
- The `store` ability makes it technically feasible for users to pass the capability to external contracts
- Users migrating from v1 to v2 may seek help from "migration helper" contracts due to the complexity of the multi-step process
- The 5-step migration flow creates opportunity for users to use third-party tooling: [8](#0-7) 

**Probability Assessment:**
Medium-to-High likelihood because:
- Migration is a complex, one-time operation where users might seek external assistance
- The technical exploitation is trivial once the cap is obtained
- No on-chain mechanism prevents passing the cap to untrusted contracts

### Recommendation

**Immediate Fix:**

1. **Remove the `recipient` parameter** and hardcode the recipient to the original MigrationCap creator:

```move
public fun take_unclaimed_fees(
    migration_storage: &mut MigrationStorage,
    migration_cap: &mut MigrationCap,
    // Remove: recipient: address,
    native_pool: &mut NativePool,
    ctx: &mut TxContext
) {
    let unclaimed_fees = native_pool.mut_collected_rewards();
    let fee_amount = *unclaimed_fees;
    let fees = migration_storage.sui_balance.split(fee_amount);
    
    // Store the intended recipient in MigrationCap during creation
    // and transfer to that address only
    transfer::public_transfer(fees.into_coin(ctx), migration_cap.authorized_recipient);
    
    *unclaimed_fees = 0;
    migration_cap.fees_taken = true;
    event::emit(UnclaimedFeesEvent { amount: fee_amount });
}
```

2. **Add `authorized_recipient` field** to `MigrationCap` struct:

```move
public struct MigrationCap has key, store {
    id: UID,
    pool_created: bool,
    fees_taken: bool,
    authorized_recipient: address,  // Add this field
}
```

3. **Initialize the recipient** in `init_objects`:

```move
let migration_cap = MigrationCap {  
    id: object::new(ctx),
    pool_created: false,
    fees_taken: false,
    authorized_recipient: ctx.sender(),  // Lock recipient to cap creator
};
```

**Alternative Fix:**

If the recipient must remain configurable, require an additional authorization signature:
- Add `OwnerCap` reference as a parameter to `take_unclaimed_fees`
- Validate that the transaction sender matches an expected authorized list

**Testing:**

Add test cases that verify:
1. Fees can only go to the authorized recipient
2. Malicious contracts cannot redirect fees
3. The `authorized_recipient` cannot be changed after creation

### Proof of Concept

**Initial State:**
- V1 native pool has `collected_rewards = 1000 SUI` (accumulated protocol fees)
- Legitimate user holds `MigrationCap` 
- Migration is in progress, `export_stakes` has completed
- `MigrationStorage` contains the exported SUI balance

**Malicious Contract:**
```move
module attacker::malicious_migrator {
    use liquid_staking::migration;
    
    public entry fun steal_migration_fees(
        cap: MigrationCap,
        migration_storage: &mut MigrationStorage,
        native_pool: &mut NativePool,
        ctx: &mut TxContext
    ) {
        // Redirect fees to attacker instead of legitimate recipient
        migration::take_unclaimed_fees(
            migration_storage,
            &mut cap,
            @attacker_address,  // ← Attacker's address, not legitimate recipient
            native_pool,
            ctx
        );
        
        // Return or keep the cap
        transfer::public_transfer(cap, @attacker_address);
    }
}
```

**Attack Steps:**
1. Attacker deploys `malicious_migrator` contract claiming to provide "migration helper" services
2. Legitimate user calls `attacker::malicious_migrator::steal_migration_fees` with their `MigrationCap`
3. Malicious contract calls `migration::take_unclaimed_fees` with attacker's address as recipient
4. All 1000 SUI of protocol fees are transferred to attacker
5. Legitimate migration recipient receives 0 SUI

**Expected Result:** 
Fees transferred to legitimate protocol treasury address

**Actual Result:** 
Fees transferred to `@attacker_address`, protocol loses all v1 accumulated fees

**Success Condition:** 
Attacker's address receives the entire `collected_rewards` balance, verifiable on-chain

### Notes

This vulnerability demonstrates a critical cross-contract attack surface created by the combination of:
1. Capability objects with `store` ability
2. Public function visibility 
3. Unvalidated user-controlled parameters in privileged operations

While other migration functions like `import_stakes` require both `MigrationCap` AND `AdminCap`, making cross-contract exploitation harder, the `take_unclaimed_fees` function relies solely on `MigrationCap` with an unvalidated recipient parameter. [9](#0-8) 

The `AdminCap` also has `store` ability, which could enable similar cross-contract vulnerabilities in other functions if not carefully validated: [10](#0-9)

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L3-10)
```text
/// migration will be only executed once
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
/// 6. unpause the pool (after migration)
```

**File:** liquid_staking/sources/migration/migrate.move (L59-63)
```text
    public struct MigrationCap has key, store {
        id: UID,
        pool_created: bool,
        fees_taken: bool,
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L94-101)
```text
    public fun create_stake_pool(
        migration_cap: &mut MigrationCap,
        ctx: &mut TxContext
    ) {
        assert!(!migration_cap.pool_created, 0);
        migration_cap.pool_created = true;
        stake_pool::create_stake_pool(ctx);
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L104-111)
```text
    public fun export_stakes(
        migration_storage: &mut MigrationStorage,
        _: &MigrationCap,
        native_pool: &mut NativePool,
        system_state: &mut SuiSystemState,
        max_iterations: u64,
        ctx: &mut TxContext
    ) {
```

**File:** liquid_staking/sources/migration/migrate.move (L137-155)
```text
    public fun take_unclaimed_fees(
        migration_storage: &mut MigrationStorage,
        migration_cap: &mut MigrationCap,
        recipient: address,
        native_pool: &mut NativePool,
        ctx: &mut TxContext
    ) {
        let unclaimed_fees = native_pool.mut_collected_rewards();
        let fee_amount = *unclaimed_fees;
        let fees = migration_storage.sui_balance.split(fee_amount);
        transfer::public_transfer(fees.into_coin(ctx), recipient);
        *unclaimed_fees = 0;
        migration_cap.fees_taken = true;
        event::emit(
            UnclaimedFeesEvent {
                amount: fee_amount,
            }
        );
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L158-168)
```text
    public fun import_stakes(
        migration_storage: &mut MigrationStorage,
        _: &MigrationCap,
        admin_cap: &AdminCap,
        stake_pool: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        import_amount: u64,
        min_ratio: u64,
        ctx: &mut TxContext
    ) {
```

**File:** liquid_staking/sources/volo_v1/ownership.move (L8-10)
```text
    public struct OwnerCap has key {
        id: UID,
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L150-150)
```text
        collected_rewards: u64, // rewards that stashed as protocol fee
```

**File:** liquid_staking/sources/stake_pool.move (L56-58)
```text
    public struct AdminCap has key, store { 
        id: UID
    }
```
