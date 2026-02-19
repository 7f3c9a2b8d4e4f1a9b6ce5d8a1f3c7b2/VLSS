### Title
Treasury Cap Transferred to Insecure External Address Enabling Unlimited Token Minting

### Summary
The `init()` function in `sprungsui.move` transfers the `TreasuryCap<SPRUNGSUI>` directly to `ctx.sender()` (the module deployer) instead of securing it in a protocol-controlled object. [1](#0-0)  Since `TreasuryCap` has the `store` ability in Sui's standard library, the deployer can freely transfer this capability to any address, enabling unlimited minting of SPRUNGSUI tokens outside protocol control and potentially preventing proper protocol initialization.

### Finding Description

The vulnerability exists in the module initialization flow:

**Insecure Treasury Cap Transfer:**
The `init()` function creates the SPRUNGSUI currency and immediately transfers the treasury cap to the deployer's address using `transfer::public_transfer()`. [2](#0-1) 

**Root Cause:**
Sui's `TreasuryCap` type has the `store` ability, allowing it to be freely transferred between addresses. By transferring it to `ctx.sender()`, the protocol relinquishes control and places the minting capability in an externally-owned address that can:
- Transfer the cap to any other address (including malicious actors)
- Mint unlimited SPRUNGSUI tokens directly
- Never provide the cap to the protocol's `init_staker` function

**Why Existing Protections Fail:**
The protocol's reserve module expects to receive this `TreasuryCap<SPRUNGSUI>` through the `init_staker` function to securely store it within a `Staker` object. [3](#0-2) 

The `staker::create_staker` function is designed to consume the treasury cap and integrate it into the protocol-controlled liquid staking system. [4](#0-3) 

However, there is no enforcement that the deployer must call `init_staker`, and even if they do, they retain the ability to transfer the cap beforehand or mint tokens outside the protocol.

**Execution Path:**
1. Module publishes → `init()` executes automatically
2. Treasury cap transfers to deployer's address
3. Deployer can now:
   - Option A: Transfer cap to attacker address, then attacker mints unlimited tokens
   - Option B: Mint tokens directly before calling `init_staker`
   - Option C: Never call `init_staker`, breaking protocol functionality

### Impact Explanation

**Direct Fund Impact:**
- **Unlimited Token Minting**: Anyone holding the treasury cap can mint arbitrary amounts of SPRUNGSUI tokens, causing complete supply inflation and value dilution for legitimate holders
- **Protocol Value Destruction**: The staking mechanism relies on a controlled 1:1 relationship between staked SUI and minted SPRUNGSUI tokens. Uncontrolled minting breaks this invariant, destroying the peg and rendering the liquid staking token worthless

**Security Integrity Impact:**
- **Loss of Supply Control**: The protocol loses all ability to enforce supply constraints and proper minting authorization
- **Broken Initialization**: If the deployer never provides the cap to `init_staker`, the entire staking mechanism fails to initialize, preventing the reserve from earning staking rewards on idle SUI

**Who Is Affected:**
- All SPRUNGSUI token holders suffer value dilution
- The Suilend protocol loses staking functionality for SUI reserves
- Users relying on SPRUNGSUI as collateral face liquidation risk

**Severity Justification:**
HIGH severity due to complete loss of supply control with unlimited minting capability and potential protocol functionality failure.

### Likelihood Explanation

**Attacker Capabilities:**
The deployer (`ctx.sender()`) automatically receives the treasury cap upon module publication. No special privileges or exploits are required beyond being the module deployer or compromising the deployer's address.

**Attack Complexity:**
LOW - The attack requires only:
1. Deploy the module (happens once)
2. Call `transfer::public_transfer(treasury_cap, attacker_address)` or mint tokens directly

**Feasibility Conditions:**
- **Deployment Risk**: If the deployer address is compromised at any time after deployment, the attacker gains immediate access to unlimited minting
- **Malicious Deployer**: A malicious deployer can exploit this intentionally
- **No Time Constraints**: The treasury cap remains vulnerable indefinitely until properly transferred to `init_staker`

**Detection/Operational Constraints:**
- The transfer occurs off-chain in the deployer's wallet
- No on-chain monitoring can prevent the initial insecure transfer
- By the time unauthorized minting is detected, significant damage may already be done

**Probability Assessment:**
HIGH likelihood given that:
- The vulnerability exists from deployment
- The deployer has unconstrained control
- Common key management issues or insider threats can enable exploitation

### Recommendation

**Immediate Mitigation:**
Replace the insecure transfer pattern with one of these secure approaches:

**Option 1 - Convert to Supply (Recommended):**
Following the pattern in the Volo protocol's certificate module [5](#0-4) , convert the treasury cap to a `Supply` object and store it in a protocol-controlled shared object:

```move
fun init(witness: SPRUNGSUI, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(...);
    transfer::public_freeze_object(metadata);
    
    let supply = coin::treasury_into_supply(treasury);
    transfer::share_object(SprungsuiMetadata {
        id: object::new(ctx),
        total_supply: supply,
    });
}
```

**Option 2 - Direct Integration:**
Modify `init()` to immediately create and store the `Staker` object, eliminating the external transfer:

```move
fun init(witness: SPRUNGSUI, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(...);
    transfer::public_freeze_object(metadata);
    
    let staker = staker::create_staker(treasury, ctx);
    transfer::share_object(staker);
}
```

**Invariant Checks:**
- Add compile-time verification that treasury caps are never transferred to external addresses
- Implement on-chain assertions that staker initialization occurs atomically with module deployment

**Test Cases:**
- Verify treasury cap cannot be accessed outside protocol
- Test that unauthorized minting attempts fail
- Validate staker initialization succeeds with proper supply tracking

### Proof of Concept

**Initial State:**
- SPRUNGSUI module not yet deployed
- Deployer has address `0xDeployer`
- Attacker has address `0xAttacker`

**Attack Sequence:**

**Step 1 - Module Deployment:**
```
Transaction: Publish sprungsui module
Sender: 0xDeployer
Result: init() executes, TreasuryCap<SPRUNGSUI> transfers to 0xDeployer
```

**Step 2 - Treasury Cap Exfiltration:**
```
Transaction: transfer::public_transfer(treasury_cap, 0xAttacker)
Sender: 0xDeployer (or if compromised)
Result: TreasuryCap now owned by 0xAttacker
```

**Step 3 - Unauthorized Minting:**
```
Transaction: coin::mint(&mut treasury_cap, 1_000_000_000_000_000)
Sender: 0xAttacker
Result: 1 trillion SPRUNGSUI tokens minted to attacker
```

**Expected Result:**
Treasury cap should be secured in a protocol-controlled object, inaccessible to external addresses.

**Actual Result:**
Treasury cap is freely transferable and enables unlimited minting by any holder, violating the fundamental supply control invariant.

**Success Condition:**
Attacker successfully mints arbitrary SPRUNGSUI tokens without protocol authorization, proving complete loss of supply control.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/sprungsui/sources/sprungsui.move (L6-19)
```text
    fun init(witness: SPRUNGSUI, ctx: &mut TxContext) {
        let (treasury, metadata) = coin::create_currency(
            witness, 
            9, 
            b"", 
            b"Staked SUI", 
            b"", 
            option::none(),
            ctx
        );

        transfer::public_share_object(metadata);
        transfer::public_transfer(treasury, ctx.sender())
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L819-829)
```text
    public(package) fun init_staker<P, S: drop>(
        reserve: &mut Reserve<P>,
        treasury_cap: TreasuryCap<S>,
        ctx: &mut TxContext
    ) {
        assert!(!dynamic_field::exists_(&reserve.id, StakerKey {}), EStakerAlreadyInitialized);
        assert!(type_name::get<S>() == type_name::get<SPRUNGSUI>(), EWrongType);

        let staker = staker::create_staker(treasury_cap, ctx);
        dynamic_field::add(&mut reserve.id, StakerKey {}, staker);
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L54-73)
```text
    public(package) fun create_staker<P: drop>(
        treasury_cap: TreasuryCap<P>,
        ctx: &mut TxContext,
    ): Staker<P> {
        assert!(coin::total_supply(&treasury_cap) == 0, ETreasuryCapNonZeroSupply);

        let (admin_cap, liquid_staking_info) = liquid_staking::create_lst(
            fees::new_builder(ctx).to_fee_config(),
            treasury_cap,
            ctx,
        );

        Staker {
            admin: admin_cap,
            liquid_staking_info,
            lst_balance: balance::zero(),
            sui_balance: balance::zero(),
            liabilities: 0,
        }
    }
```

**File:** liquid_staking/sources/cert.move (L60-66)
```text
        // destroy treasury_cap and store it custom Metadata object
        let supply = coin::treasury_into_supply(treasury_cap);
        transfer::share_object(Metadata<CERT> {
                id: object::new(ctx),
                version: VERSION,
                total_supply: supply,
        });
```
