# Audit Report

## Title
Division by Zero in Validator Pool Unstaking When All Validators Become Inactive

## Summary
A division by zero vulnerability exists in the `split_n_sui` function that causes all unstake operations to fail when `total_weight` becomes zero. This occurs when all configured validators become inactive in the Sui network, resulting in a protocol-wide denial of service where users cannot redeem their LST tokens.

## Finding Description

The `split_n_sui` function performs division by `total_weight` without validating it is non-zero. [1](#0-0) 

The `total_weight` field is initialized to zero when a new `ValidatorPool` is created. [2](#0-1) 

During epoch refresh, when validators are not in the active validator address set, their weights are set to zero and subtracted from `total_weight`. [3](#0-2) 

**Execution Path**:

1. User calls `unstake_entry` [4](#0-3) 

2. This calls `unstake` which triggers `refresh` [5](#0-4) 

3. During `refresh`, all inactive validators have their weights zeroed, potentially reducing `total_weight` to zero [6](#0-5) 

4. After refresh, `unstake` calls `split_n_sui` [7](#0-6) 

5. In `split_n_sui`, when validators exist in the list (`validators().length() > 0`) but `total_weight == 0`, the division operation executes without a zero check, causing an arithmetic error

**Why Existing Protections Fail**: The protocol has a zero check in `stake_pending_sui` [8](#0-7)  but `split_n_sui` completely lacks this protection, despite performing the same type of division operation.

## Impact Explanation

**Concrete Protocol Impact**:
- **Protocol-Level Denial of Service**: All user unstake operations fail with arithmetic division by zero errors
- **Fund Lock**: Users holding LST tokens cannot redeem them for underlying SUI, violating the core LST invariant
- **Liquidity Crisis**: The protocol becomes completely non-functional for withdrawals until operators add active validators
- **Admin Functions Blocked**: The `collect_fees` function also calls `split_n_sui`, blocking fee collection [9](#0-8) 

This is **High Severity** because it breaks the critical security guarantee that users must always be able to redeem their LST tokens for the underlying asset.

## Likelihood Explanation

**Realistic Trigger Conditions**:
1. All configured validators simultaneously removed from Sui's active validator set due to poor performance, jailing, slashing, or network governance decisions
2. During initial deployment if `set_validator_weights` is not called before users stake
3. If operators mistakenly set all validator weights to zero through misconfiguration

**Feasibility**: HIGH - Validator set changes are normal Sui network operations. Multiple validators becoming inactive simultaneously can occur during:
- Network upgrades or consensus issues requiring validator restarts
- Coordinated validator maintenance windows
- Widespread validator performance degradation
- Protocol migration periods
- Slashing events affecting multiple validators

The vulnerability window exists from the moment all validators become inactive until operators successfully re-add active validators, during which all user withdrawals are completely blocked.

## Recommendation

Add a zero check in `split_n_sui` similar to the protection in `stake_pending_sui`:

```move
public(package) fun split_n_sui(
    self: &mut ValidatorPool,
    system_state: &mut SuiSystemState,
    max_sui_amount_out: u64,
    ctx: &mut TxContext
): Balance<SUI> {
    
    // Add zero check before attempting to unstake from validators
    if (self.total_weight == 0) {
        // Skip validator unstaking when no validators have weights
        assert!(self.sui_pool.value() >= max_sui_amount_out, ENotEnoughSuiInSuiPool);
        return self.split_from_sui_pool(max_sui_amount_out)
    };
    
    {
        let to_unstake = if(max_sui_amount_out > self.sui_pool.value()) {
            max_sui_amount_out - self.sui_pool.value()
        } else {
            0
        };
        let total_weight = self.total_weight as u128;
        // ... rest of function
    }
    // ... rest of function
}
```

This ensures the function gracefully handles the case where all validators become inactive, allowing unstaking to proceed from the sui_pool buffer if sufficient funds are available, or properly failing with a meaningful error if not.

## Proof of Concept

Due to the complexity of setting up a full Sui validator test environment, a conceptual PoC trace:

**Setup**: 
- StakePool deployed with 2 validators (weights: [100, 100], total_weight: 200)
- User stakes SUI, receives LST tokens
- Validators accumulate some stake

**Trigger**:
- Sui network epoch changes
- Both validators removed from active validator set (performance/governance)
- User attempts to unstake LST tokens

**Result**:
1. `unstake_entry` called by user
2. `refresh` executes, detects both validators inactive
3. Lines 202-207: Both validators weights set to 0, total_weight becomes 0
4. Validators remain in list (not empty yet, have stake being withdrawn)
5. `split_n_sui` called with max_sui_amount_out > sui_pool.value()
6. Line 709: `i = validators().length()` = 2 (validators still in list)
7. Line 711: Loop condition true (i > 0 and needs more sui)
8. Line 714-716: Computes `to_unstake_i` with division by total_weight (0)
9. **Transaction aborts with arithmetic error: division by zero**
10. User cannot unstake, funds effectively locked

This same path applies to `collect_fees`, blocking admin operations as well.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L68-78)
```text
    public(package) fun new(ctx: &mut TxContext): ValidatorPool {
        ValidatorPool {
            sui_pool: balance::zero(),
            validator_infos: vector::empty(),
            total_sui_supply: 0,
            last_refresh_epoch: ctx.epoch() - 1,
            total_weight: 0,
            manage: manage::new(),
            extra_fields: bag::new(ctx)
        }
    }
```

**File:** liquid_staking/sources/validator_pool.move (L175-207)
```text
    public(package) fun refresh(
        self: &mut ValidatorPool, 
        system_state: &mut SuiSystemState, 
        ctx: &mut TxContext
    ): bool {
        self.manage.check_version();
        
        if(self.total_sui_supply() == 0) {
            return false
        };

        // skip refresh if the pool has not changed
        if (self.last_refresh_epoch == ctx.epoch()) {
            stake_pending_sui(self, system_state, ctx);
            return false
        };

        // get all active validator addresses
        let active_validator_addresses = system_state.active_validator_addresses();

        let mut i = self.validator_infos.length();
        while (i > 0) {
            i = i - 1;

            // withdraw all stake if validator is inactive.
            // notice that inacitve validator is not invalid stake
            // Time Complexity: O(n)
            if (!active_validator_addresses.contains(&self.validator_infos[i].validator_address)) {
                // unstake max amount of sui.
                self.unstake_approx_n_sui_from_validator(system_state, i, MAX_SUI_SUPPLY, ctx);
                self.total_weight = self.total_weight - self.validator_infos[i].assigned_weight;
                self.validator_infos[i].assigned_weight = 0;
            };
```

**File:** liquid_staking/sources/validator_pool.move (L260-262)
```text
        if(self.total_weight == 0) {
            return false
        };
```

**File:** liquid_staking/sources/validator_pool.move (L708-716)
```text
            let total_weight = self.total_weight as u128;
            let mut i = self.validators().length();
            
            while (i > 0 && self.sui_pool.value() < max_sui_amount_out) {
                i = i - 1;

                let to_unstake_i = 1 + (self.validator_infos[i].assigned_weight as u128 
                                        * ((to_unstake)as u128)
                                        / total_weight);
```

**File:** liquid_staking/sources/stake_pool.move (L268-278)
```text
    public entry fun unstake_entry(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        cert: Coin<CERT>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let sui = self.unstake(metadata, system_state, cert, ctx);
        transfer::public_transfer(sui, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L287-289)
```text
        self.manage.check_version();
        self.manage.check_not_paused();
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L297-297)
```text
        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L369-369)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
```
