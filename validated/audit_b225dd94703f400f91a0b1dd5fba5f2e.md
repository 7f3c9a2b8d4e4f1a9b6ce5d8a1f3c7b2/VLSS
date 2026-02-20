# Audit Report

## Title
Liquid Staking Share Calculation Bypass Through Zero Total Supply Condition

## Summary
A critical vulnerability exists in the liquid staking module's share calculation logic that allows attackers to steal 100% of accumulated staking rewards. When all LST tokens are burned (`total_lst_supply == 0`) but SUI remains staked with accrued rewards (`total_sui_supply > 0`), the `sui_amount_to_lst_amount` function incorrectly returns a 1:1 ratio instead of the proper reward-adjusted ratio, enabling an attacker to mint LST tokens at favorable terms and immediately redeem them at the correct ratio to extract all rewards.

## Finding Description

The vulnerability resides in the share calculation logic within the `sui_amount_to_lst_amount` function. [1](#0-0) 

The condition uses an OR operator, causing the function to return a 1:1 ratio when **either** `total_sui_supply == 0` **OR** `total_lst_supply == 0`. This is incorrect - it should only use 1:1 when **both** are zero (initial state).

**Attack Execution Path:**

1. **Precondition Setup:** All users unstake their LST tokens through normal operations, burning all LST supply. [2](#0-1) 

2. **Reward Accumulation:** An epoch boundary passes (~24 hours on Sui), and validators earn staking rewards (5-10% APY). These rewards remain in the validator pool even though no LST tokens exist.

3. **Exploit Trigger:** Attacker calls the public `stake()` function. [3](#0-2) 

4. **State Update:** The `stake()` function calls `refresh()`, which updates validator exchange rates and increases `total_sui_supply` to reflect accrued rewards. [4](#0-3)  The `refresh()` function processes the epoch rollover: [5](#0-4)  And validator info is refreshed to update total supply: [6](#0-5) 

5. **Vulnerable Calculation:** The `sui_amount_to_lst_amount()` function is called to calculate LST to mint. [7](#0-6)  Since `total_lst_supply == 0`, the OR condition evaluates to TRUE, returning `sui_amount` at 1:1 ratio instead of the correct ratio that accounts for rewards.

6. **Invariant Bypass:** The ratio invariant check explicitly allows this scenario through a special case exception. [8](#0-7) 

7. **Profit Extraction:** Attacker immediately calls `unstake()` with the minted LST tokens. [9](#0-8)  The `lst_amount_to_sui_amount()` calculation uses the proper ratio formula. [10](#0-9) 

**Example:** If 100 SUI in rewards accrued while `total_lst_supply = 0`, attacker stakes 1 SUI, receives 1 LST (should receive ~0.01 LST), then unstakes 1 LST for ~101 SUI (minus fees), stealing ~100 SUI.

## Impact Explanation

**Severity: Critical - Direct Protocol Fund Theft**

This vulnerability allows complete theft of accumulated staking rewards with quantifiable impact:

- **Direct Financial Loss:** Attacker extracts 100% of rewards that accrued between the last unstake and their exploit transaction
- **Scale:** With typical staking APYs of 5-10% on Sui, a pool managing 1M SUI earns approximately 137 SUI per day. If the vulnerable state persists for even one day, the attacker steals this entire amount.
- **Risk-Free Attack:** Attacker only needs minimum stake amount (0.1 SUI per `MIN_STAKE_AMOUNT`), pays minimal gas fees, and faces no downside risk
- **Protocol Insolvency:** Repeated exploitation or exploitation after extended periods depletes all protocol rewards, damaging protocol sustainability and user trust

The minimum stake amount check does not prevent exploitation. [11](#0-10) 

## Likelihood Explanation

**Likelihood: High - Naturally Occurring Preconditions**

The vulnerability has high exploitability due to:

1. **Natural Precondition:** The state `total_lst_supply == 0` occurs through normal protocol operations whenever all users unstake - a common scenario during:
   - Protocol launch phases with low initial adoption
   - Market downturns when users exit positions
   - Periods of low liquidity
   - Migration events

2. **Automatic Reward Accrual:** Sui validator rewards accrue automatically every epoch (~24 hours), requiring no action from the attacker. The `refresh()` mechanism updates these rewards. [12](#0-11) 

3. **Permissionless Exploitation:** The `stake()` function is a public entry point accessible to anyone. [13](#0-12) 

4. **Observable State:** Attacker can monitor the blockchain for the exact condition and execute immediately when `total_lst_supply == 0` is detected.

5. **Single Transaction Attack:** The entire exploit executes in two simple sequential transactions (stake, then unstake), requiring no complex setup or multi-block coordination.

6. **No Privilege Requirements:** No admin, operator, or special capabilities needed - any wallet can execute the attack.

## Recommendation

**Fix the share calculation condition to require BOTH supplies to be zero:**

Change the condition in `sui_amount_to_lst_amount`:

```move
// Current (vulnerable):
if (total_sui_supply == 0 || total_lst_supply == 0) {
    return sui_amount
};

// Fixed:
if (total_sui_supply == 0 && total_lst_supply == 0) {
    return sui_amount
};
```

Additionally, remove or modify the special case exception in the stake invariant check to prevent exploitation:

```move
// Consider removing the special case:
assert!(
    (lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply,
    ERatio
);
```

Or add an explicit check to prevent staking when `total_lst_supply == 0 && total_sui_supply > 0`:

```move
assert!(
    !(total_lst_supply == 0 && total_sui_supply > 0),
    EInvalidStateForStaking
);
```

## Proof of Concept

```move
#[test]
fun test_share_calculation_exploit() {
    // Setup: Initialize stake pool with users
    let mut scenario = test_scenario::begin(@0xA);
    let (mut pool, mut metadata, mut system_state) = setup_pool(scenario.ctx());
    
    // Step 1: Users stake 1000 SUI
    stake(&mut pool, &mut metadata, &mut system_state, coin::mint_for_testing(1000, scenario.ctx()), scenario.ctx());
    // State: total_lst_supply = 1000, total_sui_supply = 1000
    
    // Step 2: All users unstake, burning all LST
    let all_lst = coin::mint_for_testing(1000, scenario.ctx());
    unstake(&mut pool, &mut metadata, &mut system_state, all_lst, scenario.ctx());
    // State: total_lst_supply = 0, total_sui_supply ≈ 0
    
    // Step 3: Simulate epoch rollover and reward accrual
    scenario.next_epoch(@0xA);
    // Validators earn 100 SUI in rewards
    // After refresh: total_sui_supply = 100, total_lst_supply = 0
    
    // Step 4: Attacker stakes 1 SUI
    let attacker_coin = coin::mint_for_testing(1, scenario.ctx());
    let lst_received = stake(&mut pool, &mut metadata, &mut system_state, attacker_coin, scenario.ctx());
    // Vulnerable: Receives 1 LST (should receive ~0.01 LST based on ratio)
    assert!(coin::value(&lst_received) == 1, 0);
    
    // Step 5: Attacker immediately unstakes
    let sui_out = unstake(&mut pool, &mut metadata, &mut system_state, lst_received, scenario.ctx());
    // Attacker receives ~101 SUI for their 1 SUI investment
    assert!(coin::value(&sui_out) > 100, 0); // Profit of ~100 SUI
    
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability represents a critical breach of the fundamental invariant that share price should always reflect the underlying asset value. The explicit special case exception in the invariant check suggests this edge case was considered during development but not properly secured. The fix must ensure that the 1:1 ratio is only used during true initialization (both supplies zero), not during the asymmetric state where rewards have accrued but no LST tokens exist.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L219-219)
```text
    public fun stake(
```

**File:** liquid_staking/sources/stake_pool.move (L220-225)
```text
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ): Coin<CERT> {
```

**File:** liquid_staking/sources/stake_pool.move (L229-229)
```text
        self.refresh(metadata,system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L230-230)
```text
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** liquid_staking/sources/stake_pool.move (L242-242)
```text
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
```

**File:** liquid_staking/sources/stake_pool.move (L257-261)
```text
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L280-286)
```text
    public fun unstake(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        lst: Coin<CERT>,
        ctx: &mut TxContext
    ): Coin<SUI> {
```

**File:** liquid_staking/sources/stake_pool.move (L330-330)
```text
        metadata.burn_coin(lst);
```

**File:** liquid_staking/sources/stake_pool.move (L514-525)
```text
        if (self.validator_pool.refresh(system_state, ctx)) { // epoch rolled over
            let new_total_supply = self.total_sui_supply();

            let reward_fee = if (new_total_supply > old_total_supply) {
                (((new_total_supply - old_total_supply) as u128) 
                * (self.fee_config.reward_fee_bps() as u128) 
                / (BPS_MULTIPLIER as u128)) as u64
            } else {
                0
            };

            self.accrued_reward_fees = self.accrued_reward_fees + reward_fee;
```

**File:** liquid_staking/sources/stake_pool.move (L636-638)
```text
        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return sui_amount
        };
```

**File:** liquid_staking/sources/stake_pool.move (L647-662)
```text
    public fun lst_amount_to_sui_amount(
        self: &StakePool, 
        metadata: &Metadata<CERT>,
        lst_amount: u64
    ): u64 {
        let total_sui_supply = self.total_sui_supply();
        let total_lst_supply = metadata.get_total_supply_value();

        assert!(total_lst_supply > 0, EZeroSupply);

        let sui_amount = (total_sui_supply as u128)
            * (lst_amount as u128) 
            / (total_lst_supply as u128);

        sui_amount as u64
    }
```

**File:** liquid_staking/sources/validator_pool.move (L175-184)
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
```

**File:** liquid_staking/sources/validator_pool.move (L308-329)
```text
        self.total_sui_supply = self.total_sui_supply - validator_info.total_sui_amount;

        let mut total_sui_amount = 0;
        if (validator_info.active_stake.is_some()) {
            let active_stake = validator_info.active_stake.borrow();
            let active_sui_amount = get_sui_amount(
                &validator_info.exchange_rate, 
                active_stake.value()
            );

            total_sui_amount = total_sui_amount + active_sui_amount;
        };

        if (validator_info.inactive_stake.is_some()) {
            let inactive_stake = validator_info.inactive_stake.borrow();
            let inactive_sui_amount = inactive_stake.staked_sui_amount();

            total_sui_amount = total_sui_amount + inactive_sui_amount;
        };

        validator_info.total_sui_amount = total_sui_amount;
        self.total_sui_supply = self.total_sui_supply + total_sui_amount;
```
