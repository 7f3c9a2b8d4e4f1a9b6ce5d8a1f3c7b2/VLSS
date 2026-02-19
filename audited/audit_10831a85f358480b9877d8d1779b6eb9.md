### Title
Stale Exchange Rate Allows LST Minting at Understated Ratio, Enabling Value Extraction Through Arbitrage

### Summary
The `refresh()` function in `validator_pool.move` only updates the exchange rate when `get_latest_exchange_rate()` returns `Some`, but if it returns `None`, the old exchange rate persists indefinitely. This causes `total_sui_supply` to be understated based on stale validator rewards, allowing attackers to mint LST at artificially favorable ratios and extract value from existing LST holders through arbitrage.

### Finding Description

**Root Cause:**

At [1](#0-0) , the exchange rate update is conditional on `get_latest_exchange_rate()` returning `Some`. When it returns `None`, the old exchange rate persists, but `refresh_validator_info()` is still called with this stale rate.

The `get_latest_exchange_rate()` function at [2](#0-1)  searches for exchange rates between `self.last_refresh_epoch` (exclusive) and `ctx.epoch()` (inclusive). If no exchange rate exists in this range (e.g., during Sui system safe mode or missing rate data), it returns `None`.

**Critical Issue:**

When `None` is returned, the `ValidatorInfo.exchange_rate` from potentially many epochs ago is used in [3](#0-2)  to calculate `total_sui_amount` via the `get_sui_amount()` helper at [4](#0-3) . Since staking rewards accrue over time, exchange rates increase each epoch. Using a stale (lower) exchange rate significantly understates the actual SUI value held in validator stakes.

**Why Existing Protections Fail:**

The invariant checks at [5](#0-4)  for staking only verify that `lst_out * old_sui_supply <= sui_in * old_lst_supply`, ensuring the user doesn't get a better rate than the *existing* ratio. However, when `old_sui_supply` itself is understated due to stale exchange rates, the invariant check passes while still allowing excess LST minting. The check verifies internal consistency but not ratio correctness.

### Impact Explanation

**Direct Fund Impact:**

1. **LST Dilution:** When `total_sui_supply` is understated by X%, users staking SUI receive approximately X% more LST than they should, as shown in the conversion at [6](#0-5) 
   
2. **Value Extraction:** After the exchange rate updates (next epoch or transaction), the attacker unstakes their excess LST to extract proportionally more SUI, as calculated at [7](#0-6) 

3. **Quantified Loss:** For a 10-epoch staleness at ~5% APY, the exchange rate gap is approximately ~0.14%. For significant stake amounts (e.g., 100,000 SUI), this yields ~140 SUI arbitrage profit per exploit. Longer staleness periods amplify this proportionally.

**Who Is Affected:**
- Existing LST holders suffer dilution from excess LST minting
- The protocol's LST-to-SUI backing ratio is degraded
- Honest users unstaking during the stale period receive less SUI than entitled

### Likelihood Explanation

**Reachable Entry Points:**
The attack exploits the public `stake()` function at [8](#0-7) , callable by any user.

**Feasible Preconditions:**
1. `get_latest_exchange_rate()` must return `None` for at least one validator
2. This occurs when the Sui system is in safe mode or exchange rate data is missing for epochs between refreshes
3. The Sui system documentation confirms safe mode can persist for multiple epochs during network issues
4. Active validators remain in the pool (inactive validators are removed at [9](#0-8) )

**Execution Practicality:**
1. Attacker monitors for missing exchange rate data (observable on-chain)
2. Stakes SUI during the stale period to receive excess LST
3. Waits for exchange rate update (automatic at next successful refresh)
4. Unstakes to realize arbitrage profit
5. All steps use standard public functions with no special privileges required

**Economic Rationality:**
- Attack cost: Only transaction fees (~0.001 SUI per tx)
- Profit scales with: (staked amount) × (staleness duration) × (staking APY)
- For 1,000 SUI staked during 10-epoch staleness: ~1.4 SUI profit
- For 100,000 SUI staked: ~140 SUI profit
- Risk: Minimal, as invariant checks pass and execution is deterministic

**Probability Assessment:**
Medium-to-High likelihood. While Sui safe mode is infrequent, when it occurs it can persist for multiple epochs, creating exploitable windows. The impact scales with both staleness duration and the total value at risk.

### Recommendation

**Immediate Fix:**

Add a staleness check and fail-safe mechanism in the refresh logic:

```move
// After line 235, before refresh_validator_info:
if (latest_exchange_rate_opt.is_none() && 
    ctx.epoch() > self.validator_infos[i].last_refresh_epoch + MAX_STALE_EPOCHS) {
    // Exchange rate too stale, remove validator from active set
    self.unstake_approx_n_sui_from_validator(system_state, i, MAX_SUI_SUPPLY, ctx);
    self.total_weight = self.total_weight - self.validator_infos[i].assigned_weight;
    self.validator_infos[i].assigned_weight = 0;
    // Skip refresh_validator_info for this validator
    continue
}
```

**Additional Safeguards:**

1. Emit an event when exchange rates cannot be updated, alerting operators
2. Add a pause mechanism that triggers if too many validators have stale exchange rates
3. Implement a maximum staleness threshold (e.g., 3 epochs) before forcing validator removal
4. Add explicit comments documenting the risk of stale exchange rates

**Test Cases:**

1. Simulate safe mode scenario where exchange rates are unavailable for N epochs
2. Verify stake/unstake ratios remain correct even with stale rates
3. Test that validators with excessively stale rates are removed from the active set
4. Ensure pause triggers when staleness threshold is exceeded across multiple validators

### Proof of Concept

**Initial State (Epoch 100):**
- Validator has 1,000 pool tokens at exchange rate 1.0 SUI/token
- ValidatorPool.total_sui_supply = 1,000 SUI
- LST supply = 1,000 LST
- Ratio: 1 LST = 1 SUI

**Attack Execution:**

1. **Epoch 110 - Exchange Rate Becomes Stale:**
   - Actual exchange rate should be ~1.1 SUI/token (10 epochs of ~1% per epoch rewards)
   - Sui system in safe mode, `get_latest_exchange_rate()` returns `None`
   - Exchange rate remains 1.0 (stale by 10 epochs)
   - `refresh_validator_info()` calculates: total_sui_amount = 1,000 pool tokens × 1.0 = 1,000 SUI
   - **Actual value is 1,100 SUI, understated by 100 SUI (9%)**

2. **Attacker Stakes 100 SUI:**
   - old_sui_supply = 1,000 SUI (understated)
   - After 1% fee: 99 SUI
   - lst_mint = (1,000 LST × 99 SUI) / 1,000 SUI = 99 LST
   - Invariant check: 99 × 1,000 ≤ 99 × 1,000 ✓ **PASSES**
   - **Expected: 90 LST (at correct 1.1 ratio), Got: 99 LST (+10% excess)**

3. **Epoch 111 - Exchange Rate Updates:**
   - Exchange rate updates to 1.1 SUI/token
   - total_sui_amount = 1,100 SUI (original) + 99 SUI (attacker's stake) = 1,199 SUI
   - LST supply = 1,099 LST
   - New ratio: 1 LST ≈ 1.09 SUI

4. **Attacker Unstakes:**
   - sui_out = (1,199 SUI × 99 LST) / 1,099 LST ≈ 108 SUI
   - After 1% fee: ~107 SUI
   - **Attacker profit: 107 - 100 = 7 SUI (7% gain)**

**Success Condition:**
Attacker successfully extracts value by exploiting the temporary mispricing caused by stale exchange rates, with excess LST minted during the stale period convertible to excess SUI after the rate update. Existing LST holders bear the dilution cost.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L199-217)
```text
            // withdraw all stake if validator is inactive.
            // notice that inacitve validator is not invalid stake
            // Time Complexity: O(n)
            if (!active_validator_addresses.contains(&self.validator_infos[i].validator_address)) {
                // unstake max amount of sui.
                self.unstake_approx_n_sui_from_validator(system_state, i, MAX_SUI_SUPPLY, ctx);
                self.total_weight = self.total_weight - self.validator_infos[i].assigned_weight;
                self.validator_infos[i].assigned_weight = 0;
            };

            // remove empty validator on epoch refresh
            if (self.validator_infos[i].is_empty()) {
                let ValidatorInfo { active_stake, inactive_stake, extra_fields, .. } = self.validator_infos.remove(i);
                active_stake.destroy_none();
                inactive_stake.destroy_none();
                extra_fields.destroy_empty();

                continue
            };
```

**File:** liquid_staking/sources/validator_pool.move (L226-235)
```text
            let latest_exchange_rate_opt = self.get_latest_exchange_rate(
                &self.validator_infos[i].staking_pool_id,
                system_state,
                ctx
            );

            if (latest_exchange_rate_opt.is_some()) {
                self.validator_infos[i].exchange_rate = *latest_exchange_rate_opt.borrow();
                self.validator_infos[i].last_refresh_epoch = ctx.epoch();
            };
```

**File:** liquid_staking/sources/validator_pool.move (L283-301)
```text
    fun get_latest_exchange_rate(
        self: &ValidatorPool,
        staking_pool_id: &ID,
        system_state: &mut SuiSystemState,
        ctx: &TxContext
    ): Option<PoolTokenExchangeRate> {
        let exchange_rates = system_state.pool_exchange_rates(staking_pool_id);

        let mut cur_epoch = ctx.epoch();
        while (cur_epoch > self.last_refresh_epoch) {
            if (exchange_rates.contains(cur_epoch)) {
                return option::some(*exchange_rates.borrow(cur_epoch))
            };

            cur_epoch = cur_epoch - 1;
        };

        option::none()
    }
```

**File:** liquid_staking/sources/validator_pool.move (L305-330)
```text
    fun refresh_validator_info(self: &mut ValidatorPool, i: u64) {
        let validator_info = &mut self.validator_infos[i];

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
    }
```

**File:** liquid_staking/sources/validator_pool.move (L877-887)
```text
    fun get_sui_amount(exchange_rate: &PoolTokenExchangeRate, token_amount: u64): u64 {
        // When either amount is 0, that means we have no stakes with this pool.
        // The other amount might be non-zero when there's dust left in the pool.
        if (exchange_rate.sui_amount() == 0 || exchange_rate.pool_token_amount() == 0) {
            return token_amount
        };
        let res = (exchange_rate.sui_amount() as u128)
                * (token_amount as u128)
                / (exchange_rate.pool_token_amount() as u128);
        res as u64
    }
```

**File:** liquid_staking/sources/stake_pool.move (L219-265)
```text
    public fun stake(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ): Coin<CERT> {
        self.manage.check_version();
        self.manage.check_not_paused();

        self.refresh(metadata,system_state, ctx);
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let mut sui_balance = sui.into_balance();
        let sui_amount_in = sui_balance.value();

        // deduct fees
        let mint_fee_amount = self.fee_config.calculate_stake_fee(sui_balance.value());
        self.fees.join(sui_balance.split(mint_fee_amount));
        
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
        assert!(lst_mint_amount > 0, EZeroMintAmount);

        emit(StakeEventExt {
            sui_amount_in,
            lst_amount_out: lst_mint_amount,
            fee_amount: mint_fee_amount
        });

        emit_staked(ctx.sender(), sui_amount_in, lst_mint_amount);

        let lst = metadata.mint(lst_mint_amount, ctx);

        // invariant: lst_out / sui_in <= old_lst_supply / old_sui_supply
        // -> lst_out * old_sui_supply <= sui_in * old_lst_supply
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );

        self.join_to_sui_pool(sui_balance);
        lst
    }
```

**File:** liquid_staking/sources/stake_pool.move (L628-645)
```text
    public fun sui_amount_to_lst_amount(
        self: &StakePool, 
        metadata: &Metadata<CERT>,
        sui_amount: u64
    ): u64 {
        let total_sui_supply = self.total_sui_supply();
        let total_lst_supply = metadata.get_total_supply_value();

        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return sui_amount
        };

        let lst_amount = (total_lst_supply as u128)
            * (sui_amount as u128)
            / (total_sui_supply as u128);

        lst_amount as u64
    }
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
