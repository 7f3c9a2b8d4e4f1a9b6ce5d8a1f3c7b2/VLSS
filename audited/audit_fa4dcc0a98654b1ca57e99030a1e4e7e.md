### Title
Lack of Slippage Protection in Liquid Staking Stake/Unstake Functions Exposes Users to Exchange Rate Fluctuations

### Summary
The `stake()` and `unstake()` functions in the liquid staking module lack slippage protection parameters, exposing users to unfavorable exchange rate changes between transaction submission and execution. Unlike the vault module which implements dual-sided slippage protection with `expected_shares`/`max_shares_received` parameters, liquid staking functions calculate outputs based solely on the exchange rate at execution time with no user-specified minimum output protection.

### Finding Description
The external report describes a vulnerability where deposit functions lack `min_shares_out` parameters, allowing users to receive fewer shares than expected due to NAV manipulation or front-running. This same vulnerability class exists in Volo's liquid staking module.

**Affected Functions:**

1. **stake() function** [1](#0-0) 
   - Accepts SUI input and returns LST (CERT) tokens
   - Calculates output using `sui_amount_to_lst_amount()` based on current exchange rate [2](#0-1) 
   - Only validates `lst_mint_amount > 0`, no minimum output parameter
   - Function signature has no slippage protection parameter

2. **unstake() function** [3](#0-2) 
   - Accepts LST tokens and returns SUI
   - Calculates output using `lst_amount_to_sui_amount()` [4](#0-3) 
   - Only validates `sui_amount_out >= MIN_STAKE_AMOUNT` (0.1 SUI minimum)
   - No user-specified minimum output parameter

**Exchange Rate Mechanism:**

The exchange rate is calculated on-chain based on total supplies [5](#0-4) :
- Formula: `lst_amount = (total_lst_supply * sui_amount) / total_sui_supply`
- The rate changes when:
  - Other users stake/unstake (modifying total supplies)
  - `refresh()` updates rewards from epoch changes [6](#0-5) 
  - Transaction ordering/MEV manipulation

**Root Cause:**

Unlike the vault module which has comprehensive slippage protection [7](#0-6)  and [8](#0-7) , the liquid staking module lacks any user-specified minimum output parameters. The error constants defined [9](#0-8)  do not include slippage protection errors.

**Why Protections Fail:**

The invariant checks in both functions [10](#0-9)  and [11](#0-10)  only prevent users from receiving MORE than the old exchange rate would give (preventing bugs/exploits where users benefit), but do NOT protect users from receiving LESS than expected.

### Impact Explanation
**High Impact:** Users can suffer unexpected losses when:
- Large stakes/unstakes from other users change the exchange rate before their transaction executes
- Epoch changes trigger `refresh()` updating total_sui_supply [12](#0-11) 
- MEV bots reorder transactions to extract value
- Front-running attacks execute unfavorable rate changes

Unlike the vault's oracle-based NAV (which the external client claimed was "extremely difficult to manipulate"), liquid staking uses purely on-chain state calculations that are directly affected by user actions and system updates.

### Likelihood Explanation
**High Likelihood:** The exploit path is trivially executable:
- Entry points are public functions accessible to any user [13](#0-12)  and [14](#0-13) 
- No special permissions required
- Exchange rate changes naturally occur from normal protocol operations
- Users have no protection mechanism currently available
- Both stake and unstake operations are affected

### Recommendation
Modify both `stake()` and `unstake()` functions to accept slippage protection parameters:

**For stake():**
```
public fun stake(
    self: &mut StakePool, 
    metadata: &mut Metadata<CERT>,
    system_state: &mut SuiSystemState, 
    sui: Coin<SUI>,
    min_lst_out: u64,  // ADD THIS
    ctx: &mut TxContext
): Coin<CERT>
```
Add assertion after line 242: `assert!(lst_mint_amount >= min_lst_out, ERR_UNEXPECTED_SLIPPAGE);`

**For unstake():**
```
public fun unstake(
    self: &mut StakePool,
    metadata: &mut Metadata<CERT>,
    system_state: &mut SuiSystemState, 
    lst: Coin<CERT>,
    min_sui_out: u64,  // ADD THIS
    ctx: &mut TxContext
): Coin<SUI>
```
Add assertion after line 294: `assert!(sui_amount_out >= min_sui_out, ERR_UNEXPECTED_SLIPPAGE);`

Define new error constant: `const ERR_UNEXPECTED_SLIPPAGE: u64 = 30004;`

### Proof of Concept
**Scenario:**
1. Current state: `total_sui_supply = 1,000,000 SUI`, `total_lst_supply = 950,000 LST`
2. Exchange rate: 1 SUI → 0.95 LST
3. Alice submits `stake(10,000 SUI)` expecting ~9,500 LST
4. Before Alice's transaction executes, Bob stakes 100,000 SUI, changing the state
5. New exchange rate becomes slightly different due to the state change
6. Alice's transaction executes at the new rate with no minimum output protection
7. Alice receives a different amount than expected with no recourse

**Concrete execution path:**
- Alice calls `stake_entry()` [13](#0-12) 
- Transaction enters mempool
- State changes from other transactions or `refresh()` calls
- Alice's `stake()` executes with modified `total_sui_supply`/`total_lst_supply` [15](#0-14) 
- Calculation uses current (changed) rate [16](#0-15) 
- Only check is `lst_mint_amount > 0` [17](#0-16) 
- Alice receives unpredictable output amount

### Citations

**File:** liquid_staking/sources/stake_pool.move (L35-38)
```text
    const EZeroMintAmount: u64 = 30000;
    const ERatio: u64 = 30001;
    const EZeroSupply: u64 = 30002;
    const EUnderMinAmount: u64 = 30003;
```

**File:** liquid_staking/sources/stake_pool.move (L176-186)
```text
    public entry fun stake_entry(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let cert = self.stake(metadata, system_state, sui, ctx);
        transfer::public_transfer(cert, ctx.sender());
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

**File:** liquid_staking/sources/stake_pool.move (L280-333)
```text
    public fun unstake(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        lst: Coin<CERT>,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.manage.check_not_paused();
        self.refresh(metadata, system_state, ctx);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);

        // deduct fee
        let redeem_fee_amount = self.fee_config.calculate_unstake_fee(sui.value());
        let redistribution_amount = 
            if(total_lst_supply(metadata) == lst.value()) {
                0
            } else {
                self.fee_config.calculate_unstake_fee_redistribution(redeem_fee_amount)
            };

        let mut fee = sui.split(redeem_fee_amount as u64);
        let redistribution_fee = fee.split(redistribution_amount);

        self.fees.join(fee);
        self.join_to_sui_pool(redistribution_fee);

        emit(UnstakeEventExt {
            lst_amount_in: lst.value(),
            sui_amount_out: sui.value(),
            fee_amount: redeem_fee_amount - redistribution_amount,
            redistribution_amount: redistribution_amount
        });

        emit_unstaked(ctx.sender(), lst.value(), sui.value());

        // invariant: sui_out / lst_in <= old_sui_supply / old_lst_supply
        // -> sui_out * old_lst_supply <= lst_in * old_sui_supply
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );

        metadata.burn_coin(lst);

        coin::from_balance(sui, ctx)
    }
```

**File:** liquid_staking/sources/stake_pool.move (L503-550)
```text
    public fun refresh(
        self: &mut StakePool, 
        metadata: &Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        ctx: &mut TxContext
    ): bool {
        self.manage.check_version();
        self.manage.check_not_paused();

        let old_total_supply = self.total_sui_supply();

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

            let mut boosted_reward_amount = self.boosted_reward_amount;

            if (new_total_supply > old_total_supply) {
                // boosted_reward_amount = min(new_reward, boosted_balance, set_reward_amount)
                boosted_reward_amount = boosted_reward_amount.min(new_total_supply - old_total_supply).min(self.boosted_balance.value());
                let boosted_reward = self.boosted_balance.split(boosted_reward_amount);
                self.join_to_sui_pool(boosted_reward);
            } else {
                boosted_reward_amount = 0;
            };

            emit(EpochChangedEvent {
                old_sui_supply: old_total_supply,
                new_sui_supply: new_total_supply,
                boosted_reward_amount: boosted_reward_amount,
                lst_supply: total_lst_supply(metadata),
                reward_fee
            });

            return true
        };

        false
    }
```

**File:** liquid_staking/sources/stake_pool.move (L559-561)
```text
    public fun total_sui_supply(self: &StakePool): u64 {
        self.validator_pool.total_sui_supply() - self.accrued_reward_fees
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

**File:** volo-vault/sources/volo_vault.move (L849-850)
```text
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1029-1030)
```text
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);
```
