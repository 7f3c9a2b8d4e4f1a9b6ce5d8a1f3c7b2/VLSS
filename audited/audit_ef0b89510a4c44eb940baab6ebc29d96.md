# Audit Report

## Title
Arithmetic Overflow in Percentage-Based Fee Calculations Causes DoS for Large Transactions

## Summary
The lending_core module performs percentage-based fee calculations using direct u64 multiplication without intermediate u128 casting, causing arithmetic overflow and transaction abortion for large but realistic loan amounts. This creates a denial-of-service condition that prevents users from executing legitimate large-scale flash loans and borrows, permanently limiting protocol scalability.

## Finding Description

Two critical locations perform unsafe percentage calculations that will overflow for large amounts:

**Location 1: Flash Loan Fee Calculation**

The flash loan module multiplies `_loan_amount` (u64) by fee rates (u64) directly before dividing by 10000 [1](#0-0) . Both `_loan_amount` and the rate fields are u64 types [2](#0-1) , and the intermediate multiplication result is not cast to u128, causing overflow when the product exceeds u64::MAX.

**Location 2: Borrow Fee Calculation**

The `get_borrow_fee` function multiplies `amount` (u64) by `borrow_fee_rate` (u64) directly before dividing by 10000 [3](#0-2) . The borrow_fee_rate is stored as u64 [4](#0-3) , creating the same overflow vulnerability pattern.

**Overflow Thresholds**

The percentage benchmark is 10000 [5](#0-4) . 

For flash loans, the sum of rates must be less than 10000 [6](#0-5) , allowing a maximum single rate of 9999. This causes overflow when: `_loan_amount > u64::MAX / 9999 ≈ 1,845,529,218,221,373 MIST (≈1.845 million SUI)`.

For borrows, the fee rate is capped at 10% [7](#0-6) , which is 1000 basis points. This causes overflow when: `amount > u64::MAX / 1000 ≈ 18,446,744,073,709,551 MIST (≈18.4 million SUI)`.

**Why Existing Protections Fail**

The flash loan max amount check only validates against configured limits [8](#0-7) , not overflow safety. The `cfg.max` field is a u64 [9](#0-8)  that can be set to any value by admins [10](#0-9)  without overflow constraints.

**Inconsistent Pattern**

The codebase demonstrates the correct overflow-safe pattern in the liquid staking fee_config module, which casts to u128 before multiplication [11](#0-10)  and [12](#0-11) . This safe pattern is not applied in the lending_core fee calculations.

## Impact Explanation

This vulnerability causes operational denial-of-service with the following impact:

1. **Flash Loans**: Users cannot process flash loans above ~1.845 million SUI with high fee rates. Flash loans are designed for large arbitrage and liquidation operations that can legitimately exceed this threshold in mature DeFi protocols.

2. **Borrows**: Users cannot process borrows above ~18.4 million SUI with 10% borrow fee enabled. While higher than flash loan threshold, this becomes realistic as TVL grows and institutional users participate.

3. **Protocol Growth Limitation**: As the protocol scales, it becomes unable to serve its largest users, creating competitive disadvantage versus protocols that handle arbitrarily large amounts.

4. **No Workaround**: Users cannot split flash loans due to atomicity requirements - the entire amount must be borrowed and repaid in a single transaction.

The severity is **Medium** because while no funds are at risk (Move VM prevents silent corruption by aborting), the protocol functionality is permanently limited for large but legitimate amounts, and users encounter hard failures during valid operations.

## Likelihood Explanation

**High likelihood** due to:

1. **Public Entry Points**: Both vulnerabilities are in public functions callable by any user. Flash loans are accessible via `flash_loan_with_ctx` [13](#0-12)  and `flash_loan_with_account_cap` [14](#0-13) . Borrows are accessible via `entry_borrow` [15](#0-14) .

2. **Realistic Amounts**: Major DeFi protocols regularly handle flash loans of $50M-$200M. With SUI at $3-5, 1.845M SUI represents $5.5M-$9.2M, which is achievable for mature protocols. As TVL grows, these amounts become routine.

3. **No Attack Required**: This occurs during legitimate usage. A whale user attempting a large flash loan or borrow will experience transaction failure without any malicious intent.

4. **No Special Privileges**: Any user can trigger by calling public functions with large amounts. No admin rights or capabilities required beyond normal collateral requirements for borrows.

5. **Simple Reproduction**: Just call the function with an amount above the overflow threshold. All preconditions (sufficient collateral for borrows, pool liquidity) can be legitimately met.

## Recommendation

Apply the same overflow-safe pattern used in the liquid staking fee_config module. Cast operands to u128 before multiplication:

**For flash_loan.move (lines 152-153):**
```move
let to_supplier = ((_loan_amount as u128) * (cfg.rate_to_supplier as u128) / (constants::FlashLoanMultiple() as u128)) as u64;
let to_treasury = ((_loan_amount as u128) * (cfg.rate_to_treasury as u128) / (constants::FlashLoanMultiple() as u128)) as u64;
```

**For incentive_v3.move (line 892):**
```move
((amount as u128) * (incentive.borrow_fee_rate as u128) / (constants::percentage_benchmark() as u128)) as u64
```

Additionally, consider adding overflow validation when setting `cfg.max` for flash loans to prevent admins from accidentally configuring unsafe values.

## Proof of Concept

```move
#[test]
fun test_flash_loan_overflow() {
    // Setup lending pool with sufficient liquidity
    let ctx = tx_context::dummy();
    let clock = clock::create_for_testing(&mut ctx);
    
    // Create flash loan config with 99.99% fee (9999 bps)
    let mut config = flash_loan::create_config_for_test(&mut ctx);
    flash_loan::create_asset(
        &mut config,
        0, // asset_id
        ascii::string(b"0x2::sui::SUI"),
        @pool_address,
        9999, // rate_to_supplier (max allowed)
        0,    // rate_to_treasury
        18_446_744_073_709_551_615, // max set to u64::MAX
        1,    // min
        &mut ctx
    );
    
    let mut pool = create_test_pool(&mut ctx);
    
    // Attempt flash loan with amount that causes overflow
    // amount = 1,845,529,218,221,374 (just above threshold)
    // calculation: 1,845,529,218,221,374 * 9999 > u64::MAX
    let loan_amount = 1_845_529_218_221_374;
    
    // This will abort with arithmetic overflow
    let (balance, receipt) = flash_loan::loan<SUI>(
        &config,
        &mut pool,
        @user,
        loan_amount
    );
    
    // Test fails here due to overflow abort
    abort 0
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L36-37)
```text
        rate_to_supplier: u64, // x * MultiBy --> 10% == 0.1 * 10000 = 1000, 0.09 -> 0.09 * 80% = supplier
        rate_to_treasury: u64, // x * MultiBy --> 10% == 0.1 * 10000 = 1000
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L38-38)
```text
        max: u64,
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L149-149)
```text
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L152-153)
```text
        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L276-280)
```text
    public(friend) fun set_asset_max(config: &mut Config, _coin_type: String, _value: u64) {
        version_verification(config);
        let cfg = get_asset_config_by_coin_type(config, _coin_type); 
        cfg.max = _value;  
        verify_config(cfg);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L291-291)
```text
        assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L38-38)
```text
        borrow_fee_rate: u64,
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L314-315)
```text
        // max 10% borrow fee rate
        assert!(rate <= constants::percentage_benchmark() / 10, error::invalid_value());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L890-896)
```text
    fun get_borrow_fee(incentive: &Incentive, amount: u64): u64 {
        if (incentive.borrow_fee_rate > 0) {
            amount * incentive.borrow_fee_rate / constants::percentage_benchmark()
        } else {
            0
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L898-921)
```text
    public entry fun entry_borrow<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        let fee = get_borrow_fee(incentive_v3, amount);

        let _balance =  lending::borrow_coin<CoinType>(clock, oracle, storage, pool, asset, amount + fee, ctx);

        deposit_borrow_fee(incentive_v3, &mut _balance, fee);

        let _coin = coin::from_balance(_balance, ctx);
        transfer::public_transfer(_coin, tx_context::sender(ctx));
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L16-18)
```text
    public fun FlashLoanMultiple(): u64 {10000}

    public fun percentage_benchmark(): u64 {10000}
```

**File:** liquid_staking/sources/fee_config.move (L80-80)
```text
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
```

**File:** liquid_staking/sources/fee_config.move (L89-89)
```text
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-541)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L543-545)
```text
    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }
```
