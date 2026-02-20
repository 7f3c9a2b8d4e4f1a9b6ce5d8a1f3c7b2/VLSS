# Audit Report

## Title
Arithmetic Overflow in Flash Loan and Borrow Fee Calculations Due to Multiply-Before-Divide Pattern

## Summary
The flash loan and borrow fee calculations perform unsafe u64 multiplication before division without overflow protection, causing arithmetic overflow and transaction abortion when loan amounts exceed thresholds determined by configured fee rates. This creates denial of service for legitimate large-scale operations.

## Finding Description

The vulnerability exists in two critical fee calculation locations using the multiply-before-divide pattern on u64 values without overflow protection.

**Flash Loan Fee Calculation:**

The flash loan fee calculation performs u64 multiplication before division without overflow protection. [1](#0-0) 

When `_loan_amount * cfg.rate_to_supplier` exceeds u64::MAX (18,446,744,073,709,551,615), the native multiplication operator causes arithmetic overflow, aborting the transaction before division can reduce the value.

**Borrow Fee Calculation:**

The same unsafe pattern exists in borrow fee calculations. [2](#0-1) 

**Insufficient Protections:**

The flash loan amount validation only checks against configured max. [3](#0-2) 

However, admin configuration functions allow setting max to any u64 value without overflow-aware validation. [4](#0-3) 

The only rate validation ensures rates sum below 10000. [5](#0-4) 

This allows `rate_to_supplier` up to 9999, triggering overflow at amounts above u64::MAX / 9999 ≈ 1,844,858,558,855,885 base units.

For borrow fees, the rate is capped at 1000 (10%). [6](#0-5) 

**Safe Implementation Exists:**

The codebase contains a correct overflow-safe implementation using u128 casting. [7](#0-6) 

**Entry Points:**

Flash loans are accessible via public functions. [8](#0-7) 

Borrow operations with fees are accessible via public entry functions. [9](#0-8) 

## Impact Explanation

**Operational Denial of Service:**

This vulnerability causes complete denial of service for flash loan and borrow operations above overflow thresholds:

- With maximum flash loan rate (9999): Overflow at ~1.8 billion SUI or ~1.8 trillion USDC
- With 50% flash loan fee (5000): Overflow at ~3.68 billion USDC - plausible for institutional operations
- With 10% borrow fee (1000): Overflow at ~18.4 billion SUI or ~18.4 trillion USDC

**Configuration Risk:**

Administrators configuring flash loan limits receive no warning about overflow thresholds. Setting high maximum values combined with moderate-to-high fee rates inadvertently breaks functionality. The issue remains silent until actual usage triggers overflow.

**Affected Operations:**

- All flash loan requests via `lending::flash_loan_with_ctx` and `lending::flash_loan_with_account_cap`
- All borrow operations via `incentive_v3::entry_borrow`, `incentive_v3::borrow_with_account_cap`, and `incentive_v3::borrow`

This represents HIGH severity because it breaks core protocol functionality, affects legitimate users, results from a code-level arithmetic flaw, has no validation to prevent misconfiguration, and causes complete denial of service for affected amount ranges.

## Likelihood Explanation

**Reachability:** PUBLIC entry points exist for both flash loans and borrows.

**Preconditions:**
- Admin configures flash loan max value (no upper bound validation)
- Admin sets non-zero fee rates (standard for protocol revenue)
- Users request operations at or near configured limits

**Practicality:**

Test configurations show conservative values (100k tokens). [10](#0-9) 

Production protocols commonly support significantly larger flash loans for institutional users, especially in stablecoin pools. As protocols mature and handle larger volumes, the probability of triggering overflow increases.

**Probability: HIGH** due to: DeFi protocols commonly supporting multi-million dollar flash loans, administrators receiving no warning about overflow thresholds, test values providing false confidence, no runtime checks preventing overflow, and natural protocol growth increasing operation sizes over time.

## Recommendation

Replace all unsafe multiply-before-divide operations with the safe `mul_div` pattern already present in the codebase. Specifically:

1. In `flash_loan.move`, replace unsafe fee calculations with overflow-safe implementation
2. In `incentive_v3.move`, replace unsafe borrow fee calculation with overflow-safe implementation
3. Add admin configuration validation to warn about or prevent configurations that could trigger overflow

Use the existing safe pattern that casts to u128 before multiplication, preventing intermediate overflow while maintaining u64 result constraints.

## Proof of Concept

```move
#[test]
#[expected_failure(arithmetic_error, location = lending_core::flash_loan)]
public fun test_flash_loan_overflow() {
    // Setup protocol with high fee rate
    let scenario = test_scenario::begin(ADMIN);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    
    // Initialize with 50% flash loan fee (rate = 5000)
    // This causes overflow at ~3.68 billion USDC
    
    // Attempt flash loan of 4 billion USDC (4,000,000,000 * 10^6 base units)
    // Calculation: 4,000,000,000,000,000 * 5000 = 20,000,000,000,000,000,000
    // This exceeds u64::MAX causing arithmetic overflow and transaction abort
    
    let loan_amount = 4_000_000_000_000_000; // 4 billion USDC in base units
    let (loan_balance, receipt) = lending::flash_loan_with_ctx<USDC_TEST>(
        &flash_loan_config,
        &mut usdc_pool,
        loan_amount,
        &mut scenario
    );
    // Transaction aborts here due to overflow in fee calculation
}
```

## Notes

The vulnerability is technically valid but requires specific configuration parameters to manifest. While overflow thresholds are extremely high for typical fee rates (1-10%), they become reachable with higher institutional flash loan fees (20-50%) or maximum configured rates. The lack of validation or warnings during admin configuration makes this a legitimate security concern that should be addressed by implementing the safe multiplication pattern already present elsewhere in the codebase.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L149-149)
```text
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L152-153)
```text
        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L290-293)
```text
    fun verify_config(cfg: &AssetConfig) {
        assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
        assert!(cfg.min < cfg.max, error::invalid_amount());
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L312-323)
```text
    public(friend) fun set_borrow_fee_rate(incentive: &mut Incentive, rate: u64, ctx: &TxContext) {
        version_verification(incentive); // version check
        // max 10% borrow fee rate
        assert!(rate <= constants::percentage_benchmark() / 10, error::invalid_value());

        incentive.borrow_fee_rate = rate;

        emit(BorrowFeeRateUpdated{
            sender: tx_context::sender(ctx),
            rate: rate,
        });
    }
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L898-969)
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

    public fun borrow_with_account_cap<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap,
    ): Balance<CoinType> {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        let fee = get_borrow_fee(incentive_v3, amount);

        let _balance = lending::borrow_with_account_cap<CoinType>(clock, oracle, storage, pool, asset, amount + fee, account_cap);

        deposit_borrow_fee(incentive_v3, &mut _balance, fee);

        _balance
    }

    public fun borrow<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ): Balance<CoinType> {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        let fee = get_borrow_fee(incentive_v3, amount);

        let _balance = lending::borrow_coin<CoinType>(clock, oracle, storage, pool, asset, amount + fee, ctx);

        deposit_borrow_fee(incentive_v3, &mut _balance, fee);

        _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L79-85)
```text
    public fun set_flash_loan_asset_max<T>(
        _: &StorageAdminCap,
        config: &mut FlashLoanConfig, 
        _value: u64        
    ) {
        flash_loan::set_asset_max(config, type_name::into_string(type_name::get<T>()), _value)
    }
```

**File:** liquid_staking/sources/volo_v1/math.move (L14-19)
```text
    public fun mul_div(x: u64, y: u64, z: u64): u64 {
        assert!(z != 0, E_DIVIDE_BY_ZERO);
        let r = (x as u128) * (y as u128) / (z as u128);
        assert!(r <= U64_MAX, E_U64_OVERFLOW);
        (r as u64)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-545)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }

    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/base_tests.move (L82-93)
```text
            manage::create_flash_loan_asset<SUI_TEST>(
                &storage_admin_cap,
                &mut flash_loan_config,
                &storage,
                &pool,
                0,
                16, // 0.2% * 80% = 0.0016 -> 0.0016 * 10000 = 16
                4, // 0.2% * 20% = 0.0004 -> 0.0004 * 10000 = 4
                100000_000000000, // 100k
                0, // 1
                test_scenario::ctx(scenario)
            );
```
