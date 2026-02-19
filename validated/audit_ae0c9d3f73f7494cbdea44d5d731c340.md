# Audit Report

## Title
Arithmetic Overflow in Percentage-Based Fee Calculations Causes DoS for Large Transactions

## Summary
The lending_core module performs unsafe u64 × u64 multiplication in fee calculations without intermediate u128 casting, causing arithmetic overflow and transaction abortion for large amounts. This affects both flash loan fee calculations and borrow fee calculations, creating a denial-of-service condition that prevents legitimate large-scale transactions and limits protocol scalability.

## Finding Description

Two critical arithmetic operations perform unsafe percentage-based fee calculations that can overflow:

**Location 1: Flash Loan Fee Calculation**

The flash loan module directly multiplies `_loan_amount` (u64) by `cfg.rate_to_supplier` and `cfg.rate_to_treasury` (both u64) before dividing by `FlashLoanMultiple()` (10000). [1](#0-0) 

The rates are constrained such that their sum must be less than 10000, with worst-case rate of 9999 causing overflow when `_loan_amount > u64::MAX / 9999 ≈ 1,845,529,681,549,704 MIST (≈1.8 million SUI)`. [2](#0-1) 

**Location 2: Borrow Fee Calculation**

The incentive_v3 module's `get_borrow_fee` function multiplies `amount` (u64) by `borrow_fee_rate` (u64) directly before dividing by `percentage_benchmark()` (10000). [3](#0-2) 

The borrow fee rate is capped at 10% (1000 bps), causing overflow when `amount > u64::MAX / 1000 ≈ 18,446,744,073,709,551 MIST (≈18.4 million SUI)`. [4](#0-3) 

**Why Existing Protections Fail**

The flash loan max amount check only validates against configured limits but does not prevent overflow. [5](#0-4) 

The `cfg.max` value itself is unconstrained and can be set to any u64 value by admins without overflow safety validation. [6](#0-5) 

Similarly, borrow validation checks supply balance and borrow caps but does not validate overflow safety. [7](#0-6) 

**Inconsistent with Safe Pattern**

The codebase already demonstrates the correct overflow-safe pattern in the liquid staking fee_config module, which explicitly casts to u128 before multiplication. [8](#0-7) 

This safe pattern is not applied in the lending_core percentage calculations, creating an inconsistency that indicates a code quality issue.

**Publicly Reachable Entry Points**

Both vulnerabilities are in public functions callable by any user. Flash loans are accessible via `flash_loan_with_ctx` and `flash_loan_with_account_cap`. [9](#0-8) 

Borrows are accessible via `entry_borrow`, `borrow_with_account_cap`, and `borrow` functions. [10](#0-9) 

## Impact Explanation

This vulnerability causes operational denial-of-service with the following impacts:

1. **Flash Loan Limitation**: Users cannot process flash loans above approximately 1.8 million SUI when high fee rates (near 9999 bps) are configured. Flash loans are specifically designed for large arbitrage and liquidation operations that regularly exceed these thresholds in mature DeFi protocols.

2. **Borrow Limitation**: Users cannot process borrows above approximately 18.4 million SUI when the maximum 10% borrow fee is enabled. While this is a higher threshold, it becomes realistic as the protocol scales and institutional users participate.

3. **Protocol Scalability Ceiling**: As total value locked increases, the protocol becomes unable to serve its largest users, creating a hard ceiling on growth and limiting competitive positioning.

4. **No Workaround**: Users cannot split flash loans due to atomicity requirements - the entire operation must complete in a single transaction or revert.

5. **Admin Misconfiguration Risk**: Admins can inadvertently set `cfg.max` values that trigger overflow, causing unexpected transaction failures.

The severity is **Medium** because:
- No funds are at risk (Move VM abort prevents silent corruption)
- Protocol functionality is permanently limited for large amounts
- The issue worsens as the protocol grows
- Transactions fail during legitimate operations
- Inconsistent with safe patterns elsewhere in the codebase

## Likelihood Explanation

The likelihood is **High** due to:

1. **Direct Reachability**: The vulnerable code paths are directly accessible through public entry points requiring no special privileges or capabilities.

2. **Realistic Amounts at Scale**: The overflow thresholds fall within typical DeFi transaction ranges for mature protocols. Major DeFi protocols regularly handle flash loans of $50M-$200M. With SUI at $3-5, 1.8M SUI represents $5.4M-$9M, which becomes routine as TVL grows.

3. **No Attack Required**: This manifests during legitimate protocol usage by whale users or institutional participants attempting large transactions. No malicious intent is necessary.

4. **Growing Probability**: As the protocol's TVL increases and attracts larger users, the probability of encountering this limitation increases proportionally.

5. **Simple Reproduction**: Any user can trigger this by calling the public functions with amounts above the overflow threshold, provided they have sufficient collateral and the pool has adequate liquidity.

## Recommendation

Apply the safe arithmetic pattern already used in `fee_config.move` by casting to u128 before multiplication:

**For flash_loan.move (lines 152-153):**
```move
let to_supplier = ((_loan_amount as u128) * (cfg.rate_to_supplier as u128) / (constants::FlashLoanMultiple() as u128)) as u64;
let to_treasury = ((_loan_amount as u128) * (cfg.rate_to_treasury as u128) / (constants::FlashLoanMultiple() as u128)) as u64;
```

**For incentive_v3.move (line 892):**
```move
((amount as u128) * (incentive.borrow_fee_rate as u128) / (constants::percentage_benchmark() as u128)) as u64
```

This ensures the intermediate multiplication result fits in u128 before division, preventing overflow while maintaining precision.

## Proof of Concept

A proof of concept would create a test scenario where:

1. Configure a flash loan asset with high fee rate (e.g., 9999 bps)
2. Set `cfg.max` to a value above the overflow threshold (e.g., 2,000,000,000,000,000 MIST)
3. Attempt to call `flash_loan_with_ctx` with amount at the overflow threshold
4. Transaction aborts due to arithmetic overflow in the fee calculation

The test demonstrates that while the `cfg.max` check passes, the subsequent fee calculation fails, creating a DoS condition for legitimate large transactions that should be supported by the configured limits.

**Notes**

This is a code quality and scalability issue affecting the lending_core module included in the Volo protocol dependencies. While the immediate risk is limited by current TVL levels, this represents a hard ceiling on protocol growth that should be addressed proactively. The fix is straightforward and aligns with existing safe patterns in the codebase (fee_config.move). The inconsistency between modules suggests this was an oversight rather than an intentional design decision.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L290-291)
```text
    fun verify_config(cfg: &AssetConfig) {
        assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L312-315)
```text
    public(friend) fun set_borrow_fee_rate(incentive: &mut Incentive, rate: u64, ctx: &TxContext) {
        version_verification(incentive); // version check
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L56-74)
```text
    public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        // e.g. get the total lending and total collateral for this pool
        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_borrow_balance + amount < scale_supply_balance, error::insufficient_balance());

        // get current borrowing ratio current_borrow_ratio
        let current_borrow_ratio = ray_math::ray_div(scale_borrow_balance + amount, scale_supply_balance);
        // e.g. borrow_ratio
        let borrow_ratio = storage::get_borrow_cap_ceiling_ratio(storage, asset);
        assert!(borrow_ratio >= current_borrow_ratio, error::exceeded_maximum_borrow_cap())
    }
```

**File:** liquid_staking/sources/fee_config.move (L79-80)
```text
        // ceil(sui_amount * sui_stake_fee_bps / 10_000)
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
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
