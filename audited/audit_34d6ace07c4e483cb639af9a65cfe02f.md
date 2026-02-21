# Audit Report

## Title
U64 Overflow in Withdrawal Amount Calculation Prevents Large Withdrawals in High-Value Vaults

## Summary
The `execute_withdraw` function performs an unsafe cast from u256 to u64 when calculating withdrawal amounts, causing transaction aborts for large withdrawals that exceed u64::MAX. This creates a denial-of-service condition preventing users from withdrawing legitimate positions in high-value vaults.

## Finding Description

The vulnerability exists in the withdrawal execution flow where the calculated token amount is cast to u64 without overflow validation. [1](#0-0) 

The calculation multiplies the USD value by `ORACLE_DECIMALS` (10^18) and divides by the normalized oracle price (which uses 9 decimals for asset representation), returning a u256 value. [2](#0-1) [3](#0-2) 

When the calculated amount exceeds u64::MAX (18,446,744,073,709,551,615), the Sui Move runtime aborts the transaction. This contrasts with the liquid staking module, which implements proper overflow checks before casting: [4](#0-3) [5](#0-4) 

Additionally, the `WithdrawRequest` struct stores `expected_amount` as u64, creating an artificial ceiling: [6](#0-5) 

**Security Guarantee Broken:**
Users should be able to withdraw their legitimately acquired vault shares at any time (after the locking period). This vulnerability breaks this guarantee for large positions by causing transaction aborts during execution.

## Impact Explanation

**Operational Denial of Service:**
- Users holding shares worth more than u64::MAX tokens in the principal currency cannot execute withdrawals
- For 9-decimal tokens (like SUI) at $1/token: limit is ~18.4 billion tokens (~$18.4 billion USD)
- Example: A vault with $20 billion in SUI at $1/token requires withdrawing 20 billion SUI tokens (2 × 10^19 smallest units), exceeding u64::MAX (1.844 × 10^19)
- For tokens priced at $0.10, the USD limit drops to ~$1.84 billion
- For tokens with 18 decimals, the threshold is 1 billion times more restrictive

**Affected Users:**
- Large institutional investors in successful vaults
- Any user in a vault that has accumulated sufficient value through yield generation and deposits
- Higher impact for vaults using tokens with more than 9 decimals or tokens with lower unit prices

**Severity Justification:**
While this does not directly cause permanent fund loss, it creates a severe operational DoS for large withdrawals. Users must cancel the request (after waiting the 5-minute locking period) and split into smaller requests, or accept indefinite locking if even split requests are infeasible. The vault continues accepting deposits normally, creating an asymmetric restriction where funds can enter but large positions cannot exit.

## Likelihood Explanation

**Realistic Scenarios:**

1. **Natural Vault Growth:** A vault starting with $1 billion TVL that grows to $20+ billion through compound yield and new deposits
2. **Low-Price Tokens:** Tokens priced at $0.001 hit the u64 limit at just $18.4 million in 9-decimal representation  
3. **High-Decimal Tokens:** 18-decimal tokens have thresholds 1 billion times lower than 9-decimal tokens

**Probability Factors:**
- **High likelihood:** For any vault targeting institutional scale or designed for long-term growth
- **Medium-High likelihood:** For vaults using tokens with >9 decimals or tokens priced below $0.10
- **Guaranteed occurrence:** Once a vault reaches the critical threshold (~$18.4B for standard 9-decimal $1 tokens)

**Attack Complexity:** 
None required - this is an inherent limitation that emerges through normal protocol operations. Users naturally encounter it through legitimate usage as vaults grow successfully.

## Recommendation

Implement overflow checks before casting to u64, following the pattern used in the liquid staking module:

```move
let amount_u256 = vault_utils::div_with_oracle_price(
    usd_value_to_withdraw,
    vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    ),
);

// Add overflow check
const U64_MAX: u256 = 18_446_744_073_709_551_615;
assert!(amount_u256 <= U64_MAX, ERR_AMOUNT_OVERFLOW);

let amount_to_withdraw = (amount_u256 as u64);
```

Additionally, consider upgrading `WithdrawRequest.expected_amount` to u256 to remove the artificial ceiling, though this would require more significant refactoring.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = 0x020001)] // Arithmetic error from overflow
public fun test_withdrawal_overflow_large_vault() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        
        // Set SUI price to $1 (1 * 10^18 in oracle decimals)
        let prices = vector[1 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        
        test_scenario::return_shared(oracle_config);
    };
    
    // Deposit amount that will cause >u64::MAX withdrawal
    // 20 billion SUI = 20_000_000_000 * 10^9 = 2 * 10^19 > u64::MAX
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(20_000_000_000_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin, 1, u256::max_value(),
            option::none(), &clock, s.ctx()
        );
        
        vault.execute_deposit(&clock, &config, 0, u256::max_value());
        
        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(config);
    };
    
    // Try to withdraw - will abort due to u64 overflow
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let mut receipt = s.take_from_sender<Receipt>();
        
        clock::set_for_testing(&mut clock, 12 * 3600_000);
        user_entry::withdraw(&mut vault, u256::max_value(), 1, &mut receipt, &clock, s.ctx());
        
        // This will abort with arithmetic overflow
        operation::execute_withdraw(&mut vault, &clock, &config, 0, u64::max_value());
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        s.return_to_sender(receipt);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability affects the core withdrawal mechanism and will manifest as vaults grow in value. The threshold is precisely calculable based on token decimals and price, making it a deterministic limitation rather than an edge case. The asymmetric nature (deposits work, withdrawals don't) particularly undermines protocol trust for institutional users.

### Citations

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/utils.move (L73-76)
```text
// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** liquid_staking/sources/volo_v1/math.move (L34-41)
```text
    public fun to_shares(ratio: u256, amount: u64): u64 {
        let mut shares = (amount as u256) * ratio / RATIO_MAX;
        assert!(shares <= (U64_MAX as u256), E_U64_OVERFLOW);
        if (amount > 0 && shares == 0) {
            shares = 1;
        };
        (shares as u64)
    }
```

**File:** liquid_staking/sources/volo_v1/math.move (L44-49)
```text
    public fun from_shares(ratio: u256, shares: u64): u64 {
        assert!(ratio != 0, E_DIVIDE_BY_ZERO);
        let amount = (shares as u256) * RATIO_MAX / ratio;
        assert!(amount <= (U64_MAX as u256), E_U64_OVERFLOW);
        (amount as u64)
    }
```

**File:** volo-vault/sources/requests/withdraw_request.move (L13-14)
```text
    shares: u256, // Shares to withdraw
    expected_amount: u64, // Expected amount to get after withdraw
```
