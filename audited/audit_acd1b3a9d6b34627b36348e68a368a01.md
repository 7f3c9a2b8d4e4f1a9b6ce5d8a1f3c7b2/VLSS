Audit Report

## Title
Deposit Execution DoS via Zero-Share Rounding on Minimal Deposits

## Summary
The vault's `execute_deposit` function aborts when user shares calculation rounds to zero due to integer division, preventing execution of valid deposit requests. Users can deposit minimal amounts (1 unit) that pass validation but become unexecutable as the vault matures, temporarily locking funds and enabling griefing attacks.

## Finding Description

The vulnerability exists in the share calculation logic during deposit execution. When a user deposits a minimal amount, the calculated USD value may be too small relative to the vault's share ratio, causing integer division to round down to zero and trigger an assertion failure.

**Root Cause:**

The `execute_deposit` function calculates user shares using integer division without checking if the deposit amount is viable given the current share ratio. [1](#0-0) 

The `div_d` utility performs the calculation as `v1 * DECIMALS / v2` where DECIMALS = 10^9. [2](#0-1) 

When `new_usd_value_deposited * 10^9 < share_ratio`, the result rounds to zero, triggering the assertion. [3](#0-2) 

**Exploit Path:**

1. User calls `deposit()` with minimal amount (1 unit), which only validates `amount > 0`. [4](#0-3) 

2. The deposit is buffered in vault storage awaiting operator execution.

3. When operator executes, USD value is calculated using oracle prices with 18-decimal precision. [5](#0-4) [6](#0-5) 

4. For 1 unit at $2/SUI price: `new_usd_value_deposited = 1 * (2 * 10^18) / 10^18 = 2` (representing 2 / 10^9 USD)

5. In a mature vault with share_ratio = 10^13 (e.g., $1M TVL, 100K shares): `user_shares = 2 * 10^9 / 10^13 = 0.0002 = 0`

6. The assertion fails, aborting execution and leaving funds locked.

**Why Protections Fail:**

- No minimum deposit validation based on current share ratio
- Only validates `amount > 0`, not minimum viable USD value
- Deposit fee also rounds to zero for tiny amounts. [7](#0-6) [8](#0-7) 
- No graceful handling of zero-share edge case

## Impact Explanation

**Protocol DoS and Griefing Vector:**

- Valid deposit requests become permanently unexecutable when share ratio exceeds threshold relative to deposit amount
- Users' funds are temporarily locked in the request buffer for the cancellation period (5 minutes by default) [9](#0-8) 
- Malicious actors can spam minimal deposits to clog request buffers with unexecutable requests
- Operators waste gas repeatedly attempting to execute deposits that will always fail
- Request buffer integrity compromised as unexecutable deposits accumulate

While funds are not permanently lost (users can cancel after the locking period), this represents a significant protocol disruption and griefing vulnerability.

## Likelihood Explanation

**Highly Realistic:**

- Any user can trigger by depositing minimal amounts (1 unit) which passes all entry validations
- Naturally occurs as vaults mature - share ratio increases with accumulated profits
- No special permissions, timing, or oracle manipulation required
- Realistic scenario: A vault with $1M TVL and 100K shares has `share_ratio = 10^13`, making deposits under ~10 units unexecutable
- The combination of 18-decimal oracle prices and 9-decimal vault amounts makes sub-unit USD values common for minimal deposits

## Recommendation

Implement a minimum viable deposit amount check that considers the current share ratio:

```move
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    // ... existing code ...
    
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    
    // If shares would round to zero, refund the deposit gracefully instead of aborting
    if (user_shares == 0) {
        // Return the coin to the user
        let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
        transfer::public_transfer(coin, deposit_request.recipient());
        self.delete_deposit_request(request_id);
        return
    };
    
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    // ... rest of function ...
}
```

Alternatively, add minimum deposit validation at request time:

```move
public fun deposit<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    // ... params ...
) {
    assert!(amount > 0, ERR_INVALID_AMOUNT);
    
    // Calculate minimum amount needed to mint at least 1 share
    let share_ratio = vault.get_share_ratio_without_update();
    let min_usd_value_needed = vault_utils::div_d(1, vault_utils::decimals()); // 1 share worth of USD
    let oracle_price = get_current_price(config, clock, coin_type);
    let min_amount = vault_utils::div_with_oracle_price(min_usd_value_needed, oracle_price);
    
    assert!(amount >= min_amount, ERR_AMOUNT_TOO_SMALL);
    // ... rest of function ...
}
```

## Proof of Concept

```move
#[test]
fun test_deposit_execution_dos_via_zero_share_rounding() {
    let mut scenario = test_scenario::begin(USER);
    
    // Setup vault with mature state ($1M TVL, 100K shares)
    setup_mature_vault(&mut scenario);
    
    scenario.next_tx(USER);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let mut reward_manager = scenario.take_shared<RewardManager<SUI>>();
        let clock = scenario.take_shared<Clock>();
        let oracle_config = scenario.take_shared<OracleConfig>();
        
        // User deposits minimal amount (1 unit) - passes validation
        let coin = coin::mint_for_testing<SUI>(1, scenario.ctx());
        let (request_id, receipt, _) = user_entry::deposit(
            &mut vault,
            &mut reward_manager,
            coin,
            1,
            0, // expected_shares
            option::none(),
            &clock,
            scenario.ctx()
        );
        
        transfer::public_transfer(receipt, USER);
        
        scenario.return_shared(vault);
        scenario.return_shared(reward_manager);
        scenario.return_shared(clock);
        scenario.return_shared(oracle_config);
    };
    
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let clock = scenario.take_shared<Clock>();
        let oracle_config = scenario.take_shared<OracleConfig>();
        let operator_cap = scenario.take_from_sender<OperatorCap>();
        
        // Operator attempts execution - will abort with ERR_ZERO_SHARE
        // because 1 unit * $2 = 2 USD value (in vault decimals)
        // and 2 * 10^9 / 10^13 = 0 shares
        operation::execute_deposit(
            &operator_cap,
            &mut vault,
            &clock,
            &oracle_config,
            request_id,
            1000, // max_shares_received
        ); // This will abort with ERR_ZERO_SHARE
        
        scenario.return_to_sender(operator_cap);
        scenario.return_shared(vault);
        scenario.return_shared(clock);
        scenario.return_shared(oracle_config);
    };
    
    scenario.end();
}
```

## Notes

This vulnerability represents a critical edge case in the vault's share-based accounting system. While user funds are not permanently lost (cancellation is possible after the locking period), the DoS impact on protocol operations and the griefing attack vector make this a valid security concern. The issue becomes more severe as the vault matures and the share ratio increases, making it a time-dependent vulnerability that worsens with protocol success.

### Citations

**File:** volo-vault/sources/volo_vault.move (L28-30)
```text
const RATE_SCALING: u64 = 10_000;

const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L36-36)
```text
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L830-830)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L848-848)
```text
    assert!(user_shares > 0, ERR_ZERO_SHARE);
```

**File:** volo-vault/sources/volo_vault.move (L1115-1118)
```text
    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/user_entry.move (L29-29)
```text
    assert!(amount > 0, ERR_INVALID_AMOUNT);
```
