### Title
Flash Loan Operations Bypass Protocol Pause Mechanism Enabling Unauthorized Fund Access During Emergency

### Summary
The lending_core protocol implements a pause mechanism (error code 1500) to halt critical operations during emergencies. However, flash loan operations completely bypass this pause check, allowing attackers to access protocol liquidity and modify protocol state even when the protocol is paused. This violates the fundamental pause invariant and enables exploitation of vulnerabilities that the pause was meant to prevent.

### Finding Description

The pause mechanism is defined with error code 1500 [1](#0-0) , and the pause state is stored in the Storage struct [2](#0-1) . The enforcement function checks this state and aborts with error 1500 if paused [3](#0-2) .

**Root Cause:** All critical lending operations properly check the pause state:
- Deposits check pause [4](#0-3) 
- Withdrawals check pause [5](#0-4) 
- Borrows check pause [6](#0-5) 
- Repayments check pause [7](#0-6) 
- Liquidations check pause [8](#0-7) 

However, flash loans have NO pause checks in their implementation [9](#0-8)  nor in their repayment logic [10](#0-9) . The public entry points for flash loans also bypass pause checks [11](#0-10) [12](#0-11) .

**Why Protections Fail:** During flash loan repayment, the protocol state is actively modified through interest rate updates and supply index cumulation [13](#0-12) , all while the protocol is supposed to be frozen.

### Impact Explanation

**Security Integrity Impact:**
- Complete bypass of the pause mechanism, which is a critical circuit breaker for emergencies
- Attackers gain temporary access to protocol liquidity when it should be frozen
- Protocol state is modified (interest rates, supply indices) during pause, violating the pause invariant

**Concrete Harm:**
1. If protocol is paused due to a discovered vulnerability, attackers can exploit it via flash loans before remediation
2. Flash loans can be used for price manipulation or other attacks even during emergency pause
3. State modifications during pause can compound the impact of the underlying issue that triggered the pause
4. Emergency response effectiveness is compromised as the protocol isn't truly paused

**Affected Parties:**
- All protocol users whose funds remain at risk during pause
- Protocol administrators whose emergency controls are ineffective
- The protocol treasury that accumulates flash loan fees during what should be a frozen state

### Likelihood Explanation

**Reachable Entry Point:** Flash loans are publicly accessible through multiple entry points that require no special permissions [14](#0-13) .

**Attacker Capabilities:** Any user can call flash loan functions. No special permissions, tokens, or preconditions are required beyond the flash loan being configured for an asset.

**Execution Practicality:** The attack is straightforward:
1. Protocol is paused via `set_pause()` by admin due to emergency [15](#0-14) 
2. Attacker calls `flash_loan_with_ctx()` or `flash_loan_with_account_cap()` - no pause check occurs
3. Attacker receives borrowed funds despite pause
4. Attacker performs malicious operations with the funds
5. Attacker repays flash loan - state modifications occur despite pause

**Economic Rationality:** If the protocol is paused due to a vulnerability, the economic incentive to exploit via flash loans is high, as the attacker has a time window before the issue is fixed. Flash loan fees are minimal compared to potential exploit profits.

**Probability:** HIGH - The pause mechanism is specifically designed for emergencies, making this bypass extremely dangerous during critical moments.

### Recommendation

**Immediate Fix:**
Add pause checks to flash loan operations by modifying the flash loan functions:

1. In `flash_loan.move`, add pause check at the start of the `loan()` function:
   - Call `storage::when_not_paused(storage)` before processing the loan
   - This requires adding a `storage: &Storage` parameter to the function signature

2. In `lending.move`, add pause checks in the base flash loan functions:
   - Modify `base_flash_loan()` to call `storage::when_not_paused(storage)` before calling `flash_loan::loan()`
   - Modify `base_flash_repay()` to call `storage::when_not_paused(storage)` before calling `flash_loan::repay()`

**Invariant Check:**
Add assertion that verifies no state modifications occur during pause:
```
assert!(!storage::pause(storage), error::paused())
```

**Test Cases:**
1. Test that flash loan initiation fails with error 1500 when protocol is paused
2. Test that flash loan repayment fails with error 1500 when protocol is paused
3. Add regression tests to `flash_loan_tests.move` with `#[expected_failure(abort_code = 1500)]` annotations

### Proof of Concept

**Initial State:**
- Protocol is operational with flash loans configured for SUI asset
- Liquidity exists in SUI pool (e.g., 10,000 SUI)
- Admin discovers a critical vulnerability and pauses the protocol

**Exploit Steps:**

Transaction 1 - Admin pauses protocol:
```
storage::set_pause(&owner_cap, &mut storage, true)
```
Result: `storage.paused == true`, all regular operations should be blocked

Transaction 2 - Attacker exploits via flash loan:
```
let (loan_balance, receipt) = lending::flash_loan_with_ctx(
    &flash_loan_config,
    &mut sui_pool,
    1000_000000000, // 1000 SUI
    ctx
)
// NO PAUSE CHECK - attacker receives funds despite pause
// Attacker performs malicious operations here
lending::flash_repay_with_ctx(
    &clock,
    &mut storage,
    &mut sui_pool,
    receipt,
    repay_balance,
    ctx
)
// State modifications occur despite pause
```

**Expected vs Actual Result:**
- Expected: Transaction 2 aborts with error 1500 (paused)
- Actual: Transaction 2 succeeds, attacker receives 1000 SUI and can perform operations during pause

**Success Condition:**
The exploit succeeds if the attacker can complete a flash loan while `storage.paused == true`, demonstrating complete bypass of the pause mechanism.

**Notes**

This vulnerability represents a critical gap in the protocol's security controls. The pause mechanism exists specifically for emergency situations where immediate halting of all operations is necessary. Flash loans bypassing this control means the protocol cannot be truly frozen when needed most, during active exploitation or critical vulnerabilities. The combination of fund access + state modification during pause makes this a high-severity security integrity violation that undermines the protocol's defensive capabilities.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/error.move (L5-5)
```text
    public fun paused(): u64 {1500}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L35-35)
```text
        paused: bool, // Whether the pool is paused
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L141-143)
```text
    public fun when_not_paused(storage: &Storage) {
        assert!(!pause(storage), error::paused())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L242-247)
```text
    public entry fun set_pause(_: &OwnerCap, storage: &mut Storage, val: bool) {
        version_verification(storage);

        storage.paused = val;
        emit(Paused {paused: val})
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L184-184)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L225-225)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L275-275)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L319-319)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L420-420)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L531-533)
```text
    fun base_flash_loan<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, user: address, amount: u64): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        flash_loan::loan<CoinType>(config, pool, user, amount)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L141-173)
```text
    public(friend) fun loan<CoinType>(config: &Config, _pool: &mut Pool<CoinType>, _user: address, _loan_amount: u64): (Balance<CoinType>, Receipt<CoinType>) {
        version_verification(config);
        let str_type = type_name::into_string(type_name::get<CoinType>());
        assert!(table::contains(&config.support_assets, *ascii::as_bytes(&str_type)), error::reserve_not_found());
        let asset_id = table::borrow(&config.support_assets, *ascii::as_bytes(&str_type));
        let cfg = table::borrow(&config.assets, *asset_id);

        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());

        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();

        let _balance = pool::withdraw_balance(_pool, _loan_amount, _user);
        
        let _receipt = Receipt<CoinType> {
            user: _user,
            asset: *asset_id,
            amount: _loan_amount,
            pool: pool_id,
            fee_to_supplier: to_supplier,
            fee_to_treasury: to_treasury,
        };

        emit(FlashLoan {
            sender: _user,
            asset: *asset_id,
            amount: _loan_amount,
        });

        (_balance, _receipt)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L175-209)
```text
    public(friend) fun repay<CoinType>(clock: &Clock, storage: &mut Storage, _pool: &mut Pool<CoinType>, _receipt: Receipt<CoinType>, _user: address, _repay_balance: Balance<CoinType>): Balance<CoinType> {
        let Receipt {user, asset, amount, pool, fee_to_supplier, fee_to_treasury} = _receipt;
        assert!(user == _user, error::invalid_user());
        assert!(pool == object::uid_to_address(pool::uid(_pool)), error::invalid_pool());

        // handler logic
        {
            logic::update_state_of_all(clock, storage);
            let asset_id = get_storage_asset_id_from_coin_type(storage, type_name::into_string(type_name::get<CoinType>()));

            let normal_amount = pool::normal_amount(_pool, fee_to_supplier);
            let (supply_index, _) = storage::get_index(storage, asset_id);
            let scaled_fee_to_supplier = ray_math::ray_div((normal_amount as u256), supply_index);

            logic::cumulate_to_supply_index(storage, asset_id, scaled_fee_to_supplier);
            logic::update_interest_rate(storage, asset_id);
        };

        let repay_amount = balance::value(&_repay_balance);
        assert!(repay_amount >= amount + fee_to_supplier + fee_to_treasury, error::invalid_amount());

        let repay = balance::split(&mut _repay_balance, amount + fee_to_supplier + fee_to_treasury);
        pool::deposit_balance(_pool, repay, _user);
        pool::deposit_treasury(_pool, fee_to_treasury);

        emit(FlashRepay {
            sender: _user,
            asset: asset,
            amount: amount,
            fee_to_supplier: fee_to_supplier,
            fee_to_treasury: fee_to_treasury,
        });

        _repay_balance
    }
```
