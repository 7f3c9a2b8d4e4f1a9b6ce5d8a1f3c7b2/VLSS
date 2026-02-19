### Title
Zero Price Oracle DoS Vulnerability in Vault Withdrawal Operations

### Summary
The vault's oracle system does not validate that prices are non-zero when updating price feeds. If the oracle (Switchboard) returns price=0 for the principal asset—which can occur during circuit breakers or data feed failures—all withdrawal operations will fail with a division-by-zero error, effectively locking user funds in the vault until the price is manually corrected.

### Finding Description

**Technical Context Clarification:**
The question references Pyth oracle in `adaptor_pyth.move`, but the vault actually uses **Switchboard** oracle. The Pyth adaptor is part of the Navi protocol's separate oracle system. However, the vulnerability principle applies identically: zero prices from any oracle source cause division-by-zero errors.

**Root Cause:**
The vault's oracle update mechanism lacks zero-price validation. When `update_price()` is called, it stores the price from Switchboard aggregators without checking if the price is greater than zero: [1](#0-0) 

The price is retrieved from Switchboard without validation: [2](#0-1) 

**Critical Division-by-Zero Path:**
When users execute withdrawals, the vault calculates the withdrawal amount by dividing USD value by the oracle price: [3](#0-2) 

This calls `div_with_oracle_price()` which performs the division: [4](#0-3) 

If `v2` (the oracle price) is 0, the expression `v1 * ORACLE_DECIMALS / v2` triggers a **division-by-zero panic** in Move, causing the transaction to abort.

**Why Existing Protections Fail:**
1. No validation in `update_price()` that `current_price > 0`
2. No validation in `get_asset_price()` or `get_normalized_asset_price()` 
3. No try-catch or fallback mechanism in withdrawal logic [5](#0-4) 

**Other Operations Analyzed:**
- **Share Ratio Calculation:** Protected by zero-check on `total_shares`, does not divide by price [6](#0-5) 

- **Navi Position Valuation:** Uses multiplication with price (safe), no division [7](#0-6) 

- **Navi Health Factor:** Uses separate Navi protocol oracle, not vault oracle

### Impact Explanation

**Direct Operational Impact:**
All withdrawal operations for the vault become permanently blocked when the principal asset's oracle price is zero. Users cannot:
- Execute pending withdrawal requests via `execute_withdraw()`
- Claim their principal from the vault
- Exit their positions

**Affected Parties:**
- All users with pending or future withdrawal requests
- The entire vault becomes non-functional for withdrawals
- Deposits may continue but users cannot exit, creating a "roach motel" scenario

**Severity Justification:**
- **High Impact:** Complete DoS of withdrawal functionality, funds effectively locked
- **No Admin Override:** No emergency withdrawal mechanism that bypasses price checks
- **Duration:** Persists until oracle price feed is restored or admin manually updates price
- **Scope:** Affects ALL users of the vault, not just specific positions

### Likelihood Explanation

**Realistic Trigger Conditions:**
1. **Oracle Circuit Breakers:** Oracles like Switchboard may return 0 prices during extreme volatility or circuit breaker events to prevent bad price data propagation
2. **Data Feed Failures:** Temporary oracle outages or validator set issues can result in 0 prices
3. **Market Halts:** During emergency market conditions, price feeds may halt and return 0
4. **No Attacker Required:** This is a natural system failure scenario, not requiring malicious action

**Feasibility Assessment:**
- **Entry Point:** Public `execute_withdraw()` function called by operators [8](#0-7) 

- **No Privilege Required:** Affects normal user withdrawal flow
- **Execution Certainty:** Division-by-zero in Move always causes transaction abort
- **Detection Probability:** Medium - operators may attempt withdrawals and encounter errors before realizing the root cause

**Historical Precedent:**
Similar oracle price=0 scenarios have occurred in production DeFi systems during:
- Luna/UST collapse (oracles returned 0 for depegged assets)
- FTX collapse (various oracle feeds failed)
- Network congestion events (validator outages)

### Recommendation

**Immediate Fix:**
Add price validation in the oracle update function:

```move
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();
    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);
    
    // ADD THIS CHECK
    assert!(current_price > 0, ERR_INVALID_PRICE);
    
    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);
    price_info.price = current_price;
    price_info.last_updated = now;
    emit(AssetPriceUpdated { asset_type, price: current_price, timestamp: now })
}
```

**Additional Safeguards:**
1. Add validation in `get_asset_price()` to assert stored price > 0
2. Add minimum price thresholds per asset type (similar to Navi protocol's `minimum_effective_price`)
3. Implement emergency withdrawal mechanism that uses last known good price or fallback oracle
4. Add circuit breaker detection that pauses withdrawals rather than allowing DoS

**Test Cases:**
1. Test oracle update with price=0 (should revert)
2. Test withdrawal when stored price=0 (should revert gracefully)
3. Test price recovery after zero price event
4. Test emergency withdrawal flow during oracle failures

### Proof of Concept

**Initial State:**
- Vault has users with deposited funds and valid withdrawal requests
- Oracle is functioning normally with non-zero prices

**Attack Sequence:**
1. **Oracle Event:** Switchboard aggregator returns price=0 due to circuit breaker/data feed failure
2. **Price Update:** Operator calls `update_price()` which stores price=0 without validation
3. **Withdrawal Attempt:** Operator calls `execute_withdraw()` for pending request
4. **Division-by-Zero:** `div_with_oracle_price(usd_value, 0)` executes `v1 * 10^18 / 0`
5. **Transaction Abort:** Move runtime panics with division-by-zero error

**Expected vs Actual:**
- **Expected:** Withdrawal should complete successfully OR revert with graceful error
- **Actual:** Transaction aborts with panic, no withdrawals can be processed

**Success Condition:**
DoS is successful when any withdrawal transaction aborts due to division-by-zero, proven by:
- Zero price stored in oracle config
- All `execute_withdraw()` calls fail with arithmetic error
- No alternative path exists to withdraw funds

### Notes

**Important Clarifications:**
1. The question mentions "adaptor_pyth.move" but the vault uses Switchboard oracle, not Pyth directly
2. The Navi protocol has a separate oracle system with Pyth integration, but the vault does not use the Navi oracle
3. When valuing Navi positions, the vault uses its own Switchboard oracle (see navi_adaptor.move line 63)
4. The vulnerability exists regardless of oracle provider—any zero price causes the same DoS

**Scope Boundaries:**
- Share ratio calculations are NOT vulnerable (protected by zero-check on total_shares)
- Navi health factor checks use separate oracle and are not directly affected
- Deposit operations may continue functioning (use multiplication, not division)

### Citations

**File:** volo-vault/sources/oracle.move (L126-154)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}

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

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

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

**File:** volo-vault/sources/volo_vault.move (L1304-1318)
```text
    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/operation.move (L449-467)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let withdraw_request = vault.withdraw_request(request_id);
    reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

    let (withdraw_balance, recipient) = vault.execute_withdraw(
```
