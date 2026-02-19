# Audit Report

## Title
Missing Zero Price Validation in Vault Oracle Enables Share Ratio Manipulation and Fund Theft

## Summary
The vault oracle's price retrieval functions lack zero price validation, unlike the lending protocol's oracle. When receipt asset prices become zero due to Switchboard oracle failures, the vault's total USD value is artificially deflated, causing share ratio manipulation. Attackers can exploit this to mint inflated shares during deposits and extract excess funds, while legitimate withdrawals fail due to division by zero.

## Finding Description

The vulnerability stems from missing defensive validation in the vault oracle system that exists in comparable protocol code.

**Missing Validation in Vault Oracle:**

The `get_asset_price()` function only validates price staleness but does NOT check if the price is zero before returning it. [1](#0-0) 

**Contrast with Lending Protocol Oracle:**

The lending protocol's oracle includes explicit zero price validation, checking `token_price.value > 0` as part of its validity check. [2](#0-1) 

**Zero Price Propagation:**

When a receipt vault's principal asset price is zero, the receipt value calculation produces zero USD value through the multiplication operation. [3](#0-2) 

The `mul_with_oracle_price()` function mathematically returns zero when the price parameter is zero. [4](#0-3) 

**Share Ratio Deflation:**

The vault's total USD value aggregates all asset values, including undervalued receipts with zero-price principals. [5](#0-4) 

This deflated total USD value directly reduces the share ratio calculation. [6](#0-5) 

**Share Minting Exploitation:**

During deposit execution, users receive shares calculated by dividing their deposit value by the current share ratio. An artificially low share ratio results in inflated share allocation. [7](#0-6) 

**Withdrawal DoS:**

Zero prices also cause transaction failures in withdrawal operations. The amount calculation requires dividing by the oracle price, resulting in division by zero. [8](#0-7) [9](#0-8) 

**Supporting Evidence:**

The test infrastructure explicitly supports zero prices, demonstrating the system doesn't prevent this state. [10](#0-9) 

## Impact Explanation

**Direct Fund Theft:**
When a receipt asset (which can represent significant vault value) has a zero price, the total USD value calculation undervalues the vault. If receipts represent 50% of vault value and their price drops to zero, the total USD value is cut by ~50%, causing the share ratio to halve. An attacker depositing $100K receives ~$200K worth of shares. When prices normalize, the attacker withdraws using their inflated shares, extracting $100K more than deposited.

**Shareholder Dilution:**
Existing vault shareholders suffer proportional value loss as the attacker's inflated shares dilute the total shares pool.

**Denial of Service:**
Zero prices trigger division by zero errors in withdrawal calculations, preventing legitimate users from withdrawing their funds until prices are corrected.

**Protocol Integrity:**
The inconsistency between vault oracle (no validation) and lending protocol oracle (with validation) indicates this is a defensive programming gap that should be filled.

## Likelihood Explanation

**Precondition Feasibility:**

Zero price conditions can occur through:
1. Switchboard aggregator initialization or malfunction
2. Oracle configuration errors or network failures
3. Temporary downtime during maintenance windows

The system explicitly supports zero prices as shown in test code, and lacks production validation to prevent them.

**Attacker Requirements:**

The attacker needs only standard user access to:
- Monitor public on-chain oracle price feeds
- Execute deposit transactions when zero price detected
- Wait for oracle correction
- Execute withdrawal with inflated shares

No privileged access, admin compromise, or complex contract deployment required.

**Execution Practicality:**

All operations use normal protocol entry points via standard Move transactions. The attacker acts opportunistically when external conditions create the vulnerability window.

**Realistic Assessment:**

While requiring external oracle failure, the lack of defensive validation present in comparable protocol code (lending oracle) indicates this is a known risk vector that should be protected against. Blockchain oracle systems do experience failures, and the severe impact when combined with missing validation justifies the validity of this vulnerability.

## Recommendation

Add zero price validation to the vault oracle's `get_asset_price()` function, mirroring the protection in the lending protocol oracle:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    // Validate price is not stale
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    // ADD: Validate price is not zero
    assert!(price_info.price > 0, ERR_INVALID_PRICE);
    
    price_info.price
}
```

Additionally, add similar validation in `add_switchboard_aggregator()` and `update_price()` to prevent zero prices from being stored in the first place.

Define a new error constant:
```move
const ERR_INVALID_PRICE: u64 = 2_006;
```

## Proof of Concept

```move
#[test]
fun test_zero_price_share_manipulation() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with receipt asset
    setup_vault_with_receipt_asset(&mut scenario, &mut clock);
    
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<USDC>>();
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        
        // Record initial state
        let initial_total_value = vault.get_total_usd_value_without_update();
        let initial_share_ratio = vault.get_share_ratio_without_update();
        
        // Simulate oracle failure: Set receipt principal price to 0
        oracle_config.set_current_price(&clock, string::utf8(b"RECEIPT_PRINCIPAL"), 0);
        
        // Update receipt value with zero price
        receipt_adaptor::update_receipt_value(&mut vault, &receipt_vault, &oracle_config, &clock, asset_type);
        
        // Verify total USD value is deflated
        let deflated_total_value = vault.get_total_usd_value(&clock);
        assert!(deflated_total_value < initial_total_value, 0);
        
        // Verify share ratio is deflated
        let deflated_share_ratio = vault.get_share_ratio(&clock);
        assert!(deflated_share_ratio < initial_share_ratio, 1);
        
        // Attacker deposits and receives inflated shares
        scenario.next_tx(ATTACKER);
        let deposit_coin = coin::mint_for_testing<USDC>(100_000_000_000, scenario.ctx());
        vault.request_deposit(&clock, receipt_id, deposit_coin, expected_shares, scenario.ctx());
        
        // Execute deposit with deflated share ratio
        vault.execute_deposit(&clock, &oracle_config, request_id, max_shares);
        
        let attacker_receipt = vault.vault_receipt_info(receipt_id);
        let attacker_shares = attacker_receipt.shares();
        
        // Verify attacker received more shares than they should
        let fair_shares = calculate_fair_shares(100_000_000_000, initial_share_ratio);
        assert!(attacker_shares > fair_shares, 2);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

### Citations

**File:** volo-vault/sources/oracle.move (L126-138)
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
```

**File:** volo-vault/sources/oracle.move (L304-309)
```text
    let price_info = PriceInfo {
        aggregator: aggregator,
        decimals,
        price: 0,
        last_updated: clock.timestamp_ms(),
    };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L194-194)
```text
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-73)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
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

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```
