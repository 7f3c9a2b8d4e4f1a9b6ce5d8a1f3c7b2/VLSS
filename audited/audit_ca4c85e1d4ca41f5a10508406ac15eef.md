### Title
Uncontrolled Switchboard Aggregator Authority Enables Price Manipulation and Fund Theft

### Summary
The Volo vault allows admins to add Switchboard aggregators without validating that they control the aggregator's authority. Malicious or compromised aggregator authorities can modify critical configuration parameters (min_sample_size, max_staleness_seconds, max_variance) to enable price manipulation, leading to inflated share issuance during deposits or excessive principal withdrawal, directly draining vault funds.

### Finding Description

The vulnerability exists in the oracle integration flow where Switchboard aggregators are added to the vault's pricing system without authority verification.

**Root Cause:**

The `add_switchboard_aggregator` function accepts any Switchboard Aggregator reference without checking who controls its authority field: [1](#0-0) 

The function only validates that the asset_type doesn't already exist and reads the initial price, but performs no authority or configuration parameter validation.

**Attack Vector:**

Switchboard aggregators have a mutable authority field that controls configuration updates: [2](#0-1) 

Any party controlling the aggregator authority can call the public entry function to modify critical parameters: [3](#0-2) 

The validation only checks that the caller is the aggregator's authority, not that the Volo admin controls it: [4](#0-3) 

**Exploitation Path:**

Once malicious parameters are set (e.g., min_sample_size=1, max_variance=huge), the attacker manipulates oracle responses. During deposit execution, the manipulated price inflates the USD value calculation: [5](#0-4) 

The inflated USD value results in more shares being minted to the attacker than deserved. During withdrawal, a deflated price causes excessive principal to be returned: [6](#0-5) 

The price directly affects the amount calculation through the oracle price division: [7](#0-6) 

### Impact Explanation

**Direct Fund Theft:**
- Attacker deposits with 2x inflated price → receives 2x shares → later withdraws 2x principal amount
- OR attacker withdraws with 0.5x deflated price → receives 2x principal amount directly
- Maximum theft: entire `free_principal` balance available in the vault

**Affected Parties:**
- All vault depositors lose funds proportionally as their share value is diluted
- Protocol loses custody of principal assets
- Loss tolerance mechanism bypassed as the price manipulation occurs before USD value updates

**Severity:**
Critical - enables complete drainage of vault principal through price manipulation with no on-chain detection mechanism.

### Likelihood Explanation

**Reachable Entry Point:**
The `aggregator_set_configs_action::run` function is publicly callable: [8](#0-7) 

**Feasible Preconditions:**
1. Volo admin adds a Switchboard aggregator they don't control (operational mistake - realistic if using public/shared aggregators)
2. OR aggregator authority is transferred to malicious party post-deployment via: [9](#0-8) 

**Execution Practicality:**
Attack sequence requires no special privileges beyond controlling the aggregator authority (which is external to Volo's trust model). The attacker:
1. Calls `set_configs` to enable single-oracle control (min_sample_size=1)
2. Manipulates price via controlled oracle
3. Executes deposit or withdraw with manipulated price

**Economic Rationality:**
If price can be inflated 2x, attacker extracts 2x value minus gas costs - highly profitable for any vault with significant TVL.

### Recommendation

**Immediate Mitigation:**
Add authority validation to `add_switchboard_aggregator`:
```move
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
    ctx: &TxContext, // Add context
) {
    config.check_version();
    
    // NEW: Validate caller controls the aggregator authority
    assert!(aggregator.authority() == ctx.sender(), ERR_AUTHORITY_NOT_CONTROLLED);
    
    // NEW: Validate secure configuration parameters
    assert!(aggregator.min_sample_size() >= 3, ERR_INSUFFICIENT_SAMPLE_SIZE);
    assert!(aggregator.max_staleness_seconds() <= 300, ERR_EXCESSIVE_STALENESS); // 5 min max
    assert!(aggregator.max_variance() <= REASONABLE_VARIANCE_CAP, ERR_EXCESSIVE_VARIANCE);
    
    // ... rest of function
}
```

**Additional Protections:**
1. Add event monitoring for aggregator configuration changes
2. Implement admin function to remove/freeze suspicious aggregators
3. Add sanity checks on price changes (e.g., reject >10% price swings between updates)
4. Document requirement that admin must control aggregator authority
5. Consider time-delayed price updates with TWAP-style averaging

**Test Cases:**
1. Test that adding aggregator with different authority fails
2. Test that price manipulation beyond configured bounds reverts
3. Test that config changes outside acceptable ranges are rejected

### Proof of Concept

**Initial State:**
- Vault has 1,000,000 USDC principal, 1,000,000 shares (1:1 ratio)
- Attacker has 100,000 USDC
- Volo admin adds Switchboard aggregator for USDC without verifying authority
- Attacker controls the aggregator authority

**Attack Sequence:**

1. **Attacker modifies aggregator config:**
   - Calls `aggregator_set_configs_action::run(aggregator, feed_hash, 1, 86400, 999999999, 1, ctx)`
   - Sets min_sample_size=1 (single oracle control)
   - Sets max_variance=999999999 (accepts any variance)
   - Transaction succeeds due to authority check passing

2. **Attacker manipulates price:**
   - Controls single oracle to report USDC price as $2.00 instead of $1.00
   - Updates aggregator with inflated price

3. **Attacker deposits:**
   - Calls `request_deposit` with 100,000 USDC
   - Operator calls `execute_deposit`
   - USD value calculated: 100,000 * $2.00 = $200,000
   - Shares minted: $200,000 / 1.0 = 200,000 shares
   - **Expected: 100,000 shares | Actual: 200,000 shares**

4. **Attacker withdraws:**
   - Later (or immediately via another account), requests withdrawal of 200,000 shares
   - Operator executes with corrected $1.00 price
   - Principal returned: 200,000 * $1.00 = 200,000 USDC
   - **Net profit: 100,000 USDC stolen from vault**

**Success Condition:**
Attacker extracts more principal than deposited by exploiting unconstrained aggregator configuration control, directly violating the invariant that share calculations must reflect actual USD value.

### Citations

**File:** volo-vault/sources/oracle.move (L158-184)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);

    emit(SwitchboardAggregatorAdded {
        asset_type,
        aggregator: aggregator.id().to_address(),
    });
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L81-83)
```text
public fun has_authority(aggregator: &Aggregator, ctx: &mut TxContext): bool {
    aggregator.authority == ctx.sender()
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L32-48)
```text
public fun validate(
    aggregator: &Aggregator,
    feed_hash: vector<u8>,
    min_sample_size: u64,
    max_staleness_seconds: u64,
    max_variance: u64,
    min_responses: u32,
    ctx: &mut TxContext
) {
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);
    assert!(aggregator.has_authority(ctx), EInvalidAuthority);
    assert!(min_sample_size > 0, EInvalidMinSampleSize);
    assert!(max_variance > 0, EInvalidMaxVariance);
    assert!(feed_hash.length() == 32, EInvalidFeedHash);
    assert!(min_responses > 0, EInvalidMinResponses);
    assert!(max_staleness_seconds > 0, EInvalidMaxStalenessSeconds);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L77-103)
```text
public entry fun run(
    aggregator: &mut Aggregator,
    feed_hash: vector<u8>,
    min_sample_size: u64,
    max_staleness_seconds: u64,
    max_variance: u64,
    min_responses: u32,
    ctx: &mut TxContext
) {   
    validate(
        aggregator,
        feed_hash,
        min_sample_size,
        max_staleness_seconds,
        max_variance,
        min_responses,
        ctx
    );
    actuate(
        aggregator,
        feed_hash,
        min_sample_size,
        max_staleness_seconds,
        max_variance,
        min_responses
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L838-850)
```text
    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1013-1030)
```text
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/utils.move (L73-76)
```text
// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_authority_action.move (L34-41)
```text
public entry fun run(
    aggregator: &mut Aggregator,
    new_authority: address,
    ctx: &mut TxContext
) {   
    validate(aggregator, ctx);
    actuate(aggregator, new_authority);
}
```
