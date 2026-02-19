### Title
Stub MMT v3 Implementation Causes Permanent Vault Lock When MomentumPosition Assets Are Used in Operations

### Summary
The mmt_v3 dependency is configured to use a local stub implementation where all functions execute `abort 0`. When vault operations borrow MomentumPosition assets, operators must call `update_momentum_position_value()` to complete the operation, but this function invokes stub mmt_v3 functions that immediately abort. This permanently locks the vault in DURING_OPERATION_STATUS with no recovery mechanism, rendering all vault funds inaccessible.

### Finding Description

**Root Cause:**
The entire mmt_v3 module consists of stub implementations where every function executes `abort 0`: [1](#0-0) 

This includes all arithmetic functions (add, sub, mul, div, etc.) and the `zero()` function. The same pattern exists in all mmt_v3 modules including: [2](#0-1) [3](#0-2) 

**Configuration Issue:**
The Move.toml explicitly configures the project to use this stub implementation instead of the real MMT Finance implementation: [4](#0-3) 

**Critical Dependency in Momentum Adaptor:**
The momentum_adaptor imports and calls these stub functions: [5](#0-4) 

Specifically, `get_position_token_amounts()` calls: [6](#0-5) 

**Operation Flow Requirements:**
When an operation borrows a MomentumPosition, it tracks the asset type in `asset_types_borrowed`: [7](#0-6) 

Before completing the operation, `check_op_value_update_record()` verifies ALL borrowed assets were updated: [8](#0-7) 

The update happens when adaptors call `finish_update_asset_value()`, which records the asset as updated: [9](#0-8) 

**No Recovery Mechanism:**
Admin cannot rescue the vault because `set_enabled()` explicitly prevents status changes during operations: [10](#0-9) 

The only way to restore NORMAL status is through `end_op_value_update_with_bag()`: [11](#0-10) 

But this requires passing the value update check, which is impossible when mmt_v3 functions abort.

### Impact Explanation

**Operational Impact - Permanent Vault Lockup:**
- Vault becomes permanently stuck in VAULT_DURING_OPERATION_STATUS (value 1)
- All user deposits remain locked and inaccessible
- No new deposits or withdrawals possible (require NORMAL status)
- Funds are not stolen but become completely frozen

**Affected Parties:**
- All vault depositors lose access to their principal and accrued rewards
- Protocol operations halt entirely for affected vault
- No administrative override exists to restore functionality

**Severity Justification:**
This is CRITICAL because:
1. Complete denial of service with no recovery path
2. Affects 100% of funds in any vault using MomentumPosition assets
3. Triggered by normal operator actions (not attack)
4. No loss of funds but permanent inaccessibility is equivalent impact
5. Violates Critical Invariant #4 (operation start/end status toggles must work)

### Likelihood Explanation

**Reachable Entry Point:**
Public operator function `start_op_with_bag()` accepts MomentumPosition in defi_asset_types: [12](#0-11) 

**Feasible Preconditions:**
- Vault has MomentumPosition as a DeFi asset
- Operator includes it in an operation's defi_asset_ids list
- Both are normal operational actions, not attacks

**Execution Practicality:**
The exploit sequence follows the standard operation flow:
1. Call `start_op_with_bag()` with MomentumPosition
2. Call `end_op_with_bag()` to return assets
3. Attempt `update_momentum_position_value()` - ABORTS HERE
4. Cannot call `end_op_value_update_with_bag()` without step 3
5. Vault permanently stuck

**Probability Assessment:**
- HIGH if MomentumPositions are used in production
- CERTAIN if deployed with current Move.toml configuration
- The stub is actively configured (not accidentally left over)
- Comment suggests intentional use: "we need to remove some test functions with errors"

### Recommendation

**Immediate Fix - Replace Stub Implementation:**
1. Update Move.toml to use real MMT Finance implementation:
```toml
[dependencies.mmt_v3]
git    = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev    = "mainnet-v1.1.3"
subdir = "mmt_v3"
addr   = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

2. If using real implementation is impossible (due to mentioned "test functions with errors"), either:
   - Fix the upstream errors
   - Remove MomentumPosition support entirely
   - Implement graceful fallback instead of abort

**Emergency Recovery Function:**
Add admin-controlled emergency status reset:
```move
public fun emergency_reset_status<T>(
    _: &AdminCap,
    vault: &mut Vault<T>
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**Validation Tests:**
Add integration tests that:
- Verify all adaptor functions complete without aborting
- Test full operation lifecycle with each DeFi asset type
- Confirm mmt_v3 functions return valid results (not abort)

### Proof of Concept

**Required Initial State:**
- Vault deployed with stub mmt_v3 dependency (current configuration)
- Vault has MomentumPosition added as DeFi asset
- Operator has OperatorCap

**Transaction Steps:**
```
1. Operator calls start_op_with_bag<T, CoinType, ObligationType>(
     vault,
     operation,
     operator_cap,
     clock,
     defi_asset_ids: [MOMENTUM_POSITION_ID],
     defi_asset_types: [TypeName::get<MomentumPosition>()],
     principal_amount: 0,
     coin_type_asset_amount: 0
   )
   → Success: MomentumPosition borrowed, added to asset_types_borrowed

2. Operator calls end_op_with_bag<T, CoinType, ObligationType>(
     vault,
     operation,
     operator_cap,
     defi_assets,
     tx,
     principal_balance,
     coin_type_asset_balance
   )
   → Success: MomentumPosition returned, value_update_enabled = true

3. Operator calls update_momentum_position_value<T, CoinA, CoinB>(
     vault,
     config,
     clock,
     asset_type,
     momentum_pool
   )
   → ABORT: tick_math::get_sqrt_price_at_tick() executes abort 0
   → Transaction reverts

4. Operator attempts end_op_value_update_with_bag<T, ObligationType>(
     vault,
     operation,
     operator_cap,
     clock,
     tx_for_check
   )
   → ABORT: check_op_value_update_record() fails at line 1216
   → "ERR_USD_VALUE_NOT_UPDATED" because MomentumPosition not in asset_types_updated

5. Admin attempts set_vault_enabled(admin_cap, vault, true)
   → ABORT: Line 523 checks status != DURING_OPERATION
   → "ERR_VAULT_DURING_OPERATION"
```

**Expected vs Actual Result:**
- Expected: Operation completes, vault returns to NORMAL status
- Actual: Vault permanently stuck in DURING_OPERATION_STATUS, all funds locked

**Success Condition for Exploit:**
Vault.status == VAULT_DURING_OPERATION_STATUS (1) with no path to return to NORMAL (0)

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L15-17)
```text
    public fun zero(): I32 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-6)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L19-27)
```text
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
```

**File:** volo-vault/Move.toml (L79-86)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/mmt_v3"
rev = "main"
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L3-6)
```text
use mmt_v3::liquidity_math;
use mmt_v3::pool::Pool as MomentumPool;
use mmt_v3::position::Position as MomentumPosition;
use mmt_v3::tick_math;
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L78-89)
```text
    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();

    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L1189-1195)
```text
    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```
