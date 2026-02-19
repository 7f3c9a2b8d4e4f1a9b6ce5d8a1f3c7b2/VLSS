### Title
Emergency Pause Front-Running Due to Shared Object Consensus Ordering

### Summary
The protocol's pause mechanism cannot guarantee immediate protection against exploitation because the `set_paused()` transaction and attacker's exploit transactions are subject to the same consensus ordering on the shared `StakePool` object. An attacker can front-run the admin's pause transaction, allowing funds to be drained before the pause takes effect during a critical vulnerability response.

### Finding Description

The pause mechanism is implemented in `manage.move` where `set_paused()` simply sets a boolean flag [1](#0-0) , and user operations check this flag via `check_not_paused()` [2](#0-1) .

The admin-facing `set_paused()` function requires an `AdminCap` but provides no transaction priority [3](#0-2) .

User operations like `stake()` and `unstake()` check the pause state before executing [4](#0-3) [5](#0-4) .

**Root Cause**: The `StakePool` is a shared object [6](#0-5) , meaning all transactions accessing it must go through Sui's consensus mechanism for ordering. There is no prioritization for admin transactions over user transactions in the consensus layer.

**Why Protections Fail**: The pause check is only evaluated at transaction execution time. If an attacker's exploit transaction is ordered before the admin's pause transaction in consensus, it will execute with `paused = false` and pass all checks.

**Execution Path**:
1. Admin discovers critical vulnerability and calls `set_paused(pool, admin_cap, true)`
2. Attacker (monitoring or independently discovered) submits multiple exploit transactions via `stake_entry()` or `unstake_entry()`
3. Consensus orders both admin and attacker transactions
4. If attacker transactions ordered first, they execute with `paused = false`
5. Pause takes effect only after attacker's transactions complete

### Impact Explanation

**Direct Fund Impact**: If a critical vulnerability exists in the protocol (e.g., ratio manipulation in `sui_amount_to_lst_amount()`, fee calculation bugs, or validator pool exploits), an attacker can drain significant funds before the admin's pause transaction takes effect.

**Quantified Damage**: The entire `total_sui_supply()` [7](#0-6)  of the pool could be at risk depending on the nature of the underlying vulnerability. With no transaction prioritization, multiple attacker transactions could execute in sequence before the pause.

**Affected Parties**: All LST holders and the protocol's total value locked. The pause mechanism, which should serve as an emergency brake, becomes ineffective during the critical window when it's most needed.

**Severity Justification**: HIGH - The pause mechanism is the last line of defense when critical vulnerabilities are discovered. Its inability to guarantee immediate effect creates a race condition where attackers have a guaranteed opportunity to exploit before protection activates.

### Likelihood Explanation

**Attacker Capabilities**: Standard untrusted user with ability to submit transactions. No special privileges required. Attacker only needs to:
- Discover or monitor for the same vulnerability as the admin
- Submit exploit transactions quickly upon discovery or when observing pause transaction

**Attack Complexity**: LOW
- Entry points are public and accessible: `stake_entry()` [8](#0-7) , `unstake_entry()` [9](#0-8) 
- No complex state manipulation required
- Simply requires submitting transactions around the same time as admin's pause

**Feasibility Conditions**: 
- A critical vulnerability exists in the protocol (prerequisite for pause scenario)
- Admin attempts to use pause as emergency response
- Attacker has discovered the vulnerability or monitors admin activity

**Detection/Operational Constraints**: In Sui, transaction ordering on shared objects is determined by consensus. There is no mechanism to prioritize admin transactions or provide atomic emergency stops. This is inherent to the blockchain's design, not a operational constraint that can be mitigated operationally.

**Probability**: HIGH - In any real-world critical vulnerability scenario where admin attempts emergency pause, this race condition will exist. The attacker doesn't need to win every time; even winning once allows significant fund drainage.

### Recommendation

**Code-Level Mitigation**:

1. **Implement Two-Phase Pause with Grace Period**:
   - Add a `pause_scheduled_epoch` field to track when pause will activate
   - Modify `check_not_paused()` to also check if current epoch >= scheduled pause epoch
   - Add `schedule_pause()` that sets activation for current_epoch + 1
   - This prevents new operations from starting even before pause flag flips

2. **Add Per-Transaction Rate Limiting**:
   ```
   // In StakePool struct
   last_large_tx_epoch: u64,
   large_tx_cooldown: u64,
   
   // In stake/unstake
   if (amount > LARGE_TX_THRESHOLD) {
       assert!(ctx.epoch() >= self.last_large_tx_epoch + self.large_tx_cooldown, E_COOLDOWN);
       self.last_large_tx_epoch = ctx.epoch();
   }
   ```
   This limits damage in the time window before pause takes effect.

3. **Add Emergency Withdrawal Limits**:
   - Implement per-epoch withdrawal caps that can be lowered (but not raised) without delay
   - When vulnerability detected, admin first lowers caps to minimal amounts, then pauses
   - Even if attacker front-runs pause, withdrawal caps limit damage

4. **Implement Circuit Breaker Pattern**:
   - Add automatic pause triggers based on abnormal activity (e.g., large ratio changes, unusual volume)
   - Check these conditions in `refresh()` which is called by all operations
   - Provides defense-in-depth beyond admin-initiated pause

**Invariant Checks to Add**:
- Verify epoch-based controls cannot be bypassed
- Ensure withdrawal limits are enforced before pause checks
- Test that circuit breakers trigger before operations complete

**Test Cases**:
- Simulate admin pause + attacker transactions in same block, verify damage is limited
- Test grace period prevents exploitation during pause scheduling
- Verify rate limits and circuit breakers function independently of pause state

### Proof of Concept

**Required Initial State**:
- StakePool deployed and operational with significant TVL (e.g., 1M SUI)
- Critical vulnerability exists in protocol (e.g., ratio manipulation allowing LST over-minting)
- Admin has discovered vulnerability and has AdminCap
- Attacker has also discovered vulnerability or is monitoring

**Transaction Sequence**:

1. **T0 - Admin Response**: Admin calls `set_paused(pool, admin_cap, true)` → Transaction enters mempool

2. **T0+Δ - Attacker Exploit**: Attacker submits multiple exploit transactions:
   - `stake_entry(pool, metadata, system, exploit_sui_1, ctx)`
   - `stake_entry(pool, metadata, system, exploit_sui_2, ctx)`
   - `unstake_entry(pool, metadata, system, manipulated_lst, ctx)`

3. **Consensus Ordering**: Sui consensus orders transactions on shared `StakePool` object
   - **No guarantee admin transaction ordered first**
   - Possible ordering: [attacker_tx1, attacker_tx2, admin_pause, attacker_tx3]

4. **Execution**:
   - Attacker's transactions execute with `paused = false`, pass `check_not_paused()`
   - Vulnerability exploited, funds drained
   - Admin's pause takes effect only after attacker's pre-ordered transactions complete

**Expected vs Actual Result**:
- **Expected**: Pause immediately stops all operations, preventing exploitation
- **Actual**: Attacker's transactions ordered before pause execute successfully, draining funds

**Success Condition**: Attacker successfully extracts value from the vulnerability before pause takes effect, demonstrating that the pause mechanism cannot guarantee timely protection during emergency response.

### Citations

**File:** liquid_staking/sources/manage.move (L25-27)
```text
    public fun check_not_paused(self: &Manage) {
        assert!(!self.paused, EIncompatiblePaused)
    }
```

**File:** liquid_staking/sources/manage.move (L34-36)
```text
    public(package) fun set_paused(self: &mut Manage, paused: bool) {
        self.paused = paused;
    }
```

**File:** liquid_staking/sources/stake_pool.move (L141-141)
```text
        transfer::public_share_object(stake_pool);
```

**File:** liquid_staking/sources/stake_pool.move (L176-186)
```text
    public entry fun stake_entry(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let cert = self.stake(metadata, system_state, sui, ctx);
        transfer::public_transfer(cert, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L226-227)
```text
        self.manage.check_version();
        self.manage.check_not_paused();
```

**File:** liquid_staking/sources/stake_pool.move (L268-278)
```text
    public entry fun unstake_entry(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        cert: Coin<CERT>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let sui = self.unstake(metadata, system_state, cert, ctx);
        transfer::public_transfer(sui, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L287-288)
```text
        self.manage.check_version();
        self.manage.check_not_paused();
```

**File:** liquid_staking/sources/stake_pool.move (L336-340)
```text
    public fun set_paused(self: &mut StakePool, _: &AdminCap, paused: bool) {
        self.manage.check_version();
        self.manage.set_paused(paused);
        emit(SetPausedEvent {paused});
    }
```

**File:** liquid_staking/sources/stake_pool.move (L559-561)
```text
    public fun total_sui_supply(self: &StakePool): u64 {
        self.validator_pool.total_sui_supply() - self.accrued_reward_fees
    }
```
