import json
import os

from decouple import config

MAX_REPO = 30
SOURCE_REPO = "Sui-Volo/volo-smart-contracts"
REPO_NAME = "volo-smart-contracts"
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
        """Convert run number to a cyclic index between 1 and max_index"""
        return (int(run_number) - 1) % max_index + 1


if run_number == "0":
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
        # Convert to cyclic index (1-100)
        run_index = get_cyclic_index(run_number, MAX_REPO)
        # Format the URL with leading zeros
        repo_number = f"{run_index:03d}"
        BASE_URL = f"https://deepwiki.com/grass-dev-pa/{REPO_NAME}-{repo_number}"

scope_files = [
        "liquid_staking/sources/stake_pool.move",
        "liquid_staking/sources/manage.move",
        "liquid_staking/sources/fee_config.move",
        "liquid_staking/sources/volo_v1/native_pool.move",
        "liquid_staking/sources/volo_v1/validator_set.move",
        "liquid_staking/sources/volo_v1/ownership.move",
        "liquid_staking/sources/volo_v1/unstake_ticket.move",
        "liquid_staking/sources/volo_v1/math.move",
        "liquid_staking/sources/cert.move",
        "liquid_staking/sources/validator_pool.move",
        "liquid_staking/sources/migration/migrate.move",
        "volo-vault/sources/utils.move",
        "volo-vault/sources/volo_vault.move",
        "volo-vault/sources/manage.move",
        "volo-vault/sources/operation.move",
        "volo-vault/sources/user_entry.move",
        "volo-vault/sources/vault_receipt_info.move",
        "volo-vault/sources/receipt.move",
        "volo-vault/sources/requests/withdraw_request.move",
        "volo-vault/sources/requests/deposit_request.move",
        "volo-vault/sources/adaptors/momentum.adaptor.move",
        "volo-vault/sources/adaptors/cetus_adaptor.move",
        "volo-vault/sources/adaptors/suilend_adaptor.move",
        "volo-vault/sources/adaptors/receipt_adaptor.move",
        "volo-vault/sources/adaptors/navi_adaptor.move",
        "volo-vault/sources/reward_manager.move",
        "volo-vault/sources/oracle.move",
        "volo-vault/health-limiter/sources/adaptors/navi_limiter.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_authority_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_delete_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_guardian_queue_id_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_package_id_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_oracle_queue_id_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_authority_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_configs_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_add_fee_coin_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/oracle_queue_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_remove_fee_coin_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/guardian_queue_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/on_demand.move",
        "volo-vault/local_dependencies/mmt_v3/sources/global_config.move",
        "volo-vault/local_dependencies/mmt_v3/sources/pool.move",
        "volo-vault/local_dependencies/mmt_v3/sources/tick.move",
        "volo-vault/local_dependencies/mmt_v3/sources/liquidity.move",
        "volo-vault/local_dependencies/mmt_v3/sources/i128.move",
        "volo-vault/local_dependencies/mmt_v3/sources/collect.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/utils.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/sqrt_price_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/constants.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/swap_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/comparator.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/bit_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/oracle.move",
        "volo-vault/local_dependencies/mmt_v3/sources/version.move",
        "volo-vault/local_dependencies/mmt_v3/sources/i64.move",
        "volo-vault/local_dependencies/mmt_v3/sources/i32.move",
        "volo-vault/local_dependencies/mmt_v3/sources/position.move",
        "volo-vault/local_dependencies/mmt_v3/sources/create_pool.move",
        "volo-vault/local_dependencies/mmt_v3/sources/trade.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/account.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/lending.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/logic.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/manage.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/validation.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/pool.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/storage.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/error.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/version.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/constants.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/dynamic_calculator.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/incentive.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/calculate.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/getter.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/incentive_v3.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_error.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_provider.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_dynamic_getter.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/strategy.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/config.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_version.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/adaptor_supra.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move",
        "volo-vault/local_dependencies/protocol/utils/sources/utils.move",
        "volo-vault/local_dependencies/protocol/math/sources/ray_math.move",
        "volo-vault/local_dependencies/protocol/math/sources/safe_math.move",
        "volo-vault/local_dependencies/suilend_d/sprungsui/sources/sprungsui.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/reserve_config.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/cell.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/suilend.move",

        "liquid_staking/sources/stake_pool.move",
        "liquid_staking/sources/manage.move",
        "liquid_staking/sources/fee_config.move",
        "liquid_staking/sources/volo_v1/native_pool.move",
        "liquid_staking/sources/volo_v1/validator_set.move",
        "liquid_staking/sources/volo_v1/ownership.move",
        "liquid_staking/sources/volo_v1/unstake_ticket.move",
        "liquid_staking/sources/volo_v1/math.move",
        "liquid_staking/sources/cert.move",
        "liquid_staking/sources/validator_pool.move",
        "liquid_staking/sources/migration/migrate.move",
        "volo-vault/sources/utils.move",
        "volo-vault/sources/volo_vault.move",
        "volo-vault/sources/manage.move",
        "volo-vault/sources/operation.move",
        "volo-vault/sources/user_entry.move",
        "volo-vault/sources/vault_receipt_info.move",
        "volo-vault/sources/receipt.move",
        "volo-vault/sources/requests/withdraw_request.move",
        "volo-vault/sources/requests/deposit_request.move",
        "volo-vault/sources/adaptors/momentum.adaptor.move",
        "volo-vault/sources/adaptors/cetus_adaptor.move",
        "volo-vault/sources/adaptors/suilend_adaptor.move",
        "volo-vault/sources/adaptors/receipt_adaptor.move",
        "volo-vault/sources/adaptors/navi_adaptor.move",
        "volo-vault/sources/reward_manager.move",
        "volo-vault/sources/oracle.move",
        "volo-vault/health-limiter/sources/adaptors/navi_limiter.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_authority_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_delete_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_guardian_queue_id_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_package_id_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_oracle_queue_id_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_authority_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_configs_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_add_fee_coin_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/oracle_queue_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_remove_fee_coin_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/guardian_queue_init_action.move",
        "volo-vault/local_dependencies/switchboard_sui/on_demand/sources/on_demand.move",
        "volo-vault/local_dependencies/mmt_v3/sources/global_config.move",
        "volo-vault/local_dependencies/mmt_v3/sources/pool.move",
        "volo-vault/local_dependencies/mmt_v3/sources/tick.move",
        "volo-vault/local_dependencies/mmt_v3/sources/liquidity.move",
        "volo-vault/local_dependencies/mmt_v3/sources/i128.move",
        "volo-vault/local_dependencies/mmt_v3/sources/collect.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/utils.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/sqrt_price_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/constants.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/swap_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/comparator.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/bit_math.move",
        "volo-vault/local_dependencies/mmt_v3/sources/utils/oracle.move",
        "volo-vault/local_dependencies/mmt_v3/sources/version.move",
        "volo-vault/local_dependencies/mmt_v3/sources/i64.move",
        "volo-vault/local_dependencies/mmt_v3/sources/i32.move",
        "volo-vault/local_dependencies/mmt_v3/sources/position.move",
        "volo-vault/local_dependencies/mmt_v3/sources/create_pool.move",
        "volo-vault/local_dependencies/mmt_v3/sources/trade.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/account.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/lending.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/logic.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/manage.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/validation.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/pool.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/storage.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/error.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/version.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/constants.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/dynamic_calculator.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move",
        "volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/incentive.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/calculate.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/getter.move",
        "volo-vault/local_dependencies/protocol/lending_ui/sources/incentive_v3.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_error.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_provider.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_dynamic_getter.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/strategy.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/config.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_version.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/adaptor_supra.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle.move",
        "volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move",
        "volo-vault/local_dependencies/protocol/utils/sources/utils.move",
        "volo-vault/local_dependencies/protocol/math/sources/ray_math.move",
        "volo-vault/local_dependencies/protocol/math/sources/safe_math.move",
        "volo-vault/local_dependencies/suilend_d/sprungsui/sources/sprungsui.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/reserve_config.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/cell.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move",
        "volo-vault/local_dependencies/suilend_d/suilend/sources/suilend.move",


]


def question_generator(target_file: str) -> str:
        """
        Generates targeted security audit questions for a specific Volo smart contract file.

        Args:
            target_file: The specific file path to focus question generation on.
                        (e.g., "volo-vault/sources/vault.move")

        Returns:
            A formatted prompt string for generating security questions.
        """
        prompt = f"""
# **Generate 150+ Targeted Security Audit Questions for Volo Protocol (Liquid Staking LST + Volo Vault on Sui)**

## **Context**

The target project is **Volo** on **Sui Move**, composed of:
- **Liquid Staking**: stake/unstake SUI for LST, fee configuration (bps caps), epoch rollover rewards, boosted balances, validator pool management, validator weights, pause flag, operator/admin caps, delegation to specific validators, migration path from volo_v1, request/extra_fields bag storage.
- **Volo Vault**: multi-asset vault with request buffers for deposits/withdrawals, share accounting, fee caps, locking windows, loss tolerance per epoch, operation status gating (normal/during operation/disabled), operator freeze map, reward manager + vault receipts alignment, oracle price config, adaptors to external protocols (Navi lending_core, Suilend, Cetus CLMM, Momentum), DeFi asset borrow/return tracking, value update checks, health-limiter hooks.
- **Health Limiter**: adaptor checking Navi health factor before operations using oracle prices, emitting verification events.
- **Local Dependencies**: Switchboard on-demand oracle actions, MMT v3 AMM math, protocol lending_core/ui/oracle/math/utils, Suilend modules, ensuring cross-module integrity.

## **Scope**

**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`

Note: Questions must be generated from **`{target_file}`** only. If you cannot generate 150 questions from this single file, generate as many high-quality questions as the file allows.  
If a file is more than a thousand lines, generate up to 300+ questions.  
Always generate as many strong questions as possible and do not return empty results.

## **Core Volo Components** (for reference only)

```python
core_components = [
    "liquid_staking/sources/stake_pool.move",
    "liquid_staking/sources/manage.move",
    "liquid_staking/sources/fee_config.move",
    "liquid_staking/sources/validator_pool.move",
    "liquid_staking/sources/volo_v1/*",
    "volo-vault/sources/*.move",
    "volo-vault/sources/adaptors/*.move",
    "volo-vault/sources/requests/*.move",
    "volo-vault/health-limiter/sources/adaptors/navi_limiter.move",
    "volo-vault/local_dependencies/**/sources/*.move",
]
```

## **Critical Invariant Areas**

- Auth/roles: admin vs operator caps, paused flag, operator freeze list, vault status gating (normal vs during operation vs disabled), migration restrictions, public share/transfer paths.
- Share/accounting: deposit/withdraw request buffers, share mint/burn math, receipt/vault ID matching, expected_shares/expected_amount slippage checks, fee caps vs defaults, boosted balances and accrued reward fees.
- Value & oracles: Switchboard on-demand aggregator correctness, price decimals (1e9/1e18) conversions, staleness tracking (`assets_value_updated`), tolerance reset per epoch, loss_tolerance enforcement.
- External adaptors: borrow/return of DeFi assets (Navi account caps, Cetus positions, Suilend obligations, Momentum positions, receipts) must be balanced; type/ID parsing via `vault_utils::parse_key`; no missing asset return; health factor checks via limiter.
- Operations lifecycle: pre/post op status toggling, total_usd_value snapshots, asset IDs/types alignment, op_value_update gating, locking windows for withdraw/cancel, request cancel timing.
- LST specifics: min stake amount, ratio math, supply zero checks, delegation path, validator weight updates, fee update bounds, pause enforcement.

## **In-Scope Vulnerability Categories**

- Authorization or pause/status bypass allowing restricted actions (mint, stake/unstake, op start/end, config update).
- Accounting/fee/ratio errors leading to share inflation/deflation, fee under/over-collection, loss tolerance bypass, or boosted reward mis-accounting.
- Oracle/value update issues causing incorrect USD valuations, stale price acceptance, overflow/underflow in decimal conversions.
- Asset custody/return failures in operations or adaptors (assets not returned, wrong type IDs, mismatched vault IDs).
- Locking/withdrawal window bypass, request buffer corruption, receipt mismatch enabling theft or denial of funds.
- External protocol misuse (health factor not enforced, missing approvals) enabling unsafe leverage or DoS.

## **Question Format Template**

Each question MUST follow this Python list format:

```python
questions = [
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific exploit scenario with preconditions, violated invariant, attacker action, and concrete impact? (High)",
]
```

## **Output Requirements**

Generate questions focusing EXCLUSIVELY on `{target_file}` that:

- Reference real functions/methods/logic blocks in `{target_file}`
- Include concrete exploit paths, not generic checks
- Tie each question to math logic, business logic, scenario validity, or invariant break
- Prioritize questions likely to result in **valid vulnerabilities**
- Avoid low-signal or non-exploitable questions
- Include severity `(Critical/High/Medium/Low)` in each question
- Use exact Python list format

## **Target Question Count**

- Small files: 80-150 questions when possible
- Medium files: 150+ questions
- Very large files (>1000 lines): 300+ questions
- If code size limits quantity, output as many quality questions as possible

Begin generating questions for `{target_file}` now.
"""
        return prompt


def validation_format(report: str) -> str:
        """
        Generates a comprehensive validation prompt for Volo (Sui) protocol security claims.

        Args:
            report: A security vulnerability report to validate

        Returns:
            A formatted validation prompt string for strict technical scrutiny
        """
        prompt = f"""
You are an **Elite Volo Protocol Security Judge** with deep expertise in Sui Move liquid staking, vault accounting, oracle/value updates, external adaptor integrations (Navi/Cetus/Suilend/Momentum), and health-factor enforcement.

Your ONLY task is **ruthless technical validation** of the claim below.

Note: Trusted roles include Volo admin/operator caps, package publishing authorities, and honest oracle authorities for Switchboard; assume these roles are honest unless the claim is about mis-scoped privileges.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **VOLO VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if **ANY** apply.

Note before a vulnerability can be considered valid it must have BOTH:
1) valid impact to protocol/users/funds/state integrity
2) valid likelihood / feasible trigger path

If it cannot be triggered in a realistic way, it is invalid (except pure logic invariant break that is directly reachable).

Return MUST be either:
- the original report (if valid)
- `#NoVulnerability` (if invalid)

Any vuln with no valid impact to the protocol is invalid.
Any scenario that needs attacker to deploy own contract and only self-harm is invalid.
Dark-forest user mistakes are not protocol vulnerabilities.

#### **A. Scope Violations**
- ❌ Affects files not in production source scope
- ❌ Targets tests, mocks, examples, scripts, docs, comments, style-only issues
- ❌ Claims on off-chain tooling instead of on-chain protocol logic
- ❌ Issues that only exist in test-only behavior

**In-Scope Volo smart contract files**
```python
scope_files = {scope_files}
```

#### **B. Threat Model Violations**
- ❌ Requires compromised protocol admin/operator/developer/private keys
- ❌ Assumes malicious Sui validators / consensus break / chain reorg control
- ❌ Depends on breaking cryptographic primitives or Sui runtime internals
- ❌ Relies on phishing, social engineering, user wallet compromise
- ❌ Pure network-layer attacks (DDoS/BGP/DNS/etc.) outside protocol logic

#### **C. Known/Non-Security Exclusions**
- ❌ Already known/fixed issues without current exploit path
- ❌ Gas/performance/style improvements without concrete security impact
- ❌ Logging/events/documentation-only suggestions
- ❌ Theoretical concerns without executable path and state impact
- ❌ Precision differences with negligible or non-exploitable effect

#### **D. Invalid Exploit Scenarios**
- ❌ Impossible inputs or invalid transaction semantics
- ❌ Needs calling non-reachable internal-only paths
- ❌ Requires unrealistic privileges not available to attacker
- ❌ Requires self-loss with no protocol invariant break
- ❌ Cannot produce measurable impact on balances, funds destination, ownership, or authorization

### **PHASE 2: VOLO DEEP CODE VALIDATION**

#### **Step 1: Trace Complete Execution Path**
For each claim, reconstruct:
1. Entry point (public/entry Move function)
2. Full call chain
3. Pre-state (vault status, pause flag, fee bounds, locking windows, loss tolerance/epoch, oracle update timestamps, receipt/vault match, health factor thresholds, adaptor assets present)
4. State transitions at each step
5. Existing guards/checks (cap/auth checks, paused/status checks, fee/amount bounds, share math, price decimals, tolerance enforcement, asset return checks, locking windows, health limiter)
6. Final post-state and violated invariant

If any path step is missing or non-reachable, reject as `#NoVulnerability`.

#### **Step 2: Evidence Requirements**
A valid report must provide:
- Exact file path(s) and relevant line references
- Concrete vulnerable logic and bypass explanation
- Triggerable transaction flow with realistic attacker actions
- Why protections do not stop it
- Quantified impact (fund loss, share dilution, receipt/vault desync, unauthorized admin/operator action)

Red flags -> invalid:
- “might be vulnerable” without exploit sequence
- no clear invariant broken
- no impact beyond revert/no-op
- assumptions that contradict Sui Move semantics

#### **Step 3: VOLO-Specific Validity Checks**
Validate claims against these invariant domains:

1. **Config & Auth**
- Admin/operator cap checks; pause flag; vault status (normal/during operation/disabled); operator freeze map; migration rules.

2. **Staking / Vault Requests**
- Stake/unstake min amounts; share mint/burn math; boosted balances; request buffers; locking windows; cancel timeouts; receipt/vault ID alignment; expected_shares/expected_amount honored.

3. **Operations & Asset Custody**
- pre_vault_check/post operation status; all borrowed DeFi assets returned; asset ID/type mapping; total_usd_value/tolerance checks; op_value_update gating; loss_tolerance enforcement.

4. **Oracle & Valuation**
- Switchboard on-demand price integrity; decimal conversions (1e9/1e18); staleness via `assets_value_updated`; USD value aggregation; overflow/underflow boundaries.

5. **External Integrations**
- Health limiter enforced before risky ops; adaptors correctly handle account caps/positions/obligations; no unauthorized transfer or leakage.

### **PHASE 3: IMPACT + LIKELIHOOD JUDGMENT**

A vulnerability is valid ONLY if BOTH are true:

1. **Impact is valid**
- Direct or indirect fund loss/misdirection (vault principal, LST fees, oracle collateral)
- Unauthorized ownership/receipt/vault record corruption or asset theft
- Pricing/accounting corruption (share inflation/deflation, fee bypass, loss tolerance bypass)
- Unauthorized config/auth/status change (pause/disable, operator freeze, caps)
- High-confidence protocol DoS via valid calls (vault stuck during operation, request buffer lock, oracle dependence)

2. **Likelihood is valid**
- Real attacker can execute via public interfaces
- No privileged assumptions beyond noted caps/roles
- Reasonable preconditions
- Reproducible path under normal chain rules

If either impact or likelihood fails -> `#NoVulnerability`.

### **DECISION OUTPUT (STRICT)**
           
---            
            
**AUDIT REPORT FORMAT** (if vulnerability found):            
            
Audit Report            
            
## Title 
The Title Of the Report 

## Summary
A short summary of the issue, keep it brief.

## Finding Description
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.

Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.

## Impact Explanation
Elaborate on why you've chosen a particular impact assessment.

## Likelihood Explanation
Explain how likely this is to occur and why.


## Recommendation
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.


## Proof of Concept
Note very important the poc must have a valid test that runs just one function that proove the vuln 
  **Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
**Now perform STRICT validation of the claim above.**    
    
**Output ONLY:**    
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format    
- `#NoVulnerability found for this question.` (if **any** check fails) very important    
- Note if u cant validate the claim or dont understand just send #NoVulnerability    
- Only show full report when u know this is actually and truly a  valid vulnerability """
        return prompt


def audit_format(security_question: str) -> str:
        """
        Generate a comprehensive security audit prompt for the Volo protocol on Sui.

        Args:
            security_question: The specific security concern to investigate

        Returns:
            A detailed audit prompt with strict validation requirements
        """

        prompt = f"""# VOLO PROTOCOL SECURITY AUDIT PROMPT

## Security Question to Investigate:
{security_question}

## Codebase Context

### Core Components
You are auditing **Volo**, a Sui Move suite including liquid staking (LST) and a multi-asset vault with external protocol adaptors:

**Liquid Staking (`liquid_staking/sources/*`)**
- Stake/unstake SUI for LST, fee configuration with bps caps, boosted balances, epoch rollover rewards, validator pool weights, pause flag, admin/operator caps, delegation, migration from volo_v1.

**Volo Vault (`volo-vault/sources/*`)**
- Vault object with share accounting, request buffers for deposits/withdrawals, fee caps, locking windows, loss tolerance per epoch, operation status gating, operator freeze map, reward manager + receipt alignment, oracle config, USD valuation tables, operation start/end.

**Adaptors & Health Limiter**
- Integrations for Cetus CLMM, Navi lending_core, Suilend, Momentum positions, receipt adaptor; health limiter enforcing Navi health factor; asset borrow/return via parse_key IDs.

**Local Dependencies**
- Switchboard on-demand oracle actions; MMT v3 math/AMM; protocol lending_core/ui/oracle/math/utils; suilend_d modules.

## CRITICAL INVARIANTS (Must Hold at All Times)

1. **Authorization & Enablement**
- Admin/operator caps enforced; pause and vault status gates (normal/during operation/disabled); operator freeze respected; migration/publish integrity.

2. **Staking & Vault Requests**
- Min stake amounts, ratio math, fee caps; request buffers; locking windows; cancel timeouts; receipt/vault ID alignment; expected_shares/expected_amount checks.

3. **Pricing & Funds**
- Fee caps enforced; share mint/burn consistency; loss_tolerance per epoch; total_usd_value correctness.

4. **Asset Custody & Operations**
- All borrowed DeFi assets returned; asset IDs/types match; operation start/end status toggles; op_value_update gating; tolerance reset.

5. **Oracle & Valuation**
- Switchboard price handling, decimal conversions (1e9/1e18), staleness checks (`assets_value_updated`), overflow/underflow bounds.

6. **External Integrations**
- Health-factor enforcement for Navi; adaptors for Cetus/Suilend/Momentum handle assets safely; no leakage of account caps/positions.

## ATTACK SURFACES

### 1. Staking & Requests
- `stake_entry`, `delegate_stake_entry`, `unstake` flows, epoch rollover, fee updates, pause toggles, validator weight updates.

### 2. Migration & Upgrades
- Migration from volo_v1, publish upgrades, admin/operator cap distribution.

### 3. Receipt & Vault Integrity
- Receipt issuance/matching, vault_id/receipt_id alignment, request buffers, reward manager interactions.

### 4. Config & Pricing
- Fee caps, tolerance, locking windows, status toggles, oracle config/value updates.

### 5. Operations & Adaptors
- Operation start/end with adaptors (Cetus/Navi/Suilend/Momentum/Receipt), asset borrow/return, health limiter checks.

## VULNERABILITY VALIDATION REQUIREMENTS

A finding is ONLY valid if it passes ALL checks:

### Impact Assessment (Must be Concrete)
- [ ] **Direct Fund Impact**: vault/LST fund theft, fee under/over-collection, misrouting of balances or rewards
- [ ] **Custody/Receipt Integrity**: unauthorized receipt/vault record corruption, wrong recipient, missing asset return
- [ ] **Security Integrity Impact**: authorization/pause/status/health-limiter bypass, loss_tolerance or value-update bypass
- [ ] **Operational Impact**: meaningful DoS via valid user actions (vault stuck in operation, requests locked, oracle dependence)

Impact must be real and measurable, not theoretical.

### Likelihood Assessment (Must be Practical)
- [ ] **Reachable Entry Point**: exploit starts from real public/entry callable flow
- [ ] **Feasible Preconditions**: attacker capabilities realistic for untrusted users
- [ ] **Execution Practicality**: steps executable under Move semantics and protocol checks
- [ ] **Economic Rationality**: attack cost and constraints do not make exploit non-viable

Likelihood must be realistic.

### Validation Checklist
Before reporting a vulnerability, verify:

1. [ ] Exact file/function/line references
2. [ ] Root cause clearly identified
3. [ ] End-to-end exploitation path
4. [ ] Existing checks shown insufficient
5. [ ] Realistic attack parameters and sequence
6. [ ] Concrete impact quantification
7. [ ] No reliance on trusted role compromise
8. [ ] No contradiction with Sui Move execution model

## AUDIT REPORT FORMAT

If a valid vulnerability is found (passes all checks), output this EXACT structure:

### Title
[Concise vulnerability title]

### Summary
[2-3 sentence summary of issue and consequence]

### Finding Description
[Technical details including:
- exact code location(s)
- root cause
- why protections fail
- relevant execution path]

### Impact Explanation
[Concrete impact:
- what harm occurs
- quantified value/protocol damage
- who is affected
- severity justification]

### Likelihood Explanation
[Realistic exploitability:
- attacker capabilities
- attack complexity
- feasibility conditions
- detection/operational constraints
- probability reasoning]

### Recommendation
[Actionable fix:
- exact code-level mitigation
- invariant checks to add
- test cases to prevent regression]

### Proof of Concept
[Reproducible exploit sequence:
- required initial state
- transaction steps
- expected vs actual result
- clear success condition]

## STRICT OUTPUT REQUIREMENT

After investigation:

IF a vulnerability passes ALL validation gates with clear evidence:
-> Output the complete audit report in the format above

IF no valid vulnerability exists:
-> Output exactly: "#NoVulnerability found for this question."

Do not output anything else.

## Investigation Guidelines

1. Start from entry functions reachable by untrusted users
2. Trace full state transitions and all side effects
3. Check math/rounding/decimal boundaries and extreme values
4. Check cross-module flows (stake_pool/manage/fee_config <-> validator_pool/volo_v1 <-> vault/request buffers <-> adaptors/oracle/health-limiter)
5. Validate enablement/auth/fee/locking/value-update checks end-to-end
6. Reject speculative findings lacking concrete exploit path

Remember: only report vulnerabilities with both valid impact and valid likelihood.

Begin investigation of: {security_question}
"""

        return prompt


def scan_format(report: str) -> str:
        """
        Generate a cross-protocol analog vulnerability scanning prompt for the Volo protocol.

        Args:
            report: A vulnerability report from another protocol/project

        Returns:
            A strict scan prompt string that looks for equivalent vulnerability classes in Volo
        """

        prompt = f"""# VOLO PROTOCOL CROSS-PROTOCOL ANALOG SCAN PROMPT

## External Report To Map Into Volo
{report}

## Objective
You are a senior protocol security researcher. Your job is to analyze the external report above and determine whether the **same vulnerability class** (not necessarily exact code pattern) can occur anywhere in Volo smart contracts.

You must deeply scan Volo logic across modules, execution paths, state transitions, and invariants.

## Volo Modules To Scan

- `liquid_staking` (stake_pool, manage, fee_config, validator_pool, volo_v1/*, migration)
- `volo-vault` (vault, manage, operation, user_entry, reward_manager, oracle, utils, vault_receipt_info, requests/*)
- `volo-vault/sources/adaptors` (cetus, suilend, navi, momentum, receipt)
- `volo-vault/health-limiter` (navi_limiter adaptor)
- `volo-vault/local_dependencies` (switchboard_sui/on_demand, mmt_v3, protocol lending_core/ui/oracle/math/utils, suilend_d)

## Core Scan Method

1. **Classify the external vuln type**
- authorization/pause/status/operator-cap bypass
- staking/vault request/accounting/locking/loss_tolerance violation
- pricing/fee/valuation underpayment or misdirection
- oracle or decimal conversion errors
- asset custody/return failure in operations/adaptors
- health-factor or risk-limit bypass
- denial of service through valid calls (vault stuck, request buffers locked, operation status never reset)

2. **Map to Volo analog surfaces**
- Identify equivalent trust boundaries and data-flow points in Volo modules
- Search for functionally similar logic, even if naming differs
- Check cross-module interactions, not just one file

3. **Trace full exploitability path**
- Real entry point (public/entry callable path)
- Preconditions attacker can realistically satisfy
- Step-by-step transition chain
- Why current checks fail
- Final broken invariant

4. **Validate impact + likelihood strictly**
- Must have concrete protocol impact
- Must have realistic trigger path
- No speculative or theoretical-only claims

## Critical Invariants To Test During Scan

- No unauthorized config/pause/status changes; operator freeze respected
- Min stake amounts, fee caps, share math, request buffer integrity, locking windows
- All borrowed DeFi assets returned; asset IDs/types consistent; operation status reset
- Oracle price correctness, decimal conversions (1e9/1e18), staleness control
- Health limiter enforced for risky borrowing; loss_tolerance not bypassed

## Disqualification Rules (Immediate #NoVulnerability)

Reject if ANY apply:

- Not reproducible through Volo public/entry flows
- Requires compromised admin/operator/developer/validator keys
- Depends on impossible Sui execution assumptions
- Only causes self-harm or non-protocol impact
- Has no concrete impact on funds, ownership/receipts, authorization, or critical availability
- Impact exists but no realistic likelihood
- Likelihood exists but no valid impact

## Required Decision Standard

A vulnerability is valid ONLY if BOTH are true:

1. **Valid Impact**
- Fund theft/drain or fee/valuation misrouting
- Unauthorized receipt/vault corruption or asset misappropriation
- Pricing/accounting/fee/loss_tolerance corruption
- Unauthorized config/pause/status/operator change
- High-confidence protocol DoS via valid calls

2. **Valid Likelihood**
- Reachable by untrusted actor
- Feasible preconditions
- Executable sequence under protocol rules
- Not blocked by existing checks

If either fails, it is invalid.

## Output Format (Strict)

If valid analog vulnerability is found in Volo, output full report in this exact structure:

### Title
[Concise vulnerability title]

### Summary
[2-3 sentence summary of mapped vulnerability and impact]

### Finding Description
[Detailed technical mapping from external report type to Volo:
- exact Volo file/function/line references
- root cause in Volo
- exploit path and why protections fail]

### Impact Explanation
[Concrete Volo impact and severity justification]

### Likelihood Explanation
[Realistic exploit feasibility in Volo context]

### Recommendation
[Specific code-level mitigation for Volo]

### Proof of Concept
[Reproducible Volo exploit steps with realistic state/inputs]

If no valid analog vulnerability is found, output exactly:
`#NoVulnerability found for this question.`

Do not output anything else.

## Additional Guidance

- Use the external report as a vulnerability-class hint, not as proof.
- Confirm with Volo-specific code logic only.
- Prefer false-negative over false-positive.
- A claim without executable exploit chain is invalid.

Begin deep analog scan now.
"""

        return prompt

