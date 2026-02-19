# Investigation Result

I cannot perform this security audit as requested. Here's why:

## Implementation Not Available in Repository

The `wrapping_sub()` function in the i64.move file is only a stub implementation that aborts: [1](#0-0) 

## External Dependency with Interface-Only Code

The MMT v3 module is included as a local dependency with interface definitions only. According to the documentation, the actual implementation is resolved at runtime via package address resolution on the Sui blockchain: [2](#0-1) 

The actual deployed implementations are at on-chain addresses: [3](#0-2) 

## Limitation

To audit whether `wrapping_sub()` has edge cases when wrapping from MIN_AS_U64 to MAX_AS_U64, I would need access to the actual implementation code. Since the repository only contains stub functions for compilation purposes, and the real implementation exists as compiled bytecode on-chain, **this audit cannot be performed using source code analysis tools**.

This investigation would require:
- Access to the deployed bytecode or original MMT v3 implementation repository
- Decompilation tools or the actual source code from the MMT finance team
- On-chain bytecode inspection capabilities

**This is beyond my current capabilities**, which are limited to analyzing source code present in the provided repositories.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/i64.move (L39-41)
```text
    public fun wrapping_sub(num1: I64, num2: I64): I64 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L6-11)
```markdown
| Tag of Repo    | Network              | address                                                            | 
|----------------|----------------------|--------------------------------------------------------------------|
| mainnet-v1.1.3 | mainnet package id   | 0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860 |  
| mainnet-v1.1.3 | mainnet published at | 0xc84b1ef2ac2ba5c3018e2b8c956ba5d0391e0e46d1daa1926d5a99a6a42526b4 |  
| testnet-v1.0.1 | testnet package id   | 0xd7c99e1546b1fc87a6489afdc08bcece4ae1340cbd8efd2ab152ad71dea0f0f2 | 
| testnet-v1.0.1 | testnet published at | 0xd7c99e1546b1fc87a6489afdc08bcece4ae1340cbd8efd2ab152ad71dea0f0f2 | 
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L30-31)
```markdown
The MMT V3 interface provides function definitions only and is not a complete implementation. As a result, the Sui client may flag version inconsistencies when verifying the code. However, this does not impact the contract's functionality.

```
