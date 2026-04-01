# VTIL-BinaryNinja
VTIL meets Binary Ninja and provides you with a solution to analyze VTIL code in a less painful manner.

## Installation
Install via the Plugin Manager in Binary Ninja, or clone this repository into your [plugin folder](https://docs.binary.ninja/guide/plugins.html#using-plugins).

## Python Requirements
For local development installs, use [requirements.txt](requirements.txt).

## Lifting Coverage
Implemented LLIL coverage includes all VTIL-Core instructions (49/49):
- Control flow: `js`, `jmp`, `vexit`, `vxcall`
- Data/memory: `mov`, `movsx`, `str`, `ldd`
- Arithmetic core: `neg`, `add`, `sub`, `mul`, `mulhi`, `imul`, `imulhi`, `div`, `idiv`, `rem`, `irem`
- Bitwise core: `popcnt`, `bsf`, `bsr`, `not`, `shl`, `shr`, `xor`, `or`, `and`, `rol`, `ror`
- Conditionals: `te`, `tne`, `tg`, `tge`, `tl`, `tle`, `tug`, `tuge`, `tul`, `tule`, `ifs`
- Special instructions currently map to no op IL: `nop`, `sfence`, `lfence`, `vemit`, `vpinr`, `vpinw`, `vpinrm`, `vpinwm`

Validation helper:
- Run `python tools/validate.py /path/to/VTIL-Core` to verify instruction table sync.

## Screenshots
![](images/example.png)

## Disclaimer
This is a **very early proof of concept**. Expect bugs.  

Known issues:
- Special instructions (`nop`, `sfence`, `lfence`, `vemit`, `vpinr`, `vpinw`, `vpinrm`, `vpinwm`) intentionally lower to no op IL
- Runtime semantics should still be validated on real world samples because this plugin remains a proof of concept.
