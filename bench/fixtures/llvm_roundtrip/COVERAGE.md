# LLVM round-trip coverage: committed fixtures and gap reproducers

Written by `bench/native_llvm_roundtrip_exercise.sh` from `iyi-ir coverage` over every fixture and gap reproducer. The gate fails when this file is stale; `COVERAGE_WRITE=1` rewrites it. The corpus inventory is written by `bench/native_llvm_matrix.sh`.

```
iyi-ir: bench/fixtures/llvm_roundtrip/gaps/*.ll: No such file or directory
```
