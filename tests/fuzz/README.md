# fuzz 语料与 harness 说明

## harness 一览（`LLVMFuzzerTestOneInput`）

| 可执行文件 | 覆盖 | 固定 schema |
| --- | --- | --- |
| `fuzz_decode_ber` | `asn1_decode_buffer`，`encoding=BER` | 无 |
| `fuzz_decode_der` | `asn1_decode_buffer`，`encoding=DER`（NON_CANONICAL 分支） | 无 |
| `fuzz_reader` | `asn1_decode_reader` + `asn1_decode_reader_with_schema` | 最小手工表 |
| `fuzz_schema_decode` | `asn1_decode_buffer_with_schema` | PKIX 表 + 最小手工表 |
| `fuzz_roundtrip` | DER decode → encode → 再 decode，逐字节往返 | 无 |
| `fuzz_schema_load` | `asn1_schema_load`（任意字节作表，最大攻击面） | — |
| `fuzz_asn1c` | asn1c 词法/语法/语义/描述表生成 | — |

判据：只有崩溃 / 泄漏（LSan）/ 超时 / ASan@UBSan 报错算失败；返回错误码是正常行为。

## 构建（Linux + Clang）

```bash
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
  -DASN1_BUILD_STATIC=ON -DASN1_BUILD_SHARED=OFF \
  -DASN1_BUILD_TESTS=OFF -DASN1_BUILD_TOOLS=ON -DASN1_BUILD_FUZZ=ON
cmake --build build-fuzz
```

## 运行

```bash
# 短预算：每个 60 秒，从头跑（含语料种子）
./build-fuzz/tests/fuzz/fuzz_decode_der corpus/decode_der -max_total_time=60 -print_final_stats

# 长跑：15 分钟
ASAN_OPTIONS=detect_leaks=1 ./build-fuzz/tests/fuzz/fuzz_decode_der corpus/decode_der \
  -max_total_time=900 -print_final_stats
```

CI 用同样参数跑短预算，并记录 `-print_final_stats` 的迭代数。

## 语料说明与扩展

- 语料在 `corpus/<harness>/`，按 harness 分开、检入仓库，供 CI 复用。
- 由 `scripts/gen_fuzz_corpus.py` 确定性生成：真实 DER 样本
  （`tests/data/*.der`，含 CMS ContentInfo/SignedData）+ 合成二进制样本 +
  PKIX / PKCS / CMS 表字节（`schema_load`）+ `.asn1` 文本样本（`fuzz_asn1c`）。
- 合成样本覆盖：未知扩展字段、ANY 三形态、EXPLICIT ANY、不定长（单层/嵌套）、
  截断、超长长度字段、多字节 tag、SET 乱序、非最短长度、时间格式变体、空输入。
- 扩展方式：向 `scripts/gen_fuzz_corpus.py` 的 `SYNTH_BINARY` / `REAL_DERS` /
  `PKCS_BINS` / `CMS_BINS` / `SYNTH_ASN1C` 追加条目，重跑脚本并检入新产物；或直接向对应
  `corpus/<harness>/` 追加小文件。禁止检入大体积样本。
- 崩溃样本应放入 `tests/fuzz/regressions/` 并纳入常规 CTest（当前尚未产生）。