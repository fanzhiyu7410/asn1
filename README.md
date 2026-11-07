# asn1

通用 ASN.1 解析/编解码库，配以一组独立的标准化结构模块。

核心库 `asn1` 只处理标签、节点、文档、值、模板描述与编码规则，**不包含任何领域知识**，也不内置标准结构表。X.509/PKIX、CMS/PKCS#7、PKCS#10/#12/#1/#8 等标准结构由独立模块包提供（`asn1-pkix`、`asn1-cms`、`asn1-pkcs`），每个模块拥有自己的包名、版本、公共头文件与符号前缀。依赖方向严格单向：模块 → 核心，核心不反向引用任何模块。

对外只提供 C ABI，内部使用 C++ 实现；标准结构的 ASN.1 定义直接复用公开 RFC 模块，不自创描述格式。`asn1c` 与核心之间共享一份固定的描述表字节契约（`uint8_t[]`、显式小端读取），见[描述表格式](docs/11-描述表格式.md)。

**当前状态：BER/DER 解码、DOM、值读取、schema 模板（运行时注册与描述表加载）、schema 感知解码/编码、`asn1_doc_validate`、`asn1_node_create_any` 公共构树入口（`ASN1_CAP_ANY_OPEN_TYPE` 已置位）、`asn1c` MVP（`.asn1` → 描述表 1.0 的 C 数组/二进制生成，含名称表）、`asn1-pkix` 模块（证书字段访问）、`asn1-cms` 模块（ContentInfo/SignedData 只读访问与 builder 结构构造）已实现；仍未实现：多模块 `IMPORTS`、参数化展开（二期）。** 上下文/内存模型、错误模型与 C ABI 已落地，测试覆盖 BER/DER 解码、编码往返、DOM、上下文/静态池、值读取、schema 与 ANY 节点语义、名称表读写与查询、`asn1c` 端到端生成与加载；**fuzz + 差分测试**已落地（10 个 libFuzzer harness，含 PKIX/PKCS/CMS 模块级 open/accessor harness，+ OpenSSL `asn1parse` 差分，本地构建/短跑/长跑已验证，CI 远端 run 42340940579 与 42263533895 已通过）。**嵌入式**：静态池路径已在 Cortex-M4F 交叉构建（`.text` 11,548 / `.data` 1,348 / `.bss` 17,212）与 `qemu-arm` 运行中验证（无堆调用、池耗尽返回 `ASN1_E_STATIC_POOL_EXHAUSTED`），真实板卡未实测；尚不能作为完整可用库发布。

## 分层

| 层 | 内容 | 说明 |
| --- | --- | --- |
| 核心 `asn1` | 通用 BER 解码、DER 解码/编码、DOM 值树、runtime 构树、内存与错误模型、模板机制 | 零领域知识；不解析 `.asn1` 文本 |
| 标准模块 | `asn1-pkix`（RFC 5912）、`asn1-cms`（RFC 6268）、`asn1-pkcs`（RFC 8017/5208/2986/7292） | 各自独立 CMake 包与版本；依赖核心 |
| 工具 `asn1c` | 解析 `.asn1` 文本、语义校验、生成描述表（C 数组或二进制） | 独立可执行文件；一期输入为自包含展平模块，`IMPORTS`/参数化仅报明确诊断 |

模板机制是核心一期能力：核心接受**已编译描述表**（C 源数组或二进制资源），也提供运行时注册 C API，两条入口构建同一棵类型树，用于字段命名、结构化约束校验与 `CHOICE` 分支、`SEQUENCE OF`/`SET OF`、`OPTIONAL`、`DEFAULT`、扩展标记判定。类型构造性由类型种类 `kind` 派生，标签行为由 `tag_mode` 与模块默认标注方式决定，`DEFAULT` 以规范 DER TLV 存放，`BIT STRING` 命名位与 `ENUMERATED`/`INTEGER` 数值名由名称表表达。把 `.asn1` 文本解析成描述表的工作只属于 `asn1c`；一期输入是自包含展平模块，`IMPORTS`/参数化/信息对象为明确诊断项，二期再做。

## 目录结构

```text
.
├─ CMakeLists.txt          根，编排核心与模块、工具
├─ include/asn1/           核心公共 C ABI
├─ src/                    核心实现（core/ 上下文/错误/版本，types/ DOM 与值处理，
│                          ber/ BER 解码（含不定长），der/ DER 严格校验与编码，
│                          schema/ 模板注册/描述表，c_api/ C ABI）
├─ modules/
│  ├─ pkix/                asn1-pkix：include + src + 独立导出包
│  │  └─ asn1/             RFC 5912 展平模块（PKIX-Flattened-2009.asn1；对账见 reconciliation.md）
│  ├─ cms/                 asn1-cms
│  └─ pkcs/                asn1-pkcs
├─ tools/asn1c/            `.asn1` → 描述表 1.0 生成工具（C 数组/二进制）
├─ tests/                  unit / c_api / asn1c / conformance / support / fuzz / bench
├─ examples/c              C 消费示例（占位）
├─ examples/cpp            C++ 消费示例（占位）
├─ cmake/                  构建选项、编译检查、安装导出、包配置模板
├─ docs/                   设计文档体系（入口：docs/文档索引.md）
├─ scripts/                辅助脚本（第三方依赖检查等）
├─ .screenshots/           浏览器/工具临时截图目录（已 gitignore，不随仓库分发）
├─ THIRD_PARTY_NOTICES.md  第三方组件分发声明（当前空模板）
└─ LICENSE
```

## 构建

要求：CMake ≥ 3.20、C++17 编译器（GCC/Clang/MSVC/MinGW 均可）。库本身不依赖第三方运行时；测试与工具依赖限定宽松许可，登记与检查见[第三方依赖与许可证清单](docs/第三方依赖与许可证清单.md)。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

启用示例、测试与严格告警：

```bash
cmake -S . -B build \
  -DASN1_BUILD_EXAMPLES=ON \
  -DASN1_BUILD_TESTS=ON \
  -DASN1_WARNINGS_AS_ERRORS=ON \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

安装与消费：

```bash
cmake --install build --prefix out/install
```

```cmake
find_package(asn1 CONFIG REQUIRED)          # 核心
find_package(asn1-pkix CONFIG REQUIRED)     # 模块，自动依赖 asn1

target_link_libraries(app PRIVATE asn1::shared asn1::pkix::shared)
```

模块用法（打开一张 DER 证书并按路径访问字段）：

```c
#include <asn1/pkix/pkix.h>

asn1_ctx_config_t config;
asn1_ctx_t *ctx;
asn1_pkix_certificate_t *cert;
asn1_ctx_config_init(&config);
asn1_ctx_create(&config, &ctx);

if (asn1_pkix_certificate_open(ctx, der, der_size, &cert) == ASN1_OK) {
    const asn1_node_t *subject;
    uint32_t version;
    asn1_pkix_certificate_version(cert, &version);          /* 2 = v3 */
    asn1_pkix_certificate_find(cert, "tbsCertificate.subject", &subject);
    /* 后续用核心 asn1_node_* 读取 subject 下的值 */
    asn1_pkix_certificate_close(cert);
}
asn1_ctx_destroy(ctx);
```

ANY 字段（如 `algorithmIdentifier.parameters`）只返回原始 TLV，模块不做算法参数展开。

主要选项：

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `ASN1_BUILD_SHARED` | `ON` | 构建 `asn1::shared` |
| `ASN1_BUILD_STATIC` | `ON` | 构建 `asn1::static` |
| `ASN1_BUILD_MODULES` | `ON` | 构建 `modules/` 下的独立标准模块 |
| `ASN1_BUILD_MODULE_PKIX` | `ON` | 构建 `asn1-pkix`；仅 `ASN1_BUILD_MODULES=ON` 时生效 |
| `ASN1_BUILD_MODULE_CMS` | `ON` | 构建 `asn1-cms`；仅 `ASN1_BUILD_MODULES=ON` 时生效 |
| `ASN1_BUILD_MODULE_PKCS` | `ON` | 构建 `asn1-pkcs`；仅 `ASN1_BUILD_MODULES=ON` 时生效 |
| `ASN1_BUILD_TOOLS` | `ON` | 构建 `tools/asn1c` |
| `ASN1_PKIX_REGENERATE_TABLE` | `OFF` | 构建期用 `asn1c` 重新生成 PKIX 描述表，并与检入产物逐字节比对（差异即构建失败）；默认直接用检入产物 |
| `ASN1_BUILD_EXAMPLES` | `OFF` | 构建 C/C++ 消费示例 |
| `ASN1_BUILD_TESTS` | `OFF` | 构建测试并注册 CTest |
| `ASN1_BUILD_EMBEDDED_TEST` | `OFF` | 构建嵌入式最小用例（可脱离 CTest，交叉编译时只构建不运行） |
| `ASN1_BUILD_BENCHMARKS` | `OFF` | 构建批量基准（不进 CTest 主流程） |
| `ASN1_FREESTANDING` | `OFF` | 裁剪为 freestanding 子集 |
| `ASN1_WARNINGS_AS_ERRORS` | `OFF` | 告警视为错误 |
| `ASN1_ENABLE_SANITIZERS` | `OFF` | ASan + UBSan（宿主调试） |

异常与 RTTI 固定禁用（`-fno-exceptions -fno-rtti`；MSVC `/EHs-c- /GR-`），不提供开关。

## 文档入口

- [文档索引与阅读顺序](docs/文档索引.md)
- [总体架构](docs/01-架构设计.md)
- [C API 设计规范](docs/02-C-API规范.md)
- [描述表格式（asn1c 与核心共享契约）](docs/11-描述表格式.md)
- [ASN.1 能力范围](docs/03-ASN1能力范围.md)
- [数据表示与内存模型](docs/04-数据与内存模型.md)
- [错误模型](docs/05-错误模型.md)
- [构建与移植](docs/06-构建与移植.md)
- [测试与验证策略](docs/07-测试与验证.md)
- [编码规范与工程约定](docs/08-编码规范.md)
- [里程碑与分期](docs/09-里程碑与分期.md)
- [术语表](docs/10-术语表.md)
- [基线覆盖度清单](docs/基线覆盖度清单.md)
- [未决问题清单](docs/待确认问题.md)
- [第三方依赖与许可证清单](docs/第三方依赖与许可证清单.md)
- [ADR 目录](docs/adr/ADR索引.md)

## 依赖与许可证

- 运行库零第三方依赖：核心与模块的发版产物只链接 C 运行库与平台系统库。
- 测试与工具依赖限定宽松许可（MIT、BSD-2/3-Clause、Apache-2.0 含 LLVM 例外）；禁止 GPL/LGPL/AGPL 或许可不明代码。
- 仓库当前无第三方源码；doctest（测试框架）与 libFuzzer（fuzz 驱动）登记于[第三方依赖与许可证清单](docs/第三方依赖与许可证清单.md)，均不随产物分发。
- 发版随包提供 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)（当前为空模板）；`python scripts/check_third_party.py` 检查未登记依赖，一期 CI 挂载。
- 项目许可证：MIT，见 [LICENSE](LICENSE)。策略细节见 [ADR-0011](docs/adr/0011-第三方依赖与许可证策略.md)。

## 版本与 ABI

- 核心与各模块各自声明版本，安装到 `lib/cmake/<包名>`；模块配置通过 `find_dependency(asn1 <最低版本> CONFIG)` 表达对核心的依赖。
- 版本宏由 CMake 从 `project(... VERSION ...)` 生成到构建目录（`include/asn1/asn1_version.h`、`include/asn1/<模块>/<模块>_version.h`），源码树中不手写；消费者只需包含公共头即可获得版本宏。
- 基线承诺核心 ABI 向后兼容：公共头文件只增不改，结构体带 `struct_size`，核心符号统一 `asn1_` 前缀。
- 共享库 SONAME 固定为主版本；破坏性变更只能升主版本。
- 核心 ABI 稳定期内，模块可独立升级版本，不要求与核心同版本。
- 运行时 `asn1_version_check` 只对**主版本不一致**报错，次版本差异视为兼容；可选能力通过 `asn1_version_info_t.capabilities` 与 `asn1_has_capability()` 查询，不按次版本号推断。
- 版本一致性机制见 [ADR-0010](docs/adr/0010-版本一致性机制.md)。

## 验证状态（2026-11-07，阶段 1 验证轮）

只列实测事实；“未实测”不代表不支持。三档含义：**本地实测**（写明平台/工具链/日期）、**未实测**、**不承诺**。当前用例数量与结果以实际 `ctest` 运行摘要为准（本轮 28 条）；未在本轮用例集下复跑的平台按当次基线注明，不把历史通过数当成本轮结论。

| 验证项 | 结果 |
| --- | --- |
| Windows 本机 MinGW-W64 GCC 13.2.0（2026-11-07） | **本地实测**（2026-11-07 三配置复测）：`build-pkcs-final` / `build-mingw-Release-shared` / `build-mingw-Release-static` 各 **28/28** 通过（含 `test_struct_size`、`test_build_any`、`test_cms_builder`）；`test_asn1c_cli` 缺失输入退出码 3；逐配置摘要见 [测试与验证](docs/07-测试与验证.md) 9.4 |
| ABI 导出符号守卫（共享库） | **本地实测**（MinGW-W64 GCC 13.2.0，2026-11-07）：`scripts/check_exports.py` 在 `build-pkcs-final` 与 `build-mingw-Release-shared` 上四模块全部一致（68/11/45/43）；临时删除基线符号时按预期以退出码 1 报错 |
| Windows 本机 MSVC 19.51 x64（2026-11-06 基线） | **本地实测**（当次用例集）：Release 共享/静态与 Debug 共享均通过；本轮新增 4 条用例后未复跑 |
| WSL2 Ubuntu 26.04 + GCC 15.2.0（2026-11-06 基线） | **本地实测**（当次用例集）：共享/静态各一轮通过；本轮新增 4 条用例后未复跑 |
| WSL2 Ubuntu 26.04 + Clang 21.1.8（2026-11-06 基线） | **本地实测**（当次用例集）：共享/静态各一轮通过；本轮新增 4 条用例后未复跑 |
| ASan + UBSan（Clang 21.1.8，全量插桩）（2026-11-06 基线） | **本地实测**（当次用例集）：全部通过；本轮新增 4 条用例后未复跑 |
| libFuzzer 短跑（10 harness，ASan+UBSan+LSan，各 60 s） | **本地实测**：无崩溃/泄漏/超时；迭代数见下表 |
| libFuzzer 长跑（`fuzz_schema_load`，900 s） | **本地实测**：54,361,459 次执行、无崩溃/泄漏/超时；`cov 356` 为 trace-pc-guard **边数**（补语料后检入语料短跑 `cov 559`、短 fuzz `cov 563`），非块/分支覆盖率 |
| schema 加载行/分支覆盖率（llvm-cov，检入语料全量 + 30 s 短 fuzz） | **本地实测**：`asn1_schema_table.cpp` 行 95.06% / 分支 83.14%；详见 [测试与验证](docs/07-测试与验证.md) 9.1 |
| schema 感知解码行/分支覆盖率（llvm-cov，检入语料全量 + 30 s 短 fuzz） | **本地实测**：`asn1_schema_decode.cpp` 行 90.66% / 分支 85.36% / 函数 100%，`cov 463`（trace-pc-guard 边数）；详见 [测试与验证](docs/07-测试与验证.md) 9.2 |
| 差分（`asn1_dump` + OpenSSL `asn1parse`） | **本地实测**：8 个真实 DER 全一致（结构层级/TLV 边界/偏移）；decode→encode 往返 8/8 逐字节一致且 openssl 复解析合法；asn1tools 未装 → skipped |
| 嵌入式（核心 BER/DER，无 schema） | **本地实测**：`.text` 约 11.5 KB（实测 `.text` 11,548 / `.data` 1,348 / `.bss` 17,212）、静态池 **16 KB 起**；适合小容量 MCU |
| 嵌入式（带 PKIX 描述表 + schema 感知解码） | **本地实测**：最小静态池 **86,880 字节（约 85 KB）**，需外扩 RAM；**约 85 KB 池不适合 RAM 低于 96 KB 的小容量 MCU** |
| ARM Cortex-M4F 交叉（arm-none-eabi-gcc 14.2.1 + newlib，`ASN1_FREESTANDING=ON`） | **本地实测**：构建/链接通过（`libasn1_static.a` 121,036 字节）；**真实板卡未实测** |
| 静态池嵌入式用例（ARM32 Linux + qemu-arm 10.2.1） | **本地实测**：返回 0；按 `asn1_ctx_size_for_config` 分配、池耗尽返回 `ASN1_E_STATIC_POOL_EXHAUSTED`、全程 0 次堆调用 |
| macOS AppleClang（macos-15-intel/macos-15） | **CI 实测**：run 42340940579 六平台 25 个 job 全部通过；本地无 macOS 机器；阶段 1 新增用例已在该 run 复验 |
| GitHub Actions 实际触发 | **已通过**：run 42340940579（ci 25/25、sanitizers、fuzz、differential 全部成功）；上一轮 42263533895 亦通过 |
| fuzz-hardened 认证 | **不承诺**（未做专项抗恶意输入认证；ASan/UBSan/LSan 与 libFuzzer 短跑/长跑仅证明常规鲁棒性，不等于安全认证） |
| 默认共享+静态配置与构建（含 3 个模块与 `asn1c`） | 通过 |
| 启用示例、`ASN1_WARNINGS_AS_ERRORS=ON` 的配置与构建 | 通过 |
| C 示例与 C++ 示例运行 | 返回码 0 |
| 仅静态库 + `ASN1_FREESTANDING=ON` + 严格告警构建（关闭模块与工具） | 通过 |
| `cmake --install` | 生成核心与模块头文件、库文件、`bin/asn1c` 与 `lib/cmake/asn1*` 配置 |
| 独立工程 `find_package(asn1 CONFIG REQUIRED)` | C 共享库、C++ 共享库、C 静态库三种消费均构建并运行通过 |
| 独立工程仅 `find_package(asn1-pkix CONFIG REQUIRED)` | 自动解析对 `asn1` 的依赖；`asn1::pkix::shared` 与 `asn1::pkix::static` 两种链接均构建、打开真实证书并运行通过 |
| `ASN1_PKIX_REGENERATE_TABLE=ON` | `asn1c` 重新生成的 `.h/.bin` 与检入产物逐字节一致；人为改动检入 `.bin` 后构建失败 |
| `asn1c --version` | 输出 `asn1c 0.1.0`，与生成头 `ASN1C_VERSION_STRING` 一致 |
| `python scripts/check_third_party.py` | 通过：已登记 doctest、libFuzzer 两项，未发现未登记引用 |

libFuzzer 短跑（各 60 s，`-max_len` 二进制 8192 / 文本 4096，ASan+UBSan+LSan，`detect_leaks=1`）：

| Harness | 执行单元 | exec/s | 新增单元 | Asan/UBSan 命中 |
| --- | --- | --- | --- | --- |
| `fuzz_decode_ber` | 795,082 | 13,034 | 552 | 0 |
| `fuzz_decode_der` | 1,195,689 | 19,601 | 578 | 0 |
| `fuzz_reader` | 399,190 | 6,544 | 465 | 0 |
| `fuzz_schema_decode` | 4,111,037 | 67,394 | 0 | 0 |
| `fuzz_roundtrip` | 1,000,010 | 16,393 | 718 | 0 |
| `fuzz_schema_load` | 4,576,677 | 75,027 | 123 | 0 |
| `fuzz_asn1c` | 40,518 | 664 | 1,013 | 0 |
| `fuzz_pkix_open` | 3,107 | 50 | 38 | 0 |
| `fuzz_pkcs_open` | 4,103 | 67 | 26 | 0 |
| `fuzz_cms_open` | 2,089 | 34 | 28 | 0 |

断言点静态计数 **2411 处**（宏调用点；循环体内实际执行次数更多）。`tests/` 静态库与共享库配置均注册 **28 个**无第三方依赖的 C 用例（以实际 `ctest` 运行摘要为准，见 [测试与验证](docs/07-测试与验证.md) 9.4），覆盖 `asn1-pkix` 证书打开与字段访问（RSA/RSA-PSS/EC 三张真实证书、ANY 三形态、句柄隔离、负例、安装后共享/静态独立消费）、BER 解码（含不定长）、DER 严格解码、DER 编码往返、DOM 值树、上下文/静态池、值读取、schema 运行时注册与描述表加载、名称表、schema 感知解码与约束求值、`asn1_doc_validate`、schema 感知编码、ANY/开放类型（含 EXPLICIT 包装）、buffer/reader 双路径解码、`asn1c` 端到端（PKIX 69 个具名类型 / 173 条记录 / 6 处 ANY 字段 / 31 条名称记录、CRC32C 自检、负例诊断 9001/9002/9003/9004/9006/9009、RSA/EC 证书 schema 往返）、`asn1-cms` ContentInfo/SignedData 只读访问与 builder 结构构造（5 份样本 decode→重建→编码逐字节一致）与嵌入式静态池最小用例。

批量基准（`ASN1_BUILD_BENCHMARKS=OFF` 默认关闭，不进 CTest）：`asn1_pkix_certificate_open + close`，RSA 自签证书 865 字节。MSVC 19.51 x64 Release：1,000 次 918 ms（918 µs/次）、10,000 次 8,505 ms（850.5 µs/次），峰值堆 73,260 字节；WSL2 GCC 15.2.0 Release：1,000 次 368 ms、10,000 次 5,119 ms，峰值堆 73,284 字节。每次 open 加载一次 24 KB 描述表并构建上下文级 schema，生命周期到 close，无全局缓存；该数字仅用于评估是否需要核心 ctx 级 schema 缓存，本轮不改核心 ABI。五组模块 `open + close`（PKIX/PKCS#8/PKCS#1/PKCS#10/CMS）的 `count/min/median/p95/mean` 与峰值堆基线见[性能基线](docs/性能基线.md)，由 `ASN1_BUILD_BENCHMARKS=ON` 构建的 `bench_module_open` 生成。

尚未验证：本地 macOS 实机复现（CI 已通过）、真实 Cortex-M4 板卡运行、多模块 `IMPORTS`/参数化（二期）。fuzz/差分已本地构建并短跑+长跑验证（无崩溃/泄漏）。当前库仅实现上述子集，不可用于生产。

## 许可证

MIT，见 [LICENSE](LICENSE)。运行库不含第三方组件；随产物分发的第三方声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)（当前为空模板）。

Copyright (c) 2026 asn1 project contributors
