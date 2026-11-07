# 变更记录

本文件记录对外可见的版本变更；格式参考 Keep a Changelog，版本号遵循语义化版本。

## [0.1.2] - 2026-11-07

发布后状态文档同步批：**无代码变更**（不改公共 ABI、不改错误码、不改用例），核心与 `asn1-pkix`/`asn1-pkcs`/`asn1-cms` 版本同步升为 0.1.2；`tools/asn1c` 独立版本保持 0.1.0。本版不含代码变更，与 0.1.1 的二进制行为一致。

- 状态文档：README 与 `docs/06`/`docs/07` 的 CI 证据统一改为引用 0.1.1 **tag commit** 轮（ci 42377612726、sanitizers 42377612727、fuzz 42377612742、differential 42377612618），不再停留在 0.1.0 发布轮或 0.1.1 卫生批轮。
- 发布状态：README 与 `docs/09` 明确 `v0.1.0` 与 `v0.1.1` 均已于 2026-11-07 发布；`docs/09` 区分“二期第二批已完成切片”（`ContentInfo`/`SignedData` 只读、builder 结构构造、`AttributeCertificate` 分支收口）与“其余 CMS 结构未开工”。
- 修正 0.1.1 发布说明中的不实表述：`v0.1.1` Release 正文曾称 `docs/06` 已引用 0.1.1 证据，实际当时 `docs/06` 仍引用 0.1.0 发布轮；已修正 Release 正文，此处如实记录，不做静默抹除。

## [0.1.1] - 2026-11-07

卫生批，只改文档与测试：**无公共 ABI 变更**（不新增、不删除、不改名符号，不变更错误码语义），核心与 `asn1-pkix`/`asn1-pkcs`/`asn1-cms` 版本同步升为 0.1.1；`tools/asn1c` 独立版本保持 0.1.0。

### 文档

- CI 与状态同步：README 与 `docs/07` 统一引用 0.1.1 卫生批 CI 证据；0.1.0 发布轮与更早 run 标注为历史记录；补充 MSVC 在 CI 上 Debug/Release 均跑全量 ctest、`fuzz-longrun-der` 仅 schedule/workflow_dispatch 触发。
- PKCS#12 前缀例外：记录 PKCS#12 切片的**函数**使用 `asn1_pkcs12_*`（25 个）并随 0.1.0 冻结，导出/声明宏仍为 `ASN1_PKCS_`（不存在 `ASN1_PKCS12_` 宏前缀）；PKCS#1/#8/#10 的函数使用 `asn1_pkcs_*`（45 个）；未来统一只能在 0.2.0 新增函数别名并保留旧符号至少一个次版本周期。
- 阶段 1 验收证据索引：逆序 SET OF、tag number 31/128/16384 解码往返、`format_version` 四类（五组输入）非法值、性能基线，各给文件与用例位置。
- DER 口径收窄：无 schema 编码时普通节点仍按通用 DER 重建，只有 ANY/保留 TLV 原样回写；schema 感知编码校验保留 TLV，非 DER 返回 `ASN1_E_NON_CANONICAL`。
- ANY 深度口径：schema 感知 DER 编码校验保留 TLV 时复用上下文 `max_depth`；`asn1_doc_validate` 的 `max_depth` 只约束 schema 绑定深度，不遍历 ANY 内层。

### 测试

- `test_build_any` 新增深度回归：默认预算下 70 层嵌套 ANY 返回 `ASN1_E_DEPTH_LIMIT`，3 层编码成功。
- `test_pkcs_pool` / `test_cms_pool`：ctx 创建失败回传真实错误码；耗尽断言改为“池意外成功即判失败”；新增 `min_pool - 1` 必失败、`min_pool` 必成功边界组。

## [0.1.0] - 2026-11-07

首个 0.1.0 版本，核心与三个标准模块同源发布：版本宏由 CMake `project(... VERSION 0.1.0)` 生成到 `asn1_version.h` 与各模块 `<模块>_version.h`，运行时 `asn1_version` 与模块 `version_string` 一致。

### 新增

- 核心 `asn1`：BER/DER 解码（含不定长与 EOC）、DER 严格校验、DER 编码、DOM 值树、缓冲区/回调两种输入、值读取（OID、大整数只读视图与十进制导出、时间结构化解析、字符集白名单转换、BIT STRING 位级读取）、`asn1_doc_validate`。
- 模板机制：运行时注册与已编译描述表两条等价入口，支持 `SEQUENCE`/`SET`/`CHOICE`/`SEQUENCE OF`/`SET OF`、`OPTIONAL`/`DEFAULT`、约束与扩展标记、名称表；schema 感知解码与编码；`ANY`/开放类型与 `asn1_node_create_any` 公共构树入口（`ASN1_CAP_ANY_OPEN_TYPE`）。
- 工具 `asn1c`：`.asn1` 文本解析、语义检查与描述表 1.0 生成（C 数组/二进制 + 名称表），诊断码 9001/9002/9003/9004/9006/9007/9009。
- `asn1-pkix`：证书打开、路径查找与常用字段访问（版本、序列号、签名算法 OID、签名值、issuer/subject 原始 DER、有效期）。
- `asn1-pkcs`：PKCS#1、PKCS#8、PKCS#10、PKCS#12 只读结构访问（含 PKCS#12 明文/加密/仅证书 PFX 遍历、`MacData` 默认迭代次数、`CertBag` X.509/SDSI 分支）。
- `asn1-cms`：ContentInfo / SignedData 只读字段访问，以及 builder 结构构造与 DER 编码（证书/CRL 排序、两种 `sid`、`signedAttrs`/`unsignedAttrs` 原样承载、`AttributeCertificate` v1/v2 分支仅原始 TLV）。
- 内存与错误模型：上下文、分配器与静态池；池耗尽返回 `ASN1_E_STATIC_POOL_EXHAUSTED`。核心 `ctx` 固定开销 448 字节；宿主实测最小静态池：PKIX 86,880、PKCS 11,648、CMS 53,536 字节。
- 构建与交付：核心与模块各自独立 CMake 包、版本、公共头与符号前缀；静态/共享库不同名；`ASN1_FREESTANDING` 支持核心 + PKIX + PKCS + CMS；模块描述表以内嵌数组随库编译，无需运行时资源文件。
- 测试：无第三方依赖 C 用例（`ctest -N` 派生当前数量）；10 个 libFuzzer harness + OpenSSL `asn1parse` 差分；ABI 导出符号基线 `abi/*.symbols.txt`；公共头自包含编译测试；四个 out-of-tree 消费用例（含安装前缀重定位）。

### 限制

- 不做密码学语义：不验签、不摘要、不解密、不校验证书链、不校验 PKCS#12 MAC，也不做口令派生。
- `ANY` 字段只返回原始 TLV；`AttributeCertificate` 等非 `certificate` 分支仅原始 TLV，结构化访问器返回 `ASN1_E_UNSUPPORTED`。
- 无 schema 编码按原字节回写，允许 BER 往返，不保证输出 DER。
- CMS builder 要求至少一条 signer，不支持 certificates-only（空 `signerInfos`）输出；只读侧允许空 `signerInfos`。
- `asn1c` 一期只接受自包含展平模块；`IMPORTS` 与参数化展开在二期。
- 未做 fuzz-hardened 安全认证；真实 Cortex-M4 板卡与本地 macOS 实机未实测（后者由 CI 覆盖）。

[0.1.2]: https://github.com/fanzhiyu7410/asn1/releases/tag/v0.1.2
[0.1.1]: https://github.com/fanzhiyu7410/asn1/releases/tag/v0.1.1
[0.1.0]: https://github.com/fanzhiyu7410/asn1/releases/tag/v0.1.0
