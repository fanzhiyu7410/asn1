# 变更记录

本文件记录对外可见的版本变更；格式参考 Keep a Changelog，版本号遵循语义化版本。

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

[0.1.0]: https://github.com/fanzhiyu7410/asn1/releases/tag/v0.1.0
