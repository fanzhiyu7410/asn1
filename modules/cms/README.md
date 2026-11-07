# asn1-cms

CMS / PKCS#7 标准结构模块（RFC 5652），以 `.asn1` 描述表驱动，提供**只读结构访问**与**结构构造（写）**两类能力。

## 模块范围

当前切片覆盖 2 个顶层结构，均支持只读打开与结构构造：

| 结构 | 标准 | 说明 |
| --- | --- | --- |
| `ContentInfo` | RFC 5652 §3 | `contentType` + `content [0] EXPLICIT ANY` |
| `SignedData` | RFC 5652 §5 | 版本、摘要算法、封装内容、证书、CRL、签名者信息 |

**不包含**：签名生成/验签、摘要计算、加解密、证书链校验、吊销状态查询、属性语义解析。结构构造只按 RFC 5652 组装节点并输出 DER；`CMSVersion`、算法 OID、eContent、签名值与证书/CRL 原始 DER 全部由调用方给值并原样承载，模块不推导、不校验业务范围。`ANY` 与属性集合只读写原始 TLV，密码学语义由调用方按 OID 二次解析。

后续规划：DetachedSignedData 之外的 CMS 结构（EnvelopedData、EncryptedData、AuthenticatedData、CompressedData）、PKCS#12 均后置，不在本切片实现。

## 公共头与链接

- 公共头：`asn1/cms/cms.h`
- 链接目标：`asn1::cms::shared` 或 `asn1::cms::static`
- 构建开关：`-DASN1_BUILD_MODULE_CMS=ON`

`asn1-cms` 是独立包，可独立安装后用 `find_package(asn1-cms CONFIG REQUIRED)` 消费。只依赖核心公共 C ABI，**不依赖 asn1-pkix**（ADR-0012）。

## 句柄与生命周期

2 个不透明句柄各由 `open` 创建、`close` 销毁：

- `asn1_cms_content_info_open` / `asn1_cms_content_info_close`
- `asn1_cms_signed_data_open` / `asn1_cms_signed_data_close`

约束：

- `open` 接收 DER 字节并复制进内部文档 arena，返回后调用方可释放输入缓冲。
- 句柄借用调用方的 `asn1_ctx_t`，**ctx 必须比句柄存活更久**。
- 每次 `open` 加载一次描述表并构建上下文级 schema，生命周期到 `close`；无全局缓存、无进程级单例。
- 所有访问器返回的指针（OID 文本、大整数十进制文本、字节/TLV）均**借用句柄**，`close` 后立即失效，不得释放。
- `close(NULL)` 为空操作；`open` 失败时 `*out_*` 置 `NULL` 并返回核心错误码。
- 构造侧句柄 `asn1_cms_builder_t` 由 `asn1_cms_builder_create` 创建、`asn1_cms_builder_destroy` 销毁；`destroy(NULL)` 与重复 destroy 安全。输入字节在设置/追加调用返回时已复制，调用方可立即释放原缓冲。
- 模块无全局可变状态；不同句柄互不影响。同一 `ctx` 的并发使用需由调用方加锁。

## API 概览

### ContentInfo

| 访问器 | 返回 |
| --- | --- |
| `asn1_cms_content_info_content_type` | `contentType` OID 点分十进制文本 |
| `asn1_cms_content_info_content` | `content` 内层 ANY 的完整原始 TLV（不含 `[0]` 包装），可直接交给 `asn1_cms_signed_data_open` |

### SignedData

| 访问器 | 返回 |
| --- | --- |
| `asn1_cms_signed_data_version` | `CMSVersion` 原值，不做范围校验 |
| `asn1_cms_signed_data_digest_algorithm_count` / `_at` | 摘要算法条目数；每项 `algorithm` OID + `parameters` 原始 TLV |
| `asn1_cms_signed_data_encap_content_type` | `eContentType` OID |
| `asn1_cms_signed_data_encap_content` / `_tlv` | `eContent` 的 OCTET STRING 内容字节 / 完整 TLV |
| `asn1_cms_signed_data_certificate_count` / `_at` | 证书条目数；每项分支判别（`ASN1_CMS_CERT_CHOICE_*`）+ 原始 TLV |
| `asn1_cms_signed_data_certificate_subject` / `_issuer` / `_serial` | 仅证书分支：`TBSCertificate` 的 subject/issuer 原始 TLV、serialNumber 十进制文本；扩展证书、AttributeCertificate v1/v2 与 other 分支返回 `ASN1_E_UNSUPPORTED`（`certificate_at` 仍给分支与完整原始 TLV） |
| `asn1_cms_signed_data_crl_count` / `_at` | CRL 条目数；每项分支判别（`ASN1_CMS_REVOCATION_CHOICE_*`）+ 原始 TLV |
| `asn1_cms_signed_data_signer_count` | `signerInfos` 条目数 |
| `asn1_cms_signed_data_signer_version` | `SignerInfo.version` 原值 |
| `asn1_cms_signed_data_signer_sid_choice` / `_sid_issuer` / `_sid_serial` / `_sid_subject_key_identifier` | `sid` 分支判别与对应字段 |
| `asn1_cms_signed_data_signer_digest_algorithm` | `digestAlgorithm` OID + `parameters` 原始 TLV |
| `asn1_cms_signed_data_signer_signed_attrs` / `_unsigned_attrs` | `[0]` / `[1]` IMPLICIT 属性集合的完整 TLV（含标签） |
| `asn1_cms_signed_data_signer_signature_algorithm` | `signatureAlgorithm` OID + `parameters` 原始 TLV |
| `asn1_cms_signed_data_signer_signature` / `_tlv` | `signature` OCTET STRING 内容字节 / 完整 TLV |

缺省字段（detached 的 `eContent`、无证书/CRL、无 `signedAttrs`/`unsignedAttrs`）返回 `ASN1_OK` 且 `NULL/0`；下标越界返回 `ASN1_E_INVALID_ARG`。

### 结构构造（写）

| 接口 | 说明 |
| --- | --- |
| `asn1_cms_builder_create` / `asn1_cms_builder_destroy` | 创建/销毁 builder；重复 destroy 与 `destroy(NULL)` 安全 |
| `asn1_cms_builder_set_version` | `CMSVersion`，必填；显式给值，不推导、不校验范围；重复设置 `ASN1_E_INVALID_STATE` |
| `asn1_cms_builder_add_digest_algorithm` | 追加 `digestAlgorithm`（至少一条）；`params` 为空表示 parameters 缺省 |
| `asn1_cms_builder_set_econtent_type` | `eContentType` OID，必填；重复设置 `ASN1_E_INVALID_STATE` |
| `asn1_cms_builder_set_econtent` | 设置 `eContent`（完整 DER OCTET STRING TLV）；不设置即 detached |
| `asn1_cms_builder_add_certificate` / `add_crl` | 追加证书/CRL 原始 DER；校验单 TLV 与分支根标签，输出按 DER `SET OF` 排序 |
| `asn1_cms_builder_add_signer` | 追加 `SignerInfo`（至少一条）；两种 `sid`、可选 `signedAttrs`/`unsignedAttrs` |
| `asn1_cms_builder_encode` | 组装并编码 `ContentInfo`（`contentType = id-signedData`）到调用方缓冲 |

语义约定：

- **版本**：`CMSVersion` 与 `SignerInfo.version` 由调用方显式给值，模块不推导、不校验范围。
- **signedAttrs 原样承载**：输入必须是完整、规范的 `SET OF Attribute`（外层 `0x31`，非空且元素为 `SEQUENCE`）；模块只把外层标签改写为 `0xA0`（`unsignedAttrs` 为 `0xB1`），长度字节与内容逐字节不变，不重建、不排序。签名覆盖的是 `SET OF` 编码，调用方必须对同一份字节签名，否则验签失败。非规范输入返回 `ASN1_E_NON_CANONICAL`，空集合或元素不是 `SEQUENCE` 返回 `ASN1_E_INVALID_VALUE`。
- **证书/CRL 不解析**：除“恰好一个完整规范 DER TLV”外，只检查分支根标签——证书须为 `Certificate` 的 `SEQUENCE` 或 `CertificateChoices` 的 `[0..3]` 备选，CRL 须为 `CertificateList` 的 `SEQUENCE` 或 `RevocationInfoChoice` 的 `other [1]`；不解析内部、不做信任判断；输出按 DER `SET OF` 规则排序。
- **sid 根标签**：`issuerAndSerialNumber` 形式的 `issuer` 须为 `SEQUENCE`、`serialNumber` 须为 `INTEGER`；不符返回 `ASN1_E_INVALID_VALUE`。
- **错误模型**：必填缺失、重复设置单值字段返回 `ASN1_E_INVALID_STATE`；OID 非法、根标签/分支不符返回 `ASN1_E_INVALID_VALUE`；非单一合法 TLV 返回 `ASN1_E_TRUNCATED` / `ASN1_E_MALFORMED_LENGTH` / `ASN1_E_TRAILING_DATA` / `ASN1_E_NON_CANONICAL` 等核心错误码。失败不产出半成品缓冲。
- **输出所有权**：成功时 `asn1_buf_t` 由上下文分配，调用方用 `asn1_buf_release` 归还。

## 最小示例

```c
#include <asn1/asn1.h>
#include <asn1/cms/cms.h>

asn1_ctx_config_t config;
asn1_ctx_config_init(&config);
asn1_ctx_t *ctx = NULL;
asn1_ctx_create(&config, &ctx);

asn1_cms_content_info_t *info = NULL;
if (asn1_cms_content_info_open(ctx, der, der_size, &info) == ASN1_OK) {
    const char *type = NULL;
    size_t type_size = 0;
    asn1_cms_content_info_content_type(info, &type, &type_size);

    const uint8_t *content = NULL;
    size_t content_size = 0;
    /* content 是被封装结构的完整 TLV，可直接打开 SignedData */
    asn1_cms_content_info_content(info, &content, &content_size);

    asn1_cms_signed_data_t *signed_data = NULL;
    asn1_cms_signed_data_open(ctx, content, content_size, &signed_data);

    /* ... 读取 signerInfos / certificates ... */

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
}
asn1_ctx_destroy(ctx);
```

构造侧示例（detached，最小字段）：

```c
asn1_cms_builder_t *builder = NULL;
if (asn1_cms_builder_create(ctx, &builder) == ASN1_OK) {
    asn1_cms_builder_set_version(builder, 1);
    asn1_cms_builder_add_digest_algorithm(
        builder, "2.16.840.1.101.3.4.2.1", NULL, 0);
    asn1_cms_builder_set_econtent_type(builder, "1.2.840.113549.1.7.1");
    /* 不调用 set_econtent 即 detached */
    asn1_cms_builder_add_signer(
        builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL,
        issuer_tlv, issuer_size, serial_tlv, serial_size,
        "2.16.840.1.101.3.4.2.1", NULL, 0,
        NULL, 0, "1.2.840.113549.1.1.1", NULL, 0,
        signature, signature_size, NULL, 0);

    asn1_buf_t der;
    if (asn1_cms_builder_encode(builder, &der) == ASN1_OK) {
        /* 使用 der.data / der.size */
        asn1_buf_release(ctx, &der);
    }
    asn1_cms_builder_destroy(builder);
}
```

## 证书分支与原始 TLV

`certificates` 是 `[0] IMPLICIT SET OF CertificateChoices`，模块按实际标签判别分支：

| 分支 | DER 标签 | 常量 |
| --- | --- | --- |
| `certificate` | `0x30`（SEQUENCE） | `ASN1_CMS_CERT_CHOICE_CERTIFICATE` |
| `extendedCertificate` | `0xA0` | `ASN1_CMS_CERT_CHOICE_EXTENDED` |
| `v1AttrCert` | `0xA1` | `ASN1_CMS_CERT_CHOICE_V1_ATTR_CERT` |
| `v2AttrCert` | `0xA2` | `ASN1_CMS_CERT_CHOICE_V2_ATTR_CERT` |
| `other` | `0xA3` | `ASN1_CMS_CERT_CHOICE_OTHER` |

属性证书分支在展平模块中是 `SEQUENCE { ... }` 不透明占位：可取得完整原始 TLV，但不能结构化读取内部字段。`subject`/`issuer`/`serial` 访问器只对 `certificate` 分支有效。

## 描述表来源与重生成

展平 ASN.1 源在 `modules/cms/asn1/CMS-Flattened-5652.asn1`，按根 `ContentInfo`、`SignedData` 各生成一张表，产物检入 `modules/cms/generated/`（`.bin` + 描述头 `.h`）。默认构建不依赖 `asn1c`。

```powershell
cmake -G Ninja -B build-cms-regen -DASN1_BUILD_TOOLS=ON -DASN1_CMS_REGENERATE_TABLE=ON
cmake --build build-cms-regen --target asn1_cms_table_verify
```

来源、复制范围、逐类型对账与勘误核对见 `modules/cms/asn1/README.md` 与 `modules/cms/asn1/reconciliation.md`。

## 测试

- 样本：`tests/data/cms_rsa_attached.der`（attached，证书 + signedAttrs）、`cms_rsa_detached.der`（detached，证书 + signedAttrs）、`cms_rsa_minimal.der`（无证书、无 signedAttrs）、`cms_rsa_ec_multicert.der`（RSA + ECDSA 多证书多签名者）、`cms_rsa_keyid.der`（sid 为 subjectKeyIdentifier）。由 `python scripts/gen_test_data.py --cms` 用已提交的证书/私钥生成。
- 用例：`tests/cms/test_cms_structures.c`，覆盖正例字段读取、detached 无 `eContent`、多证书逐项、SignerInfo 各字段（含两种 sid 分支）、空参/非 CMS/截断负例。
- 构造用例：`tests/cms/test_cms_builder.c`，覆盖 attached/detached、单/多证书、两种 `sid`、带 `signedAttrs`、无证书最小样本、v1/v2 `AttributeCertificate` 分支（`certificate_at` 保留判别与原始 TLV，结构化访问器返回 `ASN1_E_UNSUPPORTED`）、必填缺失/重复设置/非法 TLV 负例；5 份样本做 decode → builder 重建 → 编码，规范 DER 源逐字节一致。
- 同时纳入差分（OpenSSL `asn1parse` 逐样本对照）与 fuzz 语料。

## 状态

0.1.0：ContentInfo / SignedData 只读字段访问与结构构造（builder + DER 编码）；只读与构造 C 用例在 MinGW（GCC 13.2，`-Werror`）下构建与 ctest 通过，5 份样本构造往返逐字节一致。证书集合覆盖 `certificate`/`extendedCertificate`/`v1AttrCert`/`v2AttrCert`/`other` 全部分支：`certificate_at` 一律返回判别与完整原始 TLV，结构化访问器只对 `certificate` 生效，其余分支返回 `ASN1_E_UNSUPPORTED`。构造侧不生成签名/摘要、不做加解密、不校验证书链。
