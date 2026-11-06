# asn1-cms

CMS / PKCS#7 标准结构模块（RFC 5652），以 `.asn1` 描述表驱动，只做**只读结构访问**。

## 模块范围

本轮只读切片覆盖 2 个顶层结构：

| 结构 | 标准 | 说明 |
| --- | --- | --- |
| `ContentInfo` | RFC 5652 §3 | `contentType` + `content [0] EXPLICIT ANY` |
| `SignedData` | RFC 5652 §5 | 版本、摘要算法、封装内容、证书、CRL、签名者信息 |

**不包含**：验签、摘要计算、解密、证书链校验、吊销状态查询、属性语义解析。`ANY` 与属性集合只返回原始 TLV，密码学语义由调用方按 OID 二次解析。

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
| `asn1_cms_signed_data_certificate_subject` / `_issuer` / `_serial` | 仅证书分支：`TBSCertificate` 的 subject/issuer 原始 TLV、serialNumber 十进制文本 |
| `asn1_cms_signed_data_crl_count` / `_at` | CRL 条目数；每项分支判别（`ASN1_CMS_REVOCATION_CHOICE_*`）+ 原始 TLV |
| `asn1_cms_signed_data_signer_count` | `signerInfos` 条目数 |
| `asn1_cms_signed_data_signer_version` | `SignerInfo.version` 原值 |
| `asn1_cms_signed_data_signer_sid_choice` / `_sid_issuer` / `_sid_serial` / `_sid_subject_key_identifier` | `sid` 分支判别与对应字段 |
| `asn1_cms_signed_data_signer_digest_algorithm` | `digestAlgorithm` OID + `parameters` 原始 TLV |
| `asn1_cms_signed_data_signer_signed_attrs` / `_unsigned_attrs` | `[0]` / `[1]` IMPLICIT 属性集合的完整 TLV（含标签） |
| `asn1_cms_signed_data_signer_signature_algorithm` | `signatureAlgorithm` OID + `parameters` 原始 TLV |
| `asn1_cms_signed_data_signer_signature` / `_tlv` | `signature` OCTET STRING 内容字节 / 完整 TLV |

缺省字段（detached 的 `eContent`、无证书/CRL、无 `signedAttrs`/`unsignedAttrs`）返回 `ASN1_OK` 且 `NULL/0`；下标越界返回 `ASN1_E_INVALID_ARG`。

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
- 同时纳入差分（OpenSSL `asn1parse` 逐样本对照）与 fuzz 语料。

## 状态

0.1.0：ContentInfo / SignedData 只读字段访问；6 组 C 用例（attached、detached、最小样本、多证书、两种 sid 分支、负例）在 MinGW（GCC 13.2，`-Werror`）下构建与 ctest 通过。
