# asn1-pkcs

PKCS 系列标准结构模块（RFC 8017 / RFC 5208 / RFC 2986 / RFC 7292），以 `.asn1` 描述表驱动，只做**只读结构访问**。

## 模块范围

覆盖以下 9 个顶层结构：

| 结构 | 标准 | 说明 |
| --- | --- | --- |
| `PrivateKeyInfo` | RFC 5208 §5（PKCS#8） | 明文私钥信息 |
| `EncryptedPrivateKeyInfo` | RFC 5208 附录 A | 加密私钥信息 |
| `RSAPublicKey` | RFC 8017 附录 A（PKCS#1） | RSA 公钥 |
| `RSAPrivateKey` | RFC 8017 附录 A（PKCS#1） | RSA 私钥 |
| `CertificationRequest` | RFC 2986 §4.2（PKCS#10） | 证书请求（CSR） |
| `PFX` | RFC 7292 §4（PKCS#12） | 个人交换格式（含 `MacData`） |
| `AuthenticatedSafe` | RFC 7292 §4 | `SEQUENCE OF ContentInfo` |
| `SafeContents` | RFC 7292 §4 | `SEQUENCE OF SafeBag`，含属性 |
| `CertBag` | RFC 7292 附录 B.1 | 证书 bag（X.509 / SDSI） |

**不包含**：解密、口令处理/密钥派生、RSA 运算、填充/签名/加密、签名校验、MAC 计算与校验。`EncryptedPrivateKeyInfo` 只暴露加密算法与密文字节，不尝试解密；`CertificationRequest` 不验证 `signatureValue`，也不校验 CSR 内容；PKCS#12 的 `MacData` 只暴露字段，不校验 MAC 是否匹配；`EncryptedData` 内容不解密，`pkcs8ShroudedKeyBag` 也不解密。

后续规划：PKCS#7 归入 CMS 模块，不在本模块实现。

## 公共头与链接

- 公共头：`asn1/pkcs/pkcs.h`
- 链接目标：`asn1::pkcs::shared` 或 `asn1::pkcs::static`
- 构建开关：`-DASN1_BUILD_MODULE_PKCS=ON`

`asn1-pkcs` 是独立包，可独立安装后用 `find_package(asn1-pkcs CONFIG REQUIRED)` 消费。

### 符号前缀

- PKCS#1 / PKCS#8 / PKCS#10：`asn1_pkcs_*`（45 个，含 `asn1_pkcs_version_string`）。
- PKCS#12：`asn1_pkcs12_*`（25 个），自 0.1.0 起冻结的例外。
- 仓库中**不存在** `asn1_pkcs1_*`、`asn1_pkcs8_*`、`asn1_pkcs10_*` 三组前缀；新增 API 统一使用 `asn1_pkcs_`。未来若统一前缀，只能在 0.2.0 新增别名并保留 `asn1_pkcs12_*` 至少一个次版本周期，不重命名、不删除。

## 句柄与生命周期

9 个不透明句柄各由 `open` 创建、`close` 销毁：

- `asn1_pkcs_private_key_info_open` / `_close`
- `asn1_pkcs_encrypted_private_key_info_open` / `_close`
- `asn1_pkcs_rsa_public_key_open` / `_close`
- `asn1_pkcs_rsa_private_key_open` / `_close`
- `asn1_pkcs_certification_request_open` / `_close`
- `asn1_pkcs12_pfx_open` / `_close`
- `asn1_pkcs12_authenticated_safe_open` / `_close`
- `asn1_pkcs12_safe_contents_open` / `_close`
- `asn1_pkcs12_cert_bag_open` / `_close`

约束：

- `open` 接收 DER 字节并复制进内部文档 arena，返回后调用方可释放输入缓冲。
- 句柄借用调用方的 `asn1_ctx_t`，**ctx 必须比句柄存活更久**。
- 每次 `open` 加载一次描述表并构建上下文级 schema，生命周期到 `close`；无全局缓存、无进程级单例。
- 所有访问器返回的指针（OID 文本、大整数十进制文本、字节/TLV、节点）均**借用句柄**，`close` 后立即失效，不得释放。
- `close(NULL)` 为空操作；`open` 失败时 `*out_*` 置 `NULL` 并返回核心错误码。
- 模块无全局可变状态；不同句柄互不影响。同一 `ctx` 的并发使用需由调用方加锁。

## 最小示例

```c
#include <asn1/asn1.h>
#include <asn1/pkcs/pkcs.h>

asn1_ctx_config_t config;
asn1_ctx_config_init(&config);
asn1_ctx_t *ctx = NULL;
asn1_ctx_create(&config, &ctx);

asn1_pkcs_private_key_info_t *info = NULL;
if (asn1_pkcs_private_key_info_open(ctx, der, der_size, &info) == ASN1_OK) {
    const char *oid = NULL;
    size_t oid_size = 0;
    asn1_pkcs_private_key_info_algorithm_oid(info, &oid, &oid_size);
    /* oid / oid_size 借用 info */

    const uint8_t *key = NULL;
    size_t key_size = 0;
    /* privateKey 的 OCTET STRING 内容，可再用 PKCS#1 API 打开 */
    asn1_pkcs_private_key_info_private_key(info, &key, &key_size);

    asn1_pkcs_private_key_info_close(info);
}
asn1_ctx_destroy(ctx);
```

`PrivateKeyInfo.privateKey` 的内容通常是 PKCS#1 `RSAPrivateKey`，可直接交给 `asn1_pkcs_rsa_private_key_open` 再次解析（第二次打开会复制这段输入）。

## ANY 字段语义

`AlgorithmIdentifier.parameters` 与 `Attribute.values` 是开放类型，模块只返回**完整原始 TLV（含 tag/len）**，不按 OID 解释：

- `parameters` 缺省时返回 `ASN1_OK` 且 `*out_data = NULL`、`*out_size = 0`，调用方不应把缺省当错误。
- 调用方按 `algorithm_oid` 的结果自行二次解析参数，例如 RSA 的 `NULL`（`05 00`）或 RSA-PSS 的 `RSASSA-PSS-params`。
- `attribute_at` 返回 `type` OID 与 `values` 节点（`SET OF ANY`），节点内容同样借用句柄。

## CSR 版本语义

`asn1_pkcs_certification_request_version` 采取“返回成功、原样给值”：

- RFC 2986 只定义 `v1 = 0`，但非 0 是合法 DER 输入，不视为解析错误；
- 模块不做范围校验，也不把非 0 静默改写为 0；
- 需要断言 v1 的调用方自行比较 `*out_version == 0`；
- 模块不为此发告警（核心未提供模块侧告警写入接口），也不新增错误码。

## PKCS#12 结构语义

`PFX` 的 `authSafe` 是一个 `ContentInfo`；其 `content` 的完整原始 TLV 由 `asn1_pkcs12_pfx_auth_safe_content_tlv` 返回。按 RFC 7292，`contentType` 为 `data` 时内层是 `OCTET STRING`，其内容才是 `AuthenticatedSafe` 的 DER；模块不替调用方拆 OCTET STRING，也不解密 `encryptedData`。

- `asn1_pkcs12_authenticated_safe_content_at` 返回每个 `ContentInfo` 的 `contentType` OID 与 `content` 内层完整 TLV。`data` 分支的内层同样是 `OCTET STRING`，`encryptedData` 分支原样返回，模块不解密。
- `asn1_pkcs12_safe_contents_bag_at` 返回 `bagId` OID、`bagValue` 内层完整 TLV 与属性数量；`bag_attribute_at` 返回属性 OID 与 `attrValues` 节点（`SET OF ANY`）。调用方按 `bagId` 自行解码内层，例如交给 `asn1_pkcs_private_key_info_open` 或 `asn1_pkcs_encrypted_private_key_info_open`。
- `asn1_pkcs12_cert_bag_certificate` 只在 `certId` 为 `x509Certificate`（`1.2.840.113549.1.9.22.1`）时返回证书 DER；`sdsiCertificate` 等非 X.509 分支返回 `ASN1_E_UNSUPPORTED`，与 `AttributeCertificate` 的结构化访问约定一致。`cert_value_tlv` 始终返回原始内层 TLV。
- `MacData.iterations` 省略时按 RFC 7292 的 `DEFAULT 1` 返回 `1`；`macData` 整个缺省时 MAC 访问器返回 `ASN1_E_SCHEMA_FIELD`，`mac_present` 返回 `0`。模块不计算、不校验 MAC。
- `PFX.version` 原样返回，不做范围校验（与 CSR 版本语义一致）。

由于展平模块去掉了 `BAG-TYPE` / `CERT-TYPE` 等信息对象集约束，`SafeBag`、`CertBag` 与 `ContentInfo` 的形状在结构上相似：模块只校验 `bagId` / `certId` 是 `OBJECT IDENTIFIER`，不强制其取值；调用方应按 OID 解释内层内容。`SafeContents` 也可能接受结构上匹配的 `AuthenticatedSafe` 输入，这是只读结构访问的已知边界。

## 描述表来源与重生成

展平 ASN.1 源在 `modules/pkcs/asn1/`：

- `PKCS8-Flattened-5208.asn1`
- `PKCS1-Flattened-8017.asn1`
- `PKCS10-Flattened-2986.asn1`
- `PKCS12-Flattened-7292.asn1`

共 9 个顶层结构，而 `asn1c` 每张表只接受一个 `--root`，因此生成 10 张表（`CertificationRequestInfo` 额外作为根），产物检入 `modules/pkcs/generated/`（`.bin` + 描述头 `.h`）。默认构建不依赖 `asn1c`。

重新生成并逐字节校验：

```powershell
cmake -G Ninja -B build-regen -DASN1_BUILD_TOOLS=ON -DASN1_PKCS_REGENERATE_TABLE=ON
cmake --build build-regen --target asn1_pkcs_table_verify
```

`ASN1_PKCS_REGENERATE_TABLE=ON` 时用 `asn1c` 重新生成；`asn1_pkcs_table_verify` 把新产物与检入产物逐字节比对，任一差异或缺失即构建失败。生成细节与对账见 `modules/pkcs/asn1/README.md`。

## 依赖约束

- 只依赖核心公共 C ABI（`asn1` 核心库）与标准 C 库。
- **不依赖 asn1-pkix**，也不包含核心私有头或复制核心解析逻辑。
- 核心库不反向引用本模块；模块可独立构建、安装与消费。

## 状态

0.1.0：PKCS#8 明文/加密结构、PKCS#1 RSA 公私钥、PKCS#10 CSR 与 PKCS#12（PFX / AuthenticatedSafe / SafeContents / CertBag）的只读字段访问；包含 10 组 C 用例（明文 PKCS#8、RSA-PSS 参数缺省、加密 PKCS#8、RSA 公私钥、RSA/EC CSR、CSR 非 0 版本、CSR 负例、PKCS#8/PKCS#1 负例、PKCS#12 明文/加密/仅证书样本遍历、`MacData` DEFAULT 与 SDSI/负例），在 MinGW（GCC 13.2，`-Werror`）与 MSVC 下构建与 ctest 通过。
