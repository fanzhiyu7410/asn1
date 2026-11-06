# PKCS 展平模块类型级对账表

对账口径：以 RFC 5208（2008-05，PKCS#8）、RFC 8017（2016-11，PKCS#1 Appendix A）与 RFC 2986（2000-11，PKCS#10）原文为基准，逐类型比对展平模块中的定义。

- 输出文件：`PKCS8-Flattened-5208.asn1`、`PKCS1-Flattened-8017.asn1`、`PKCS10-Flattened-2986.asn1`。
- 统计：PKCS#8 文件 8 个类型定义（6 个来自 RFC 5208，2 个为展平补齐的引用类型）；PKCS#1 文件 3 个类型定义；PKCS#10 文件 11 个类型定义（6 个来自 RFC 2986，5 个为展平补齐的引用类型）。
- 状态含义：
  - **原样**：名称、字段、顺序、标签、约束均不变。
  - **补齐**：原模块通过 `IMPORTS` 引用，展平后写入本模块的类型。
  - **替换**：开放类型字段改写为 `ANY`（保留完整原始 TLV），结构位置不变。
- 本切片不做密码学语义：不解密、不做 RSA 运算与填充、不验签。

## 1. RFC 5208（PKCS#8）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `PrivateKeyInfo` | `PrivateKeyInfo` | 原样 | `version`、`privateKeyAlgorithm`、`privateKey`、`[0] IMPLICIT attributes OPTIONAL` 均不变 |
| 2 | `Version` | `Version` | 原样 | `INTEGER` |
| 3 | `PrivateKey` | `PrivateKey` | 原样 | `OCTET STRING` |
| 4 | `Attributes` | `Attributes` | 原样 | `SET OF Attribute` |
| 5 | `EncryptedPrivateKeyInfo` | `EncryptedPrivateKeyInfo` | 原样 | `encryptionAlgorithm`、`encryptedData` 不变 |
| 6 | `EncryptedData` | `EncryptedData` | 原样 | `OCTET STRING` |
| 7 | `AlgorithmIdentifier`（RFC 5280 导入） | `AlgorithmIdentifier` | 补齐 + 替换 | 补齐为本模块 `SEQUENCE`；`parameters` 由随算法变化的开放类型改为 `ANY OPTIONAL` |
| 8 | `Attribute`（RFC 2985/PKCS#9 导入） | `Attribute` | 补齐 + 替换 | 补齐为 `SEQUENCE { type OBJECT IDENTIFIER, values SET SIZE (1..MAX) OF ANY }`；`values` 的成员类型改为 `ANY` |

## 2. RFC 8017 Appendix A（PKCS#1）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `RSAPublicKey` | `RSAPublicKey` | 原样 | `modulus INTEGER`、`publicExponent INTEGER` |
| 2 | `RSAPrivateKey` | `RSAPrivateKey` | 原样 | `version`、`modulus`、`publicExponent`、`privateExponent`、`prime1`、`prime2`、`exponent1`、`exponent2`、`coefficient` 字段顺序不变 |
| 3 | `Version` | `Version` | 原样 | `INTEGER { two-prime(0), multi(1) }` |

## 3. RFC 2986（PKCS#10）

| # | 原类型名 | 输出类型名 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `CertificationRequest` | `CertificationRequest` | 原样 | `certificationRequestInfo`、`signatureAlgorithm`、`signature` 字段顺序不变 |
| 2 | `CertificationRequestInfo` | `CertificationRequestInfo` | 原样 | `version`、`subject`、`subjectPKInfo`、`[0] IMPLICIT attributes` 不变 |
| 3 | `Version` | `Version` | 语法调整 | 原版 `INTEGER { v1(0) } (v1,...)`；扩展标记不影响 DER，省略 |
| 4 | `Name`（X.501/PKCS#9 导入） | `Name` | 补齐 + 语法调整 | 原版为 `CHOICE { rdnSequence RDNSequence }`，只有单一选择项，展平为 `Name ::= RDNSequence`，DER 等价 |
| 5 | `RDNSequence`（X.501） | `RDNSequence` | 补齐 | `SEQUENCE OF RelativeDistinguishedName` |
| 6 | `RelativeDistinguishedName`（X.501） | `RelativeDistinguishedName` | 补齐 | `SET SIZE (1..MAX) OF AttributeTypeAndValue` |
| 7 | `AttributeTypeAndValue`（X.501） | `AttributeTypeAndValue` | 补齐 + 替换 | 值字段为开放类型，展平为 `value ANY`（完整原始 TLV） |
| 8 | `SubjectPublicKeyInfo` | `SubjectPublicKeyInfo` | 原样 | `algorithm`、`subjectPublicKey` 不变 |
| 9 | `Attributes` | `Attributes` | 原样 | `SET OF Attribute` |
| 10 | `Attribute` | `Attribute` | 替换 | `values SET SIZE (1..MAX) OF ANY`（成员类型为开放类型） |
| 11 | `AlgorithmIdentifier`（RFC 5280 导入） | `AlgorithmIdentifier` | 补齐 + 替换 | `parameters` 改为 `ANY OPTIONAL` |

## 4. 未纳入的类型与理由

| 类型/内容 | 理由 |
| --- | --- |
| RFC 5208 中的 `Attributes` 之外的 PKCS#9 属性定义（`PKCS9Attribute` 等） | 本切片只读 `Attributes` 的通用结构，不展开具体属性值；`values` 以 `ANY` 保留原始 TLV |
| RFC 8017 中的算法标识、填充参数结构、`AlgorithmIdentifier` 的算法特定参数 | PKCS#1 模块只读密钥结构；填充参数如需读取，由调用方按 OID 从 `ANY` 原始 TLV 二次解析 |
| PKCS#8 v2（RFC 5958）的版本语义 | 不改变 `PrivateKeyInfo`/`EncryptedPrivateKeyInfo` 字段结构；本切片按 RFC 5208 生成，后续需要时单独评估 |
| PKCS#10 的具体属性值语义（`extensionRequest` 等 PKCS#9 属性） | CSR 只读通用 `Attribute` 结构；具体属性值由调用方按 `type` OID 从 `values` 的 ANY 二次解析 |
| PKCS#10 的签名校验与公钥算法语义 | 模块只读结构，不验签、不做密码学运算；`subjectPublicKey` 的算法解释由调用方完成 |

## 5. 验证

- 6 张描述表均由 `asn1c` 从上述展平模块生成，`--root` 分别为 `PrivateKeyInfo`、`EncryptedPrivateKeyInfo`、`RSAPublicKey`、`RSAPrivateKey`、`CertificationRequest`、`CertificationRequestInfo`。
- `-DASN1_PKCS_REGENERATE_TABLE=ON` 重新生成后与检入产物逐字节比对；差异即构建失败。
- 真实样本覆盖：PKCS#8 RSA 明文、PKCS#8 RSA-PSS（参数为 `SEQUENCE`）、加密 PKCS#8（PBES2）、PKCS#1 公钥与私钥、RSA CSR 与 EC CSR。
