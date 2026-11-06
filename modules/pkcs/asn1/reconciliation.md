# PKCS 展平模块类型级对账表

对账口径：以 RFC 5208（2008-05，PKCS#8）与 RFC 8017（2016-11，PKCS#1 Appendix A）原文为基准，逐类型比对展平模块中的定义。

- 输出文件：`PKCS8-Flattened-5208.asn1`、`PKCS1-Flattened-8017.asn1`。
- 统计：PKCS#8 文件 8 个类型定义（6 个来自 RFC 5208，2 个为展平补齐的引用类型）；PKCS#1 文件 3 个类型定义。
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

## 3. 未纳入的类型与理由

| 类型/内容 | 理由 |
| --- | --- |
| RFC 5208 中的 `Attributes` 之外的 PKCS#9 属性定义（`PKCS9Attribute` 等） | 本切片只读 `Attributes` 的通用结构，不展开具体属性值；`values` 以 `ANY` 保留原始 TLV |
| RFC 8017 中的算法标识、填充参数结构、`AlgorithmIdentifier` 的算法特定参数 | PKCS#1 模块只读密钥结构；填充参数如需读取，由调用方按 OID 从 `ANY` 原始 TLV 二次解析 |
| PKCS#8 v2（RFC 5958）的版本语义 | 不改变 `PrivateKeyInfo`/`EncryptedPrivateKeyInfo` 字段结构；本切片按 RFC 5208 生成，后续需要时单独评估 |

## 4. 验证

- 4 张描述表均由 `asn1c` 从上述展平模块生成，`--root` 分别为 `PrivateKeyInfo`、`EncryptedPrivateKeyInfo`、`RSAPublicKey`、`RSAPrivateKey`。
- `-DASN1_PKCS_REGENERATE_TABLE=ON` 重新生成后与检入产物逐字节比对；差异即构建失败。
- 真实样本覆盖：PKCS#8 RSA 明文、PKCS#8 RSA-PSS（参数为 `SEQUENCE`）、加密 PKCS#8（PBES2）、PKCS#1 公钥与私钥。
