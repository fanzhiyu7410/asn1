# asn1-pkcs 展平 ASN.1 模块

本目录存放 `asn1-pkcs` 第一切片使用的**自包含展平模块**。`asn1c` 只接受这类输入，不使用 `IMPORTS`，也不做参数化实例化。

## 文件

| 文件 | 对应标准 | 内容 |
| --- | --- | --- |
| `PKCS8-Flattened-5208.asn1` | RFC 5208（PKCS#8） | `PrivateKeyInfo`、`EncryptedPrivateKeyInfo` 及其引用类型 |
| `PKCS1-Flattened-8017.asn1` | RFC 8017 Appendix A（PKCS#1） | `RSAPublicKey`、`RSAPrivateKey` |
| `reconciliation.md` | — | 与原版模块的逐类型对账表 |
| `reference/rfc5208/rfc5208.txt` | RFC 5208 原文 | 只作参考，不参与构建 |
| `reference/rfc8017/rfc8017.txt` | RFC 8017 原文 | 只作参考，不参与构建 |

原文下载自 `https://www.rfc-editor.org/rfc/rfc5208.txt` 与 `https://www.rfc-editor.org/rfc/rfc8017.txt`，获取日期 2026-11-06。

## 展平规则

1. 去掉 `IMPORTS`：`AlgorithmIdentifier`（RFC 5280）与 `Attribute`（RFC 2985/X.501）直接写入本模块。
2. 开放类型字段改为 `ANY`，只保留完整原始 TLV：`AlgorithmIdentifier.parameters`、`Attribute.values`。
3. 不改类型名、字段名、字段顺序、`OPTIONAL` 与标签模式；模块默认 `IMPLICIT TAGS`，`attributes` 显式写为 `[0] IMPLICIT`。
4. 不做密码学语义：本模块不解密、不做 RSA 运算、不做填充/签名/加密，也不校验任何签名。

## 版本说明

- RFC 5208 已被 RFC 5958 更新；RFC 5958 把 `Version` 明确为 `v1(0)`/`v2(1)`，`PrivateKeyInfo`/`EncryptedPrivateKeyInfo` 的字段结构不变。本切片按 RFC 5208 原文结构生成，后续需要 v2 语义时单独评估。
- 未发现改变上述类型结构的已确认勘误；如后续核对到，先在 `reconciliation.md` 登记再改模块。

## 描述表生成

第一切片有 4 个顶层结构，而 `asn1c` 每张表只接受一个 `--root`，因此从同一展平模块生成 4 张表：

| 表 | 输入 | `--root` |
| --- | --- | --- |
| `pkcs8_private_key_info_schema.bin/.h` | `PKCS8-Flattened-5208.asn1` | `PrivateKeyInfo` |
| `pkcs8_encrypted_private_key_info_schema.bin/.h` | 同上 | `EncryptedPrivateKeyInfo` |
| `pkcs1_rsa_public_key_schema.bin/.h` | `PKCS1-Flattened-8017.asn1` | `RSAPublicKey` |
| `pkcs1_rsa_private_key_schema.bin/.h` | 同上 | `RSAPrivateKey` |

命令示例：

```powershell
asn1c -o modules/pkcs/generated/pkcs8_private_key_info_schema.bin `
      -c modules/pkcs/generated/pkcs8_private_key_info_schema.h `
      --root PrivateKeyInfo modules/pkcs/asn1/PKCS8-Flattened-5208.asn1
```

产物检入 `modules/pkcs/generated/`，默认构建不需要 `asn1c`。`-DASN1_PKCS_REGENERATE_TABLE=ON` 时构建期重新生成并逐字节比对，差异即构建失败。

生成头中的数组符号由模块名派生（同一模块的 4 张表符号相同），在 C++ 中为内部链接；模块用 4 个独立编译单元各包含一张表，避免符号冲突。

## 对账

类型级对账见 [reconciliation.md](reconciliation.md)。修改展平模块或重新生成表时，必须同时更新对账表并保持两者一致。
