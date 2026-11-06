# tests/data 测试材料

本目录存放零第三方 C 测试使用的真实 ASN.1 材料。所有 `.pem` / `.der` 由
`scripts/gen_test_data.py` 调用本机 `openssl` 生成；`*.h` 是同名 `.der` 的
C 数组表示，测试运行期不读文件。

## 来源与生成方式

- 生成脚本：`scripts/gen_test_data.py`（仅依赖 `openssl` 与 Python 标准库）。
- 生成命令：`python scripts/gen_test_data.py`。
- 本仓库快照使用 OpenSSL 3.5.9 生成。
- 只从已有 `.der` 重新生成头文件：`python scripts/gen_test_data.py --headers`。
- 只派生 PKCS#1 公私钥与加密 PKCS#8（不重新生成既有密钥）：
  `python scripts/gen_test_data.py --derived`。
- 只用已提交的证书/私钥生成 CMS SignedData 样本：
  `python scripts/gen_test_data.py --cms`。

| 文件 | 内容 |
| --- | --- |
| `key_rsa_pkcs8.pem/.der` | RSA-2048 私钥，PKCS#8，未加密 |
| `key_ec_pkcs8.pem/.der` | ECDSA P-256 私钥，PKCS#8，未加密 |
| `key_rsa_pss_pkcs8.pem/.der` | RSA-PSS 2048 私钥，PKCS#8，未加密 |
| `key_rsa_pkcs1_private.pem/.der` | RSA-2048 私钥，PKCS#1（传统格式） |
| `key_rsa_pkcs1_public.pem/.der` | RSA-2048 公钥，PKCS#1 `RSAPublicKey` |
| `key_rsa_pkcs8_encrypted.pem/.der` | RSA-2048 私钥，PKCS#8 `EncryptedPrivateKeyInfo`，PBES2 / AES-256-CBC，口令 `asn1-test` |
| `csr_rsa.pem/.der` | RSA-2048 证书请求（PKCS#10），SHA-256 |
| `csr_ec.pem/.der` | ECDSA P-256 证书请求（PKCS#10），SHA-256 |
| `cert_rsa_selfsigned.pem/.der` | RSA 自签名证书，SHA-256，含 basicConstraints/ SAN |
| `cert_ec_selfsigned.pem/.der` | ECDSA 自签名证书，SHA-256，含 basicConstraints/ SAN |
| `cert_rsa_pss_selfsigned.pem/.der` | RSA-PSS 自签名证书，SHA-256，AlgorithmIdentifier.parameters 为 SEQUENCE |
| `cms_rsa_attached.der` | CMS ContentInfo(SignedData)，attached，含 eContent、证书、signedAttrs |
| `cms_rsa_detached.der` | CMS ContentInfo(SignedData)，detached，无 eContent，含证书、signedAttrs |
| `cms_rsa_minimal.der` | CMS ContentInfo(SignedData) 最小样本，detached、无证书、无 signedAttrs |
| `cms_rsa_ec_multicert.der` | CMS ContentInfo(SignedData)，RSA + ECDSA 双签名者、多证书、attached |
| `cms_rsa_keyid.der` | CMS ContentInfo(SignedData)，SignerIdentifier 为 subjectKeyIdentifier |

## 重现性说明

- 密钥与签名含随机成分，重新生成得到的字节与仓库内已提交的版本**不同**；
  已提交的 `.der` / `.h` 是权威快照。
- 测试只校验“解码→编码逐字节一致”的自洽性，以及结构解析，不依赖固定字节，
  因此重新生成后重新运行测试仍然成立。
- 证书有效期从生成当天起 3650 天；测试不对具体时间做断言。
- CMS 样本的签名值（ECDSA 随机）与 signingTime 含随机/时间成分，重跑得到的
  字节与已提交快照不同；测试只读取结构字段（版本、OID、原始 TLV、计数），
  不对签名值或时间做断言。

## 变异样本

DER 严格校验的“反例”字节（非最短长度、BOOLEAN 0x01、INTEGER 前导零、
SET 乱序、时间缺秒、OID 非最短等）直接写在测试源码的字面量数组里，不进
本目录，便于就近阅读与定位。
