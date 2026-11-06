# CMS 展平模块对账表（RFC 5652 → CMS-Flattened-5652）

本表逐类型记录 [CMS-Flattened-5652.asn1](CMS-Flattened-5652.asn1) 的来源、处理方式与代价。
对账基准：

- 结构来源：[reference/rfc5652/rfc5652.txt](reference/rfc5652/rfc5652.txt) 第 12.1 节（CryptographicMessageSyntax2004）。
- PKIX 类型来源：[../pkix/asn1/PKIX-Flattened-2009.asn1](../../pkix/asn1/PKIX-Flattened-2009.asn1)（由 RFC 5912 第 2、3、14 节展平）。
- 复制范围判据：**只复制从 `SignedData` 可达的类型**，不做整表搬运。

## 1. 总体处理

| 项 | 处理 | 代价 |
| --- | --- | --- |
| `IMPORTS` | 不保留任何 `IMPORTS`；把 `AlgorithmIdentifier`、`Certificate`、`CertificateList`、`CertificateSerialNumber`、`Name` 及其可达依赖复制进本模块 | 类型定义在 `asn1-pkix` 与 `asn1-cms` 中重复出现；两模块需各自维护，修改时须同步核对 |
| PKIX 类型范围 | 只带出 `SignedData` 可达子集（见第 3 节“未复制”清单） | `Certificate` 的结构化访问（subject/issuer/serial）可用；其余 PKIX 类型不进入本模块 |
| `CertificateChoices` 属性证书分支 | `v1AttrCert`、`v2AttrCert` 不展开 RFC 3281 结构，改为 `SEQUENCE { ... }` 不透明占位 | 调用方可按分支判别并取得完整原始 TLV，但不能结构化读取属性证书内部字段 |
| 开放类型 | `content`、`parameters`、`otherCert`、`otherRevInfo`、`attrValues`、`AttributeValue` 使用裸 `ANY` | 保留完整原始 TLV、原样写回；不能按 OID/类型自动展开，需调用方二次解析 |
| `CMSVersion` | 原版 `INTEGER { v0(0) ... v5(5) }` 改为无约束 `INTEGER` | 值名不参与结构访问；非 RFC 定义值也能按原值返回，不在解码期被值名约束拒绝 |
| 描述表粒度 | 同一模块按根 `ContentInfo`、`SignedData` 各生成一张表 | 两张表都包含整模块的类型记录（约 10 KB/张），存在重复；换取两个顶层结构可直接 open |

## 2. 逐类型对账

“原样”表示名称、字段、顺序、`OPTIONAL`/`DEFAULT`、标签与约束均与来源一致（仅去除来源模块的 `IMPORTS` 依赖）。

| # | 类型 | 来源 | 处理 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | `ContentInfo` | RFC 5652 §12.1 | 原样 | `content [0] EXPLICIT ANY` 保留显式标签 |
| 2 | `ContentType` | RFC 5652 §12.1 | 原样 | `OBJECT IDENTIFIER` |
| 3 | `SignedData` | RFC 5652 §12.1 | 原样 | `certificates [0] IMPLICIT`、`crls [1] IMPLICIT` 保留隐式标签 |
| 4 | `DigestAlgorithmIdentifiers` | RFC 5652 §12.1 | 原样 | `SET OF DigestAlgorithmIdentifier` |
| 5 | `DigestAlgorithmIdentifier` | RFC 5652 §12.1 | 原样 | 指向复制的 `AlgorithmIdentifier` |
| 6 | `EncapsulatedContentInfo` | RFC 5652 §12.1 | 原样 | `eContent [0] EXPLICIT OCTET STRING OPTIONAL` |
| 7 | `SignerInfos` | RFC 5652 §12.1 | 原样 | `SET OF SignerInfo` |
| 8 | `SignerInfo` | RFC 5652 §12.1 | 原样 | `signedAttrs [0] IMPLICIT`、`unsignedAttrs [1] IMPLICIT` 保留隐式标签 |
| 9 | `SignerIdentifier` | RFC 5652 §12.1 | 原样 | CHOICE：`issuerAndSerialNumber` / `subjectKeyIdentifier [0]` |
| 10 | `SignedAttributes` | RFC 5652 §12.1 | 原样 | `SET SIZE (1..MAX) OF Attribute` |
| 11 | `UnsignedAttributes` | RFC 5652 §12.1 | 原样 | 同上 |
| 12 | `Attribute` | RFC 5652 §12.1 | 原样 | `attrType` + `attrValues SET OF ANY` |
| 13 | `AttributeValue` | RFC 5652 §12.1 | 原样 | 裸 `ANY` |
| 14 | `SignatureValue` | RFC 5652 §12.1 | 原样 | `OCTET STRING` |
| 15 | `SignatureAlgorithmIdentifier` | RFC 5652 §12.1 | 原样 | 指向复制的 `AlgorithmIdentifier` |
| 16 | `SubjectKeyIdentifier` | RFC 5652 §12.1 | 原样 | `OCTET STRING`；PKIX1Implicit-2009 有同义类型，本模块只保留这一份 |
| 17 | `RevocationInfoChoices` | RFC 5652 §12.1 | 原样 | `SET OF RevocationInfoChoice` |
| 18 | `RevocationInfoChoice` | RFC 5652 §12.1 | 原样 | CHOICE：`crl` / `other [1] IMPLICIT` |
| 19 | `OtherRevocationInfoFormat` | RFC 5652 §12.1 | 原样 | `otherRevInfo ANY` |
| 20 | `CertificateChoices` | RFC 5652 §12.1 | 原样 | 5 个分支标签：`certificate` 0x30、`extendedCertificate` 0xA0、`v1AttrCert` 0xA1、`v2AttrCert` 0xA2、`other` 0xA3 |
| 21 | `CertificateSet` | RFC 5652 §12.1 | 原样 | `SET OF CertificateChoices` |
| 22 | `IssuerAndSerialNumber` | RFC 5652 §12.1 | 原样 | `issuer Name` + `serialNumber` |
| 23 | `CMSVersion` | RFC 5652 §12.1 | 语法调整 | 去值名与约束，改为无约束 `INTEGER`；见第 1 节 |
| 24 | `OtherCertificateFormat` | RFC 5652 §12.1 | 原样 | `otherCert ANY` |
| 25 | `AttributeCertificateV1` | RFC 5652 §12.1（引用 RFC 3281） | 占位 | `SEQUENCE { ... }`；不透明，仅原始 TLV 可用 |
| 26 | `AttributeCertificateV2` | RFC 5652 §12.1（引用 RFC 3281） | 占位 | 同上；源码中类型名为 `AttributeCertificateV2`，对应 RFC 5652 的 `AttributeCertificate` |
| 27 | `ExtendedCertificate` | RFC 5652 §12.1（废弃 PKCS #6） | 原样 | 结构完整保留（含内嵌 `Certificate`） |
| 28 | `ExtendedCertificateInfo` | RFC 5652 §12.1 | 原样 | `version` + `certificate` + `attributes` |
| 29 | `AlgorithmIdentifier` | PKIX 展平（RFC 5912） | 原样 | `parameters ANY OPTIONAL` |
| 30 | `Name` | PKIX 展平 | 原样 | 单分支 CHOICE `rdnSequence` |
| 31 | `RDNSequence` | PKIX 展平 | 原样 | `SEQUENCE OF RelativeDistinguishedName` |
| 32 | `RelativeDistinguishedName` | PKIX 展平 | 原样 | `SET SIZE (1..MAX) OF SingleAttribute` |
| 33 | `SingleAttribute` | PKIX 展平 | 原样 | `type` + `value ANY` |
| 34 | `Certificate` | PKIX 展平 | 原样 | `SIGNED-TBSCertificate` |
| 35 | `SIGNED-TBSCertificate` | PKIX 展平 | 原样 | RFC 5912 的 `SIGNED{TBSCertificate}` 已展开 |
| 36 | `TBSCertificate` | PKIX 展平 | 原样 | 含 `[0] EXPLICIT Version DEFAULT v1`、`[3] EXPLICIT Extensions` |
| 37 | `Version` | PKIX 展平 | 原样 | 命名 `INTEGER { v1(0), v2(1), v3(2) }`；解码期约束为 0..2 |
| 38 | `CertificateSerialNumber` | PKIX 展平 | 原样 | `INTEGER` |
| 39 | `Validity` | PKIX 展平 | 原样 | `notBefore` + `notAfter` |
| 40 | `Time` | RFC 5652 §12.1 与 PKIX 展平同名同构 | 保留一份 | RFC 5652 本地定义与 PKIX 定义逐字段相同；取 PKIX 版本，避免重名 |
| 41 | `UniqueIdentifier` | PKIX 展平 | 原样 | `BIT STRING` |
| 42 | `SubjectPublicKeyInfo` | PKIX 展平 | 原样 | `algorithm` + `subjectPublicKey` |
| 43 | `Extensions` | PKIX 展平 | 原样 | `SEQUENCE SIZE (1..MAX) OF Extension` |
| 44 | `Extension` | PKIX 展平 | 原样 | `extnID` + `critical DEFAULT FALSE` + `extnValue` |
| 45 | `CertificateList` | PKIX 展平 | 原样 | `SIGNED-TBSCertList` |
| 46 | `SIGNED-TBSCertList` | PKIX 展平 | 原样 | RFC 5912 的 `SIGNED{TBSCertList}` 已展开 |
| 47 | `TBSCertList` | PKIX 展平 | 原样 | 含匿名 `revokedCertificates` 与 `[0] EXPLICIT Extensions` |

合计 47 个类型级声明。

### 2.1 未复制（不在 `SignedData` 可达范围）

以下 PKIX 展平模块中的类型**没有**进入本模块，因此不能通过本模块 API 结构化读取：

`AttributeType`、`AttributeSet`、`DirectoryString`、`X520name`、`X520CommonName`、`X520LocalityName`、`X520StateOrProvinceName`、`X520OrganizationName`、`X520OrganizationalUnitName`、`X520Pseudonym`、`X520SerialNumber`、`X520Title`、`X520dnQualifier`、`X520countryName`、`EmailAddress`、`DomainComponent`、`EDIPartyName`、`OtherName`、`ORAddress`、`GeneralName`、`GeneralNames`、`AnotherName`、`CountryName`、`AdministrationDomainName`、`NetworkAddress`、`BuiltInStandardAttributes`、`BuiltInDomainDefinedAttributes`、`BuiltInDomainDefinedAttribute`、`ExtensionAttributes`、`ExtensionAttribute`、`PDSParameter`、`PresentationAddress`、`TeletexTerminalIdentifier`、`TeletexString`、`KeyUsage`、`KeyIdentifier`、`SubjectKeyIdentifier`（PKIX1Implicit 版本）、`AuthorityKeyIdentifier`、`PrivateKeyUsagePeriod`、`CertificatePolicies`、`PolicyInformation`、`PolicyMappings`、`SubjectAltName`、`IssuerAltName`、`SubjectDirectoryAttributes`、`BasicConstraints`、`NameConstraints`、`PolicyConstraints`、`ExtendedKeyUsage`、`CRLDistributionPoints`、`CRLNumber`、`CRLReason`、`FreshestCRL`、`InhibitAnyPolicy`、`AuthorityInfoAccessSyntax`、`SubjectInfoAccessSyntax`、`AttributeCertificate`、`AttributeCertificateInfo`、`Holder`、`AttCertIssuer`、`AttCertValidityPeriod`、`IssuingDistributionPoint`、`SecurityCategory`、`OTHER-NAME` 等。

这些类型的原始字节仍可能出现在 `certificates`、`crls`、`attributes` 等位置，但本模块按原始 TLV 返回，不做结构展开。`Name` 的 RDN `value ANY` 也不展开为 `DirectoryString`。

## 3. ANY 与标签模型

| 位置 | 标签模型 | 原始 TLV 含义 |
| --- | --- | --- |
| `ContentInfo.content [0] EXPLICIT ANY` | 显式：节点是 `[0]` 包装，内层是 ANY | API 返回内层 ANY 的完整 TLV（可直接交给 `SignedData` open） |
| `EncapsulatedContentInfo.eContent [0] EXPLICIT OCTET STRING` | 显式：节点是 `[0]` 包装，内层是 OCTET STRING | API 的 `_tlv` 返回 OCTET STRING 的完整 TLV，`_content` 返回其内容字节 |
| `SignerInfo.signedAttrs [0] IMPLICIT SET OF Attribute` | 隐式：节点本身就是 SET，标签 0xA0 | API 返回含 0xA0 的完整 TLV |
| `SignerInfo.unsignedAttrs [1] IMPLICIT SET OF Attribute` | 隐式：节点本身就是 SET，标签 0xA1 | API 返回含 0xA1 的完整 TLV |
| `SignedData.certificates [0] IMPLICIT SET OF CertificateChoices` | 隐式：节点本身就是 SET，标签 0xA0 | 逐项返回选择分支的完整 TLV |
| `SignedData.crls [1] IMPLICIT RevocationInfoChoices` | 隐式：节点本身就是 SET，标签 0xA1 | 逐项返回选择分支的完整 TLV |
| `AlgorithmIdentifier.parameters ANY OPTIONAL` | 无标签：节点就是 ANY 值 | API 返回 ANY 完整 TLV；缺省 NULL/0 |
| `Attribute.attrValues SET OF ANY` | 无标签：元素就是 ANY 值 | 本模块 API 不逐属性展开，调用方按 signedAttrs 原始 TLV 二次解析 |

所有隐式/显式标签均通过模块级 `DEFINITIONS IMPLICIT TAGS` 与源码中的显式 `EXPLICIT` 标注表达，没有为绕过 seal/标签校验新增临时特例。

## 4. 勘误核对

对 [reference/rfc5652/errata.html](reference/rfc5652/errata.html) 中的 6 条记录逐条核对：

| Errata ID | 状态 | 位置 | 是否影响本产出 | 处理 |
| --- | --- | --- | --- | --- |
| 6250 | Verified | §9.2 | 否 | 只涉及 MAC 输入/AuthAttributes 的文字说明，`SignedData` 结构不受影响 |
| 6546 | Verified | §12.1 | 否（说明性） | 指出 `AttributeCertificateV1` 的导入来源应为 §12.2；本产出不含 `IMPORTS`，属性证书分支本就是占位 |
| 7863 | Held for Document Update | §5.2 | 否 | `SignedData` 版本语义文字，不影响字段/标签 |
| 2026 | Held for Document Update | §5.3 | 否 | `SignerInfo` 文字说明，不影响字段/标签 |
| 3867 | Held for Document Update | §5.3 | 否 | 同上 |
| 5331 | Rejected | §6.1 | 否 | 未采纳 |

结论：没有需要改写的结构级勘误。

## 5. 校验方式

- `asn1c -o <bin> -c <h> --root ContentInfo|SignedData CMS-Flattened-5652.asn1` 均生成成功。
- 两张表由 `tests/cms/test_cms_structures.c` 在 Windows/MinGW 本地实测加载并解码 openssl 生成的 4 份 CMS 样本。
- `-DASN1_CMS_REGENERATE_TABLE=ON` 重新生成并与检入产物逐字节比对（目标 `asn1_cms_table_verify`）。
- 差分测试将 CMS 样本纳入 OpenSSL `asn1parse` 的偏移/层级/TLV 边界对照。
