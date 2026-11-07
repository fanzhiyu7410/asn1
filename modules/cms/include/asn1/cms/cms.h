/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-cms 公共头文件（RFC 5652 ContentInfo / SignedData 只读结构访问）。
 *
 * 本模块承载 RFC 5652 第 12.1 节展平模块生成的描述表，并自包含复制
 * SignedData 可达的 PKIX 类型（见 asn1/reconciliation.md）。只读语义：
 * 不验签、不计算摘要、不解密、不校验证书链；ANY 与属性集合只返回原始
 * TLV，密码学语义由调用方按 OID 二次解析。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asn1_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASN1_CMS_CMS_H_INCLUDED
#define ASN1_CMS_CMS_H_INCLUDED

/* 由 CMake 从 project(asn1-cms VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asn1/cms/cms_version.h>

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_build.h>
#include <asn1/asn1_encode.h>
#include <asn1/asn1_node.h>

#if defined(ASN1_CMS_STATIC)
#define ASN1_CMS_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASN1_CMS_BUILDING_LIBRARY)
#define ASN1_CMS_API __declspec(dllexport)
#else
#define ASN1_CMS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASN1_CMS_API __attribute__((visibility("default")))
#else
#define ASN1_CMS_API
#endif

/* CertificateChoices 分支判别值（与 RFC 5652 备选顺序一致）。 */
#define ASN1_CMS_CERT_CHOICE_CERTIFICATE 0
#define ASN1_CMS_CERT_CHOICE_EXTENDED 1
#define ASN1_CMS_CERT_CHOICE_V1_ATTR_CERT 2
#define ASN1_CMS_CERT_CHOICE_V2_ATTR_CERT 3
#define ASN1_CMS_CERT_CHOICE_OTHER 4

/* SignerIdentifier 分支判别值。 */
#define ASN1_CMS_SID_ISSUER_AND_SERIAL 0
#define ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER 1

/* RevocationInfoChoice 分支判别值。 */
#define ASN1_CMS_REVOCATION_CHOICE_CRL 0
#define ASN1_CMS_REVOCATION_CHOICE_OTHER 1

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asn1_cms_content_info asn1_cms_content_info_t;
typedef struct asn1_cms_signed_data asn1_cms_signed_data_t;

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASN1_CMS_API const char *asn1_cms_version_string(void);

/* ------------------------------------------------------------------------- */
/* ContentInfo（RFC 5652 第 3 节）                                            */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 ContentInfo。
 *
 * - 使用模块随包发布的描述表加载 schema，并以 DER 严格模式解码；
 * - 输入被复制进文档 arena，调用方可在 open 返回后释放 der；
 * - 成功时 *out_info 非 NULL；失败时置 NULL 并返回核心错误码；
 * - 空参返回 ASN1_E_INVALID_ARG；分配失败返回 ASN1_E_NOMEM。
 */
ASN1_CMS_API asn1_err_t asn1_cms_content_info_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_cms_content_info_t **out_info);

/* 关闭句柄；info == NULL 为空操作。 */
ASN1_CMS_API void asn1_cms_content_info_close(
    asn1_cms_content_info_t *info);

/* contentType：OID 点分十进制文本（借用句柄）。 */
ASN1_CMS_API asn1_err_t asn1_cms_content_info_content_type(
    const asn1_cms_content_info_t *info, const char **out_dotted,
    size_t *out_size);

/*
 * content：`[0] EXPLICIT ANY` 内层的完整原始 TLV（含 tag/len，借用句柄），
 * 即被封装结构的 DER，可直接交给对应的 open 函数（如 SignedData）。
 * 外层 `[0]` 包装不包含在返回值内。
 */
ASN1_CMS_API asn1_err_t asn1_cms_content_info_content(
    const asn1_cms_content_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* ------------------------------------------------------------------------- */
/* SignedData（RFC 5652 第 5 节）                                              */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 SignedData（不含外层 ContentInfo）。只读结构。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_cms_signed_data_t **out_signed_data);

ASN1_CMS_API void asn1_cms_signed_data_close(
    asn1_cms_signed_data_t *signed_data);

/* version：原样返回 CMSVersion 整数值，不做范围校验。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_version(
    const asn1_cms_signed_data_t *signed_data, int64_t *out_version);

/* digestAlgorithms（SET OF AlgorithmIdentifier）条目数。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_digest_algorithm_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count);

/*
 * 按下标访问 digestAlgorithms 条目：algorithm OID 点分十进制 + parameters
 * 完整原始 TLV。parameters 缺省时返回 ASN1_OK 且 *out_parameters = NULL、
 * *out_parameters_size = 0。index 越界返回 ASN1_E_INVALID_ARG。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_digest_algorithm_at(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/* encapContentInfo.eContentType：OID 点分十进制文本（借用句柄）。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_encap_content_type(
    const asn1_cms_signed_data_t *signed_data, const char **out_dotted,
    size_t *out_size);

/*
 * encapContentInfo.eContent：OCTET STRING 内容字节（不含 tag/len）。
 * detached 场景字段缺省：返回 ASN1_OK 且 NULL/0。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_encap_content(
    const asn1_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size);

/* eContent 字段完整 TLV（OCTET STRING，含 tag/len）；缺省 NULL/0。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_encap_content_tlv(
    const asn1_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size);

/* certificates（CertificateSet）条目数；字段缺省时为 0。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_certificate_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count);

/*
 * 按下标判别并返回证书条目：
 * - *out_choice 为 ASN1_CMS_CERT_CHOICE_*；
 * - *out_tlv 为该分支的完整原始 TLV（含 tag/len），借用句柄；
 * - index 越界返回 ASN1_E_INVALID_ARG。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_certificate_at(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size);

/*
 * 仅对 ASN1_CMS_CERT_CHOICE_CERTIFICATE 分支有效：返回 TBSCertificate
 * 中 subject / issuer 的完整原始 TLV。其他分支或越界返回
 * ASN1_E_INVALID_ARG。不做链校验，也不解析 RDN 内容。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_certificate_subject(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

ASN1_CMS_API asn1_err_t asn1_cms_signed_data_certificate_issuer(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* 仅证书分支：serialNumber 大整数严格十进制文本（借用句柄）。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_certificate_serial(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size);

/* crls（RevocationInfoChoices）条目数；字段缺省时为 0。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_crl_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count);

/*
 * 按下标判别并返回 crls 条目：*out_choice 为
 * ASN1_CMS_REVOCATION_CHOICE_CRL 或 ASN1_CMS_REVOCATION_CHOICE_OTHER；
 * *out_tlv 为完整原始 TLV。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_crl_at(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size);

/* signerInfos 条目数。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count);

/* SignerInfo.version：原样返回整数值。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_version(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int64_t *out_version);

/*
 * signerInfos[index].sid 分支判别：ASN1_CMS_SID_ISSUER_AND_SERIAL 或
 * ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_sid_choice(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int *out_choice);

/* sid 为 issuerAndSerialNumber 时的 issuer 完整原始 TLV。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_sid_issuer(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* sid 为 issuerAndSerialNumber 时的 serialNumber 十进制文本。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_sid_serial(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size);

/* sid 为 issuerAndSerialNumber 时的 serialNumber 完整原始 TLV。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_sid_serial_tlv(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* sid 为 subjectKeyIdentifier 时的内容字节（不含 tag/len）。 */
ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_sid_subject_key_identifier(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* SignerInfo.digestAlgorithm：OID 与 parameters（ANY 原始 TLV）。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_digest_algorithm(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/*
 * SignerInfo.signedAttrs：`[0] IMPLICIT SET OF Attribute` 的完整原始 TLV
 * （含 [0] 标签）；缺省时返回 ASN1_OK 且 NULL/0。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_signed_attrs(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* SignerInfo.signatureAlgorithm：OID 与 parameters（ANY 原始 TLV）。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_signature_algorithm(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size);

/* SignerInfo.signature：OCTET STRING 内容字节（不含 tag/len）。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_signature(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* SignerInfo.signature：OCTET STRING 完整 TLV。 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_signature_tlv(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/*
 * SignerInfo.unsignedAttrs：`[1] IMPLICIT SET OF Attribute` 的完整原始
 * TLV（含 [1] 标签）；缺省时返回 ASN1_OK 且 NULL/0。
 */
ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_unsigned_attrs(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size);

/* ------------------------------------------------------------------------- */
/* 结构构造（写）：ContentInfo / SignedData builder                            */
/* ------------------------------------------------------------------------- */

/*
 * 只做结构构造与 DER 编码：证书/CRL 原始 DER、算法 OID、eContent、签名值、
 * 属性集合等全部由调用方给值，模块原样承载。不做签名生成、摘要计算、
 * 加密/解密、证书链校验、时间与随机数生成。
 *
 * 责任边界：
 * - CMSVersion 由调用方通过 asn1_cms_builder_set_version 显式给出，模块不
 *   推导、不校验范围；
 * - signedAttrs / unsignedAttrs 原样承载：输入必须是完整、规范的
 *   `SET OF` TLV（外层 `0x31`），集合非空且每个元素为 `SEQUENCE`
 *   （Attribute）；模块只把外层标签改写为 `0xA0`（signedAttrs）或
 *   `0xB1`（unsignedAttrs），长度字节与内容逐字节不变，不重建、不排序。
 *   签名覆盖的是 SET OF 编码，调用方必须对同一份字节签名，否则验签失败；
 * - certificates / crls 校验“恰好一个完整规范 DER TLV”与分支根标签
 *   （证书 SEQUENCE 或 [0..3]；CRL SEQUENCE 或 other [1]），不解析内部、
 *   不做信任判断；输出按 DER `SET OF` 规则排序。
 *
 * 生命周期：create 建立句柄，逐项设置/追加，encode 编码到调用方缓冲，
 * destroy 释放。destroy(NULL) 与重复 destroy 安全；句柄没有全局状态。
 * 所有输入字节在调用返回时已复制进模块内存，调用方可立即释放原缓冲。
 */

typedef struct asn1_cms_builder asn1_cms_builder_t;

/* 创建/销毁 builder。create 失败时 *out_builder 置 NULL。 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_create(
    asn1_ctx_t *ctx, asn1_cms_builder_t **out_builder);

ASN1_CMS_API void asn1_cms_builder_destroy(asn1_cms_builder_t *builder);

/*
 * 设置 CMSVersion（SignedData.version）。必填，重复设置返回
 * ASN1_E_INVALID_STATE。值原样写入，不推导、不校验范围。
 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_set_version(
    asn1_cms_builder_t *builder, int64_t version);

/*
 * 追加 digestAlgorithms 条目（至少一条）。oid 为点分十进制；params 为
 * 可选的完整 DER TLV（为空表示 parameters 缺省）。
 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_add_digest_algorithm(
    asn1_cms_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size);

/* 设置 encapContentInfo.eContentType OID。必填，重复设置返回 INVALID_STATE。 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_set_econtent_type(
    asn1_cms_builder_t *builder, const char *oid);

/*
 * 设置 encapContentInfo.eContent。econtent 必须是完整 DER OCTET STRING TLV
 * （tag 0x04）；模块取其中的内容字节。不设置即 detached。重复设置返回
 * ASN1_E_INVALID_STATE。
 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_set_econtent(
    asn1_cms_builder_t *builder, const uint8_t *econtent, size_t econtent_size);

/*
 * 追加证书 / CRL：各为恰好一个完整、规范的 DER TLV。除单 TLV 与规范性
 * 校验外，还检查分支根标签：证书须为 Certificate 的 SEQUENCE 或
 * CertificateChoices 的 [0..3] 备选；CRL 须为 CertificateList 的
 * SEQUENCE 或 RevocationInfoChoice 的 other [1]。模块不解析内部字段；
 * 输出按 DER SET OF 排序。
 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_add_certificate(
    asn1_cms_builder_t *builder, const uint8_t *tlv, size_t tlv_size);

ASN1_CMS_API asn1_err_t asn1_cms_builder_add_crl(
    asn1_cms_builder_t *builder, const uint8_t *tlv, size_t tlv_size);

/*
 * 追加 SignerInfo（至少一条）。
 *
 * sid_kind = ASN1_CMS_SID_ISSUER_AND_SERIAL：
 *   sid1 = issuer Name 的完整 DER TLV（须为 SEQUENCE），sid2 =
 *   serialNumber 的完整 DER TLV（须为 INTEGER）；两者都必须完整规范。
 * sid_kind = ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER：
 *   sid1 = subjectKeyIdentifier 内容字节（不含 tag/len），sid2 必须为空。
 *
 * digest_params / signature_params 为空表示 parameters 缺省，否则为完整
 * DER TLV。signed_attrs_tlv / unsigned_attrs_tlv 为空表示缺省，否则为
 * 非空 SET OF Attribute（外层 0x31，元素为 SEQUENCE），按上文规则原样
 * 承载并改写外层标签；根标签不符返回 ASN1_E_INVALID_VALUE。
 * signature 为 OCTET STRING 内容字节。
 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_add_signer(
    asn1_cms_builder_t *builder, int64_t version, int32_t sid_kind,
    const uint8_t *sid1, size_t sid1_size, const uint8_t *sid2,
    size_t sid2_size, const char *digest_oid, const uint8_t *digest_params,
    size_t digest_params_size, const uint8_t *signed_attrs_tlv,
    size_t signed_attrs_size, const char *signature_oid,
    const uint8_t *signature_params, size_t signature_params_size,
    const uint8_t *signature, size_t signature_size,
    const uint8_t *unsigned_attrs_tlv, size_t unsigned_attrs_size);

/*
 * 组装并编码 ContentInfo（contentType = id-signedData）。
 *
 * 成功时 out_buf 由上下文分配，调用方用 asn1_buf_release 归还；失败时
 * out_buf 清零且不产出半成品。必填项缺失（version / digestAlgorithm /
 * eContentType / signer）返回 ASN1_E_INVALID_STATE。
 */
ASN1_CMS_API asn1_err_t asn1_cms_builder_encode(
    const asn1_cms_builder_t *builder, asn1_buf_t *out_buf);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_CMS_CMS_H_INCLUDED */
