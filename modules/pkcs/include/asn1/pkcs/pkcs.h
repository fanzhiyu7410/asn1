/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 公共头文件（PKCS#8 + PKCS#1 + PKCS#10 + PKCS#12 只读结构访问）。
 *
 * 本模块承载 RFC 5208（PKCS#8）、RFC 8017 Appendix A（PKCS#1）、RFC 2986
 * （PKCS#10）与 RFC 7292（PKCS#12）展平模块生成的描述表。只读语义：不解密、
 * 不做 RSA 运算、不做填充/签名/加密、不做口令密钥派生，也不校验任何签名或
 * MAC；ANY 字段只返回原始 TLV，由调用方按 OID 二次解析。
 *
 * 生命周期：句柄由 open 创建、close 销毁；内部文档与 schema 随句柄创建
 * 和销毁。句柄借用调用方的 asn1_ctx_t，ctx 必须比句柄存活更久。所有由
 * 访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASN1_PKCS_PKCS_H_INCLUDED
#define ASN1_PKCS_PKCS_H_INCLUDED

/* 由 CMake 从 project(asn1-pkcs VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asn1/pkcs/pkcs_version.h>

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_build.h>
#include <asn1/asn1_node.h>

#if defined(ASN1_PKCS_STATIC)
#define ASN1_PKCS_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASN1_PKCS_BUILDING_LIBRARY)
#define ASN1_PKCS_API __declspec(dllexport)
#else
#define ASN1_PKCS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASN1_PKCS_API __attribute__((visibility("default")))
#else
#define ASN1_PKCS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明句柄；具体布局属于模块私有实现。 */
typedef struct asn1_pkcs_private_key_info asn1_pkcs_private_key_info_t;
typedef struct asn1_pkcs_encrypted_private_key_info
    asn1_pkcs_encrypted_private_key_info_t;
typedef struct asn1_pkcs_rsa_public_key asn1_pkcs_rsa_public_key_t;
typedef struct asn1_pkcs_rsa_private_key asn1_pkcs_rsa_private_key_t;
typedef struct asn1_pkcs_certification_request
    asn1_pkcs_certification_request_t;

/* PKCS#12（RFC 7292）句柄；均为不透明类型。 */
typedef struct asn1_pkcs12_pfx asn1_pkcs12_pfx_t;
typedef struct asn1_pkcs12_authenticated_safe
    asn1_pkcs12_authenticated_safe_t;
typedef struct asn1_pkcs12_safe_contents asn1_pkcs12_safe_contents_t;
typedef struct asn1_pkcs12_cert_bag asn1_pkcs12_cert_bag_t;

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASN1_PKCS_API const char *asn1_pkcs_version_string(void);

/* ------------------------------------------------------------------------- */
/* PKCS#8 PrivateKeyInfo（RFC 5208 第 5 节）                                  */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 PrivateKeyInfo。
 *
 * - 使用模块随包发布的描述表加载 schema，并以 DER 严格模式解码；
 * - 输入被复制进文档 arena，调用方可在 open 返回后释放 der；
 * - 成功时 *out_info 非 NULL；失败时置 NULL 并返回核心错误码；
 * - 空参返回 ASN1_E_INVALID_ARG；分配失败返回 ASN1_E_NOMEM。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_private_key_info_t **out_info);

/* 关闭句柄；info == NULL 为空操作。 */
ASN1_PKCS_API void asn1_pkcs_private_key_info_close(
    asn1_pkcs_private_key_info_t *info);

/* version 字段（RFC 5208 为 INTEGER；常见值 0）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_version(
    const asn1_pkcs_private_key_info_t *info, int64_t *out_version);

/* privateKeyAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_algorithm_oid(
    const asn1_pkcs_private_key_info_t *info, const char **out_dotted,
    size_t *out_size);

/*
 * privateKeyAlgorithm.parameters：ANY 原始 TLV（含 tag/len）。
 * 字段缺省时返回 ASN1_OK，且 *out_data = NULL、*out_size = 0。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_algorithm_parameters(
    const asn1_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* privateKey：OCTET STRING 内容字节（不含 tag/len，借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_private_key(
    const asn1_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* privateKey 字段完整 TLV（含 tag/len，借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_private_key_tlv(
    const asn1_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size);

/* attributes 中的属性个数；字段缺省时为 0。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_attribute_count(
    const asn1_pkcs_private_key_info_t *info, size_t *out_count);

/*
 * 按下标访问 Attribute：type OID 点分十进制 + values（SET OF ANY）借用节点。
 * index 越界返回 ASN1_E_INVALID_ARG；attributes 缺省且 count = 0。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_attribute_at(
    const asn1_pkcs_private_key_info_t *info, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asn1_node_t **out_values);

/* ------------------------------------------------------------------------- */
/* PKCS#8 EncryptedPrivateKeyInfo（RFC 5208 附录 A）                          */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 EncryptedPrivateKeyInfo；只读结构，不解密。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_encrypted_private_key_info_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_encrypted_private_key_info_t **out_info);

ASN1_PKCS_API void asn1_pkcs_encrypted_private_key_info_close(
    asn1_pkcs_encrypted_private_key_info_t *info);

/* encryptionAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_algorithm_oid(
    const asn1_pkcs_encrypted_private_key_info_t *info, const char **out_dotted,
    size_t *out_size);

/* encryptionAlgorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_algorithm_parameters(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size);

/* encryptedData：OCTET STRING 内容字节（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_encrypted_data(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size);

/* encryptedData 字段完整 TLV（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_encrypted_data_tlv(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size);

/* ------------------------------------------------------------------------- */
/* PKCS#1 RSAPublicKey / RSAPrivateKey（RFC 8017 Appendix A）                 */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 RSAPublicKey；只读结构，不做 RSA 运算。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_public_key_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_rsa_public_key_t **out_key);

ASN1_PKCS_API void asn1_pkcs_rsa_public_key_close(
    asn1_pkcs_rsa_public_key_t *key);

/* modulus（n）：大整数严格十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_public_key_modulus(
    const asn1_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size);

/* publicExponent（e）：大整数严格十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_public_key_public_exponent(
    const asn1_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size);

/* 打开 DER 编码的 RSAPrivateKey；只读结构，不做 RSA 运算。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_rsa_private_key_t **out_key);

ASN1_PKCS_API void asn1_pkcs_rsa_private_key_close(
    asn1_pkcs_rsa_private_key_t *key);

/* version（two-prime = 0、multi = 1）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_version(
    const asn1_pkcs_rsa_private_key_t *key, int64_t *out_version);

/* 以下均为大整数严格十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_modulus(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_public_exponent(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_private_exponent(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_prime1(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_prime2(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_exponent1(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_exponent2(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);
ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_coefficient(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size);

/* ------------------------------------------------------------------------- */
/* PKCS#10 CertificationRequest（RFC 2986 4.2）                              */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 CertificationRequest。
 *
 * 只读结构：不验证 signatureValue，也不对 certificationRequestInfo 做任何
 * 密码学处理；attributes 只按通用结构给出类型 OID 与 ANY 值节点。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_certification_request_t **out_request);

/* 关闭句柄；request == NULL 为空操作。 */
ASN1_PKCS_API void asn1_pkcs_certification_request_close(
    asn1_pkcs_certification_request_t *request);

/*
 * certificationRequestInfo.version。
 *
 * RFC 2986 只定义 v1 = 0；非 0 属不常见但合法的 DER 输入，不应视为错误。
 * 本函数采取“返回成功、原样给出值”：不做范围校验，也不把非 0 静默改写
 * 为 0；调用方需要判断 v1 时自行比较 *out_version == 0。模块不为此发
 * 告警（核心未提供模块侧告警写入接口），也不额外引入错误码。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_version(
    const asn1_pkcs_certification_request_t *request,
    int64_t *out_version);

/* certificationRequestInfo.subject 完整 DER TLV（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_subject_der(
    const asn1_pkcs_certification_request_t *request, const uint8_t **out_data,
    size_t *out_size);

/* subjectPKInfo.algorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
    const asn1_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size);

/* subjectPKInfo.algorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* subjectPKInfo.subjectPublicKey：BIT STRING 位字节（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* subjectPKInfo.subjectPublicKey 字段完整 TLV（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key_tlv(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* certificationRequestInfo.attributes 中的属性个数；空集合为 0。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_attribute_count(
    const asn1_pkcs_certification_request_t *request, size_t *out_count);

/*
 * 按下标访问 Attribute：type OID 点分十进制 + values（SET OF ANY）借用节点。
 * index 越界返回 ASN1_E_INVALID_ARG。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_attribute_at(
    const asn1_pkcs_certification_request_t *request, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asn1_node_t **out_values);

/* signatureAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_algorithm_oid(
    const asn1_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size);

/* signatureAlgorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_algorithm_parameters(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* signature：BIT STRING 位字节（借用于句柄，不解码、不验签）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_signature_value(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* signature 字段完整 TLV（借用句柄）。 */
ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_value_tlv(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size);

/* ------------------------------------------------------------------------- */
/* PKCS#12 PFX（RFC 7292）                                                    */
/* ------------------------------------------------------------------------- */

/*
 * PKCS#12 切片只做结构访问：不解密 SafeContents、不验 MAC、不做口令密钥
 * 派生。加密内容（EncryptedData / EncryptedPrivateKeyInfo）只作为原始 TLV
 * 给出，解密与后续解析由调用方完成。
 */

/*
 * 打开 DER 编码的 PFX（RFC 7292 附录 D）。
 *
 * 输入被复制进文档 arena，调用方可在 open 返回后释放 der；失败时
 * *out_pfx 置 NULL 并返回核心错误码。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs12_pfx_t **out_pfx);

/* 关闭句柄；pfx == NULL 为空操作。 */
ASN1_PKCS_API void asn1_pkcs12_pfx_close(asn1_pkcs12_pfx_t *pfx);

/*
 * PFX.version。RFC 7292 只定义 v3 = 3；非 3 的输入按原值返回，不在解码期
 * 被值名约束拒绝。需要判断 v3 时由调用方比较 *out_version == 3。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_version(
    const asn1_pkcs12_pfx_t *pfx, int64_t *out_version);

/* authSafe.contentType：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_auth_safe_content_type(
    const asn1_pkcs12_pfx_t *pfx, const char **out_dotted,
    size_t *out_size);

/*
 * authSafe.content 的内层完整 TLV（含 tag/len，借用句柄）。
 *
 * 常见形态：contentType = data 时为包住 AuthenticatedSafe DER 的 OCTET
 * STRING；口令加密时为 encryptedData 的 SEQUENCE。模块不递归解析，也不
 * 剥去 OCTET STRING 的 tag/len。content 缺省时返回 ASN1_OK + NULL/0。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_auth_safe_content_tlv(
    const asn1_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData 是否存在：1 存在、0 缺省。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_mac_present(
    const asn1_pkcs12_pfx_t *pfx, int *out_present);

/* 以下 mac* 访问器在 macData 缺省时返回 ASN1_E_SCHEMA_FIELD。 */

/* macData.mac.digestAlgorithm.algorithm：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_mac_digest_algorithm_oid(
    const asn1_pkcs12_pfx_t *pfx, const char **out_dotted,
    size_t *out_size);

/* macData.mac.digestAlgorithm.parameters：ANY 原始 TLV；缺省返回 NULL/0。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_mac_digest_algorithm_parameters(
    const asn1_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData.mac.digest：OCTET STRING 内容字节（借用句柄，不验 MAC）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_mac_digest(
    const asn1_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/* macData.macSalt：OCTET STRING 内容字节（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_mac_salt(
    const asn1_pkcs12_pfx_t *pfx, const uint8_t **out_data,
    size_t *out_size);

/*
 * macData.iterations。字段缺省时按 DEFAULT 1 返回 1；不改变文档内容。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_pfx_mac_iterations(
    const asn1_pkcs12_pfx_t *pfx, int64_t *out_iterations);

/* ------------------------------------------------------------------------- */
/* PKCS#12 AuthenticatedSafe（RFC 7292：SEQUENCE OF ContentInfo）             */
/* ------------------------------------------------------------------------- */

/*
 * 打开 DER 编码的 AuthenticatedSafe。
 *
 * 调用方通常先从 PFX.authSafe.content 的 OCTET STRING 中取出内容字节
 *（contentType = data），或解密 encryptedData 后得到该 DER。模块只做结构
 * 解码，不区分来源。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_authenticated_safe_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs12_authenticated_safe_t **out_safe);

ASN1_PKCS_API void asn1_pkcs12_authenticated_safe_close(
    asn1_pkcs12_authenticated_safe_t *safe);

/* ContentInfo 个数。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_authenticated_safe_content_count(
    const asn1_pkcs12_authenticated_safe_t *safe, size_t *out_count);

/*
 * 按下标访问 ContentInfo：contentType OID + content 内层完整 TLV。
 *
 * contentType 常见值：data（1.2.840.113549.1.7.1，明文 SafeContents 装在
 * OCTET STRING 中）、encryptedData（1.2.840.113549.1.7.6，口令加密）、
 * envelopedData（1.2.840.113549.1.7.3，公钥加密）。content 缺省时
 * *out_content 为 NULL、*out_content_size 为 0。index 越界返回
 * ASN1_E_INVALID_ARG。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_authenticated_safe_content_at(
    const asn1_pkcs12_authenticated_safe_t *safe, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const uint8_t **out_content, size_t *out_content_size);

/* ------------------------------------------------------------------------- */
/* PKCS#12 SafeContents / SafeBag（RFC 7292）                                 */
/* ------------------------------------------------------------------------- */

/* 打开已解密的 DER 编码 SafeContents（SEQUENCE OF SafeBag）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_safe_contents_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs12_safe_contents_t **out_contents);

ASN1_PKCS_API void asn1_pkcs12_safe_contents_close(
    asn1_pkcs12_safe_contents_t *contents);

/* SafeBag 个数。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_safe_contents_bag_count(
    const asn1_pkcs12_safe_contents_t *contents, size_t *out_count);

/*
 * 按下标访问 SafeBag。
 *
 * - bagId：OID 点分十进制文本（借用句柄）。常见值：
 *   keyBag 1.2.840.113549.1.12.10.1.1、
 *   pkcs8ShroudedKeyBag 1.2.840.113549.1.12.10.1.2、
 *   certBag 1.2.840.113549.1.12.10.1.3、
 *   crlBag 1.2.840.113549.1.12.10.1.4、
 *   secretBag 1.2.840.113549.1.12.10.1.5、
 *   safeContentsBag 1.2.840.113549.1.12.10.1.6。
 * - bagValue：bagValue [0] EXPLICIT 内层完整 TLV（含 tag/len）。keyBag 为
 *   PrivateKeyInfo，pkcs8ShroudedKeyBag 为 EncryptedPrivateKeyInfo，certBag
 *   为 CertBag；未知 bagId 同样原样返回。
 * - attribute_count：bagAttributes 的元素数；字段缺省时为 0。
 *
 * index 越界返回 ASN1_E_INVALID_ARG。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_safe_contents_bag_at(
    const asn1_pkcs12_safe_contents_t *contents, size_t index,
    const char **out_bag_id_oid, size_t *out_bag_id_oid_size,
    const uint8_t **out_bag_value_tlv, size_t *out_bag_value_tlv_size,
    size_t *out_attribute_count);

/*
 * 按下标访问 SafeBag 中的 PKCS12Attribute：attrId OID + attrValues 节点
 *（SET OF ANY，借用句柄）。bag_index 或 attribute_index 越界返回
 * ASN1_E_INVALID_ARG。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_safe_contents_bag_attribute_at(
    const asn1_pkcs12_safe_contents_t *contents, size_t bag_index,
    size_t attribute_index, const char **out_attr_id_oid,
    size_t *out_attr_id_oid_size, const asn1_node_t **out_values);

/* ------------------------------------------------------------------------- */
/* PKCS#12 CertBag（RFC 7292）                                                */
/* ------------------------------------------------------------------------- */

/* 打开 DER 编码的 CertBag；通常取自 SafeBag.bagValue。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_cert_bag_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs12_cert_bag_t **out_bag);

ASN1_PKCS_API void asn1_pkcs12_cert_bag_close(asn1_pkcs12_cert_bag_t *bag);

/* certId：OID 点分十进制文本（借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_cert_bag_cert_id(
    const asn1_pkcs12_cert_bag_t *bag, const char **out_dotted,
    size_t *out_size);

/* certValue [0] EXPLICIT 内层完整 TLV（含 tag/len，借用句柄）。 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_cert_bag_cert_value_tlv(
    const asn1_pkcs12_cert_bag_t *bag, const uint8_t **out_data,
    size_t *out_size);

/*
 * X.509 证书字节：仅 certId = x509Certificate
 *（1.2.840.113549.1.9.22.1）且 certValue 内层为 OCTET STRING 时返回其
 * 内容字节（即证书 DER，借用句柄）。其他 certId（如 sdsiCertificate）返回
 * ASN1_E_UNSUPPORTED，调用方仍可用 cert_value_tlv 取得原始 TLV。
 */
ASN1_PKCS_API asn1_err_t asn1_pkcs12_cert_bag_certificate(
    const asn1_pkcs12_cert_bag_t *bag, const uint8_t **out_data,
    size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_PKCS_PKCS_H_INCLUDED */
