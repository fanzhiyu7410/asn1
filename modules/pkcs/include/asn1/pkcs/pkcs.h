/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 公共头文件（第一切片：PKCS#8 + PKCS#1 只读结构访问）。
 *
 * 本模块承载 RFC 5208（PKCS#8）与 RFC 8017 Appendix A（PKCS#1）展平模块
 * 生成的描述表。只读语义：不解密、不做 RSA 运算、不做填充/签名/加密，
 * 也不校验任何签名；ANY 字段只返回原始 TLV，由调用方按 OID 二次解析。
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

#ifdef __cplusplus
}
#endif

#endif /* ASN1_PKCS_PKCS_H_INCLUDED */
