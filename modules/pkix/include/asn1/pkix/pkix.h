/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkix 公共头文件。
 *
 * 本模块承载 RFC 5912（PKIX1Explicit-2009 / PKIX1Implicit-2009 /
 * PKIX-CommonTypes-2009）展平模块生成的描述表与证书字段访问 API。
 * 来源、勘误与更新链见 docs/11-描述表格式.md 第 15 节；模块只依赖
 * 核心公共 C ABI，不包含核心私有头，也不复制核心解析逻辑。
 *
 * 生命周期：asn1_pkix_certificate_t 由 open 创建、close 销毁；内部文档与
 * schema 随句柄创建和销毁。句柄借用调用方的 asn1_ctx_t，ctx 必须比句柄
 * 存活更久。所有由访问器返回的指针均借用句柄，close 后立即失效。
 */

#ifndef ASN1_PKIX_PKIX_H_INCLUDED
#define ASN1_PKIX_PKIX_H_INCLUDED

/* 由 CMake 从 project(asn1-pkix VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asn1/pkix/pkix_version.h>

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_allocator.h>
#include <asn1/asn1_build.h>
#include <asn1/asn1_node.h>

#if defined(ASN1_PKIX_STATIC)
#define ASN1_PKIX_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASN1_PKIX_BUILDING_LIBRARY)
#define ASN1_PKIX_API __declspec(dllexport)
#else
#define ASN1_PKIX_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASN1_PKIX_API __attribute__((visibility("default")))
#else
#define ASN1_PKIX_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明证书句柄；具体布局属于模块私有实现。 */
typedef struct asn1_pkix_certificate asn1_pkix_certificate_t;

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASN1_PKIX_API const char *asn1_pkix_version_string(void);

/*
 * 打开一张 DER 编码的 X.509 证书。
 *
 * - 使用模块随包发布的 PKIX 描述表加载 schema，并以 DER 严格模式解码；
 * - 输入被复制进文档 arena，调用方可在 open 返回后释放 der；
 * - 成功时 *out_cert 非 NULL；失败时 *out_cert 置 NULL 并返回核心错误码
 *   （截断、非法 DER、不符合 Certificate schema 等）；
 * - 空参返回 ASN1_E_INVALID_ARG；分配失败返回 ASN1_E_NOMEM。
 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkix_certificate_t **out_cert);

/* 关闭证书句柄；cert == NULL 为空操作。 */
ASN1_PKIX_API void asn1_pkix_certificate_close(
    asn1_pkix_certificate_t *cert);

/*
 * 按路径取节点。路径以 '.' 分隔字段名，相对 Certificate 根；空串表示根。
 * 例："tbsCertificate.subject"、"tbsCertificate.validity.notBefore"、
 * "tbsCertificate.extensions"。
 *
 * - 命中时 *out_node 非 NULL，为文档借用；
 * - 路径不存在（含 DEFAULT/OPTIONAL 字段缺省）返回 ASN1_OK 且
 *   *out_node = NULL，不报错；
 * - 空参或路径为空段返回 ASN1_E_INVALID_ARG。
 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_find(
    const asn1_pkix_certificate_t *cert, const char *path,
    const asn1_node_t **out_node);

/*
 * 便捷访问器：签名算法 OID（点分十进制，借用句柄）。
 * 失败时不写任何输出；字段缺失返回 ASN1_E_SCHEMA_FIELD。
 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_signature_algorithm_oid(
    const asn1_pkix_certificate_t *cert, const char **out_dotted,
    size_t *out_size);

/*
 * 签名值 BIT STRING 原始内容：不含 unused-bits 首字节。
 * out_bit_length = out_size * 8 - out_unused_bits；借用句柄。
 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_signature_value(
    const asn1_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size, size_t *out_bit_length, uint8_t *out_unused_bits);

/* 证书序列号：大整数严格十进制文本（借用句柄）。 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_serial_number(
    const asn1_pkix_certificate_t *cert, const char **out_decimal,
    size_t *out_size);

/* 证书版本：0 = v1、1 = v2、2 = v3；DEFAULT v1 缺省时返回 0。 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_version(
    const asn1_pkix_certificate_t *cert, uint32_t *out_version);

/* issuer / subject 的完整原始 DER（含 tag/len，借用句柄）。 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_issuer_der(
    const asn1_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size);
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_subject_der(
    const asn1_pkix_certificate_t *cert, const uint8_t **out_data,
    size_t *out_size);

/*
 * 有效期起止时间（结构化）。两个 asn1_time_t 的 struct_size 必须由调用方
 * 初始化为 sizeof(asn1_time_t)；失败时不写部分输出。
 */
ASN1_PKIX_API asn1_err_t asn1_pkix_certificate_validity(
    const asn1_pkix_certificate_t *cert, asn1_time_t *out_not_before,
    asn1_time_t *out_not_after);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_PKIX_PKIX_H_INCLUDED */
