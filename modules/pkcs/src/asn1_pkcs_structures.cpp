/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 第一切片的只读结构访问。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码
 *       PrivateKeyInfo / EncryptedPrivateKeyInfo / RSAPublicKey /
 *       RSAPrivateKey，并把结构字段投影为核心节点/值。
 * 边界：不解密、不做 RSA 运算、不做填充/签名/加密、不校验签名；
 *       ANY 字段只返回原始 TLV。
 * 依赖：只使用核心公共 C ABI；生成表由 asn1c 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 * 线程：模块没有全局可变状态；不同句柄/上下文互不影响。同一 ctx 的
 *       并发使用需由调用方加锁（核心错误状态挂在 ctx 上）。
 */

#include "asn1/pkcs/pkcs.h"

#include "pkcs_handle.h"

using pkcs_internal::algorithmOid;
using pkcs_internal::algorithmParameters;
using pkcs_internal::bigintField;
using pkcs_internal::closeStructure;
using pkcs_internal::field;
using pkcs_internal::handle_base;
using pkcs_internal::nestedField;
using pkcs_internal::octetsField;
using pkcs_internal::openStructure;
using pkcs_internal::requireField;
using pkcs_internal::tlvField;

/* ------------------------------------------------------------------------- */
/* PKCS#8 PrivateKeyInfo                                                      */
/* ------------------------------------------------------------------------- */

struct asn1_pkcs_private_key_info : handle_base {};

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_private_key_info_t **out_info)
{
    return openStructure(ctx, der, der_size, pkcs8PrivateKeyInfoTable(),
                         out_info);
}

extern "C" ASN1_PKCS_API void asn1_pkcs_private_key_info_close(
    asn1_pkcs_private_key_info_t *info)
{
    closeStructure(info);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_version(
    const asn1_pkcs_private_key_info_t *info, int64_t *out_version)
{
    if (info == nullptr || out_version == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(info, "version", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_int64(node, out_version);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_private_key_info_algorithm_oid(
    const asn1_pkcs_private_key_info_t *info, const char **out_dotted,
    size_t *out_size)
{
    if (info == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return algorithmOid(info, "privateKeyAlgorithm", out_dotted, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_private_key_info_algorithm_parameters(
    const asn1_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return algorithmParameters(info, "privateKeyAlgorithm", out_data,
                               out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_private_key_info_private_key(
    const asn1_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return octetsField(info, "privateKey", out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_private_key_info_private_key_tlv(
    const asn1_pkcs_private_key_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return tlvField(info, "privateKey", out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_private_key_info_attribute_count(
    const asn1_pkcs_private_key_info_t *info, size_t *out_count)
{
    if (info == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *attributes = field(info, "attributes");
    *out_count = (attributes == nullptr) ? 0 : asn1_node_child_count(attributes);
    return ASN1_OK;
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_private_key_info_attribute_at(
    const asn1_pkcs_private_key_info_t *info, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asn1_node_t **out_values)
{
    if (info == nullptr || out_type_oid == nullptr ||
        out_type_oid_size == nullptr || out_values == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_type_oid = nullptr;
    *out_type_oid_size = 0;
    *out_values = nullptr;

    const asn1_node_t *attributes = field(info, "attributes");
    if (attributes == nullptr || index >= asn1_node_child_count(attributes)) {
        return ASN1_E_INVALID_ARG;
    }

    const asn1_node_t *attribute = asn1_node_child_at(attributes, index);
    if (attribute == nullptr) {
        return ASN1_E_INVALID_STATE;
    }

    const asn1_node_t *type = asn1_node_child_by_name(attribute, "type");
    if (type == nullptr) {
        type = asn1_node_child_at(attribute, 0);
    }
    const asn1_node_t *values = asn1_node_child_by_name(attribute, "values");
    if (values == nullptr) {
        values = asn1_node_child_at(attribute, 1);
    }
    if (type == nullptr || values == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }

    asn1_err_t status =
        asn1_node_get_oid(type, out_type_oid, out_type_oid_size);
    if (status != ASN1_OK) {
        return status;
    }
    *out_values = values;
    return ASN1_OK;
}

/* ------------------------------------------------------------------------- */
/* PKCS#8 EncryptedPrivateKeyInfo                                             */
/* ------------------------------------------------------------------------- */

struct asn1_pkcs_encrypted_private_key_info : handle_base {};

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_encrypted_private_key_info_t **out_info)
{
    return openStructure(ctx, der, der_size,
                         pkcs8EncryptedPrivateKeyInfoTable(), out_info);
}

extern "C" ASN1_PKCS_API void asn1_pkcs_encrypted_private_key_info_close(
    asn1_pkcs_encrypted_private_key_info_t *info)
{
    closeStructure(info);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_algorithm_oid(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const char **out_dotted, size_t *out_size)
{
    if (info == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return algorithmOid(info, "encryptionAlgorithm", out_dotted, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_algorithm_parameters(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return algorithmParameters(info, "encryptionAlgorithm", out_data,
                               out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_encrypted_data(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return octetsField(info, "encryptedData", out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_encrypted_private_key_info_encrypted_data_tlv(
    const asn1_pkcs_encrypted_private_key_info_t *info,
    const uint8_t **out_data, size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return tlvField(info, "encryptedData", out_data, out_size);
}

/* ------------------------------------------------------------------------- */
/* PKCS#1 RSAPublicKey / RSAPrivateKey                                        */
/* ------------------------------------------------------------------------- */

struct asn1_pkcs_rsa_public_key : handle_base {};

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_public_key_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_rsa_public_key_t **out_key)
{
    return openStructure(ctx, der, der_size, pkcs1RsaPublicKeyTable(),
                         out_key);
}

extern "C" ASN1_PKCS_API void asn1_pkcs_rsa_public_key_close(
    asn1_pkcs_rsa_public_key_t *key)
{
    closeStructure(key);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_public_key_modulus(
    const asn1_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "modulus", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_rsa_public_key_public_exponent(
    const asn1_pkcs_rsa_public_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "publicExponent", out_decimal, out_size);
}

struct asn1_pkcs_rsa_private_key : handle_base {};

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_rsa_private_key_t **out_key)
{
    return openStructure(ctx, der, der_size, pkcs1RsaPrivateKeyTable(),
                         out_key);
}

extern "C" ASN1_PKCS_API void asn1_pkcs_rsa_private_key_close(
    asn1_pkcs_rsa_private_key_t *key)
{
    closeStructure(key);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_version(
    const asn1_pkcs_rsa_private_key_t *key, int64_t *out_version)
{
    if (key == nullptr || out_version == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(key, "version", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_int64(node, out_version);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_modulus(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "modulus", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_rsa_private_key_public_exponent(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "publicExponent", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_rsa_private_key_private_exponent(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "privateExponent", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_prime1(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "prime1", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_prime2(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "prime2", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_exponent1(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "exponent1", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_exponent2(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "exponent2", out_decimal, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_rsa_private_key_coefficient(
    const asn1_pkcs_rsa_private_key_t *key, const char **out_decimal,
    size_t *out_size)
{
    if (key == nullptr || out_decimal == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return bigintField(key, "coefficient", out_decimal, out_size);
}

/* ------------------------------------------------------------------------- */
/* PKCS#10 CertificationRequest                                               */
/* ------------------------------------------------------------------------- */

namespace {

const asn1_node_t *crInfoChild(const handle_base *request,
                               const char *name) noexcept
{
    const asn1_node_t *info = field(request, "certificationRequestInfo");
    if (info == nullptr) {
        return nullptr;
    }
    return asn1_node_child_by_name(info, name);
}

asn1_err_t requireCrInfoChild(const handle_base *request, const char *name,
                              const asn1_node_t **out_node) noexcept
{
    const asn1_node_t *node = crInfoChild(request, name);
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_node = node;
    return ASN1_OK;
}

asn1_err_t nodeOid(const asn1_node_t *node, const char **out_dotted,
                   size_t *out_size) noexcept
{
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    return asn1_node_get_oid(node, out_dotted, out_size);
}

/* ANY 参数缺省时按“无参数”返回 ASN1_OK + NULL/0。 */
asn1_err_t nodeParameters(const asn1_node_t *node, const uint8_t **out_data,
                          size_t *out_size) noexcept
{
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASN1_OK;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

/* BIT STRING 位字节；中心只读结构，不使用 bit_length/unused 输出。 */
asn1_err_t nodeBitString(const asn1_node_t *node, const uint8_t **out_data,
                         size_t *out_size) noexcept
{
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    size_t bit_length = 0;
    uint8_t unused_bits = 0;
    return asn1_node_get_bits(node, out_data, out_size, &bit_length,
                              &unused_bits);
}

asn1_err_t nodeTlv(const asn1_node_t *node, const uint8_t **out_data,
                   size_t *out_size) noexcept
{
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

} // namespace

struct asn1_pkcs_certification_request : handle_base {};

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_pkcs_certification_request_t **out_request)
{
    return openStructure(ctx, der, der_size, pkcs10CertificationRequestTable(),
                         out_request);
}

extern "C" ASN1_PKCS_API void asn1_pkcs_certification_request_close(
    asn1_pkcs_certification_request_t *request)
{
    closeStructure(request);
}

extern "C" ASN1_PKCS_API asn1_err_t asn1_pkcs_certification_request_version(
    const asn1_pkcs_certification_request_t *request, int64_t *out_version)
{
    if (request == nullptr || out_version == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireCrInfoChild(request, "version", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_int64(node, out_version);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_der(
    const asn1_pkcs_certification_request_t *request, const uint8_t **out_data,
    size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireCrInfoChild(request, "subject", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeTlv(node, out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
    const asn1_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size)
{
    if (request == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *spki = nullptr;
    asn1_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASN1_OK) {
        return status;
    }
    const asn1_node_t *algorithm = asn1_node_child_by_name(spki, "algorithm");
    const asn1_node_t *oid =
        (algorithm == nullptr)
            ? nullptr
            : asn1_node_child_by_name(algorithm, "algorithm");
    return nodeOid(oid, out_dotted, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *spki = nullptr;
    asn1_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASN1_OK) {
        return status;
    }
    const asn1_node_t *algorithm = asn1_node_child_by_name(spki, "algorithm");
    const asn1_node_t *parameters =
        (algorithm == nullptr)
            ? nullptr
            : asn1_node_child_by_name(algorithm, "parameters");
    return nodeParameters(parameters, out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *spki = nullptr;
    asn1_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeBitString(asn1_node_child_by_name(spki, "subjectPublicKey"),
                         out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_subject_public_key_tlv(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *spki = nullptr;
    asn1_err_t status = requireCrInfoChild(request, "subjectPKInfo", &spki);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeTlv(asn1_node_child_by_name(spki, "subjectPublicKey"), out_data,
                   out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_attribute_count(
    const asn1_pkcs_certification_request_t *request, size_t *out_count)
{
    if (request == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *attributes = crInfoChild(request, "attributes");
    *out_count =
        (attributes == nullptr) ? 0 : asn1_node_child_count(attributes);
    return ASN1_OK;
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_attribute_at(
    const asn1_pkcs_certification_request_t *request, size_t index,
    const char **out_type_oid, size_t *out_type_oid_size,
    const asn1_node_t **out_values)
{
    if (request == nullptr || out_type_oid == nullptr ||
        out_type_oid_size == nullptr || out_values == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_type_oid = nullptr;
    *out_type_oid_size = 0;
    *out_values = nullptr;

    const asn1_node_t *attributes = crInfoChild(request, "attributes");
    if (attributes == nullptr || index >= asn1_node_child_count(attributes)) {
        return ASN1_E_INVALID_ARG;
    }

    const asn1_node_t *attribute = asn1_node_child_at(attributes, index);
    if (attribute == nullptr) {
        return ASN1_E_INVALID_STATE;
    }

    const asn1_node_t *type = asn1_node_child_by_name(attribute, "type");
    if (type == nullptr) {
        type = asn1_node_child_at(attribute, 0);
    }
    const asn1_node_t *values = asn1_node_child_by_name(attribute, "values");
    if (values == nullptr) {
        values = asn1_node_child_at(attribute, 1);
    }
    if (type == nullptr || values == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }

    asn1_err_t status =
        asn1_node_get_oid(type, out_type_oid, out_type_oid_size);
    if (status != ASN1_OK) {
        return status;
    }
    *out_values = values;
    return ASN1_OK;
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_algorithm_oid(
    const asn1_pkcs_certification_request_t *request, const char **out_dotted,
    size_t *out_size)
{
    if (request == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *algorithm = nullptr;
    asn1_err_t status =
        requireField(request, "signatureAlgorithm", &algorithm);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeOid(asn1_node_child_by_name(algorithm, "algorithm"), out_dotted,
                   out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_algorithm_parameters(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *algorithm = nullptr;
    asn1_err_t status =
        requireField(request, "signatureAlgorithm", &algorithm);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeParameters(asn1_node_child_by_name(algorithm, "parameters"),
                          out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_value(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(request, "signature", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeBitString(node, out_data, out_size);
}

extern "C" ASN1_PKCS_API asn1_err_t
asn1_pkcs_certification_request_signature_value_tlv(
    const asn1_pkcs_certification_request_t *request,
    const uint8_t **out_data, size_t *out_size)
{
    if (request == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(request, "signature", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return nodeTlv(node, out_data, out_size);
}
