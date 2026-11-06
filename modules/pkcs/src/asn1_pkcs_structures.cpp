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

#include <asn1/asn1_schema.h>

#include "pkcs_tables.h"

#include <cstdlib>

namespace {

constexpr uint32_t kPkcsFormatVersion = 1u << 16;

/* 四个句柄共享的字段；派生句柄以它为第一个成员。 */
struct handle_base {
    asn1_ctx_t *ctx;
    asn1_schema_t *schema;
    asn1_doc_t *doc;
    const asn1_node_t *root;
};

template <typename T>
asn1_err_t openStructure(asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
                         pkcs_table_view table, T **out_object) noexcept
{
    if (ctx == nullptr || der == nullptr || der_size == 0 ||
        out_object == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_object = nullptr;

    asn1_schema_table_t schema_table;
    schema_table.struct_size = sizeof(schema_table);
    schema_table.data = table.data;
    schema_table.size = table.size;
    schema_table.format_version = kPkcsFormatVersion;
    schema_table.reserved = 0;

    asn1_schema_t *schema = nullptr;
    asn1_err_t status = asn1_schema_load(ctx, &schema_table, &schema);
    if (status != ASN1_OK) {
        return status;
    }

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    options.flags = ASN1_DECODE_COPY_INPUT;

    asn1_doc_t *doc = nullptr;
    size_t consumed = 0;
    status = asn1_decode_buffer_with_schema(ctx, der, der_size, schema,
                                            &options, &doc, &consumed);
    if (status != ASN1_OK) {
        asn1_schema_destroy(schema);
        return status;
    }

    T *object = static_cast<T *>(std::malloc(sizeof(T)));
    if (object == nullptr) {
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
        return ASN1_E_NOMEM;
    }

    object->ctx = ctx;
    object->schema = schema;
    object->doc = doc;
    object->root = asn1_doc_root(doc);
    *out_object = object;
    return ASN1_OK;
}

void closeStructure(handle_base *object) noexcept
{
    if (object == nullptr) {
        return;
    }
    asn1_doc_destroy(object->doc);
    asn1_schema_destroy(object->schema);
    std::free(object);
}

/* 取顶层字段；调用方保证句柄与输出非空。 */
const asn1_node_t *field(const handle_base *object,
                         const char *name) noexcept
{
    return asn1_node_child_by_name(object->root, name);
}

/* 取顶层字段的两个层级，例如 privateKeyAlgorithm.algorithm。 */
const asn1_node_t *nestedField(const handle_base *object,
                               const char *container,
                               const char *name) noexcept
{
    const asn1_node_t *parent = field(object, container);
    if (parent == nullptr) {
        return nullptr;
    }
    return asn1_node_child_by_name(parent, name);
}

asn1_err_t requireField(const handle_base *object, const char *name,
                        const asn1_node_t **out_node) noexcept
{
    const asn1_node_t *node = field(object, name);
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_node = node;
    return ASN1_OK;
}

asn1_err_t algorithmOid(const handle_base *object, const char *container,
                        const char **out_dotted,
                        size_t *out_size) noexcept
{
    const asn1_node_t *node =
        nestedField(object, container, "algorithm");
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    return asn1_node_get_oid(node, out_dotted, out_size);
}

/*
 * ANY 参数：返回完整原始 TLV；字段缺省时按“无参数”返回 ASN1_OK + NULL/0，
 * 与 find 语义一致，避免调用方把 OPTIONAL 缺省当错误。
 */
asn1_err_t algorithmParameters(const handle_base *object,
                               const char *container,
                               const uint8_t **out_data,
                               size_t *out_size) noexcept
{
    const asn1_node_t *node = nestedField(object, container, "parameters");
    if (node == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASN1_OK;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

asn1_err_t bigintField(const handle_base *object, const char *name,
                       const char **out_decimal,
                       size_t *out_size) noexcept
{
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(object, name, &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_bigint_decimal(node, out_decimal, out_size);
}

asn1_err_t octetsField(const handle_base *object, const char *name,
                       const uint8_t **out_data,
                       size_t *out_size) noexcept
{
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(object, name, &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_octets(node, out_data, out_size);
}

asn1_err_t tlvField(const handle_base *object, const char *name,
                    const uint8_t **out_data, size_t *out_size) noexcept
{
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(object, name, &node);
    if (status != ASN1_OK) {
        return status;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

} // namespace

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
