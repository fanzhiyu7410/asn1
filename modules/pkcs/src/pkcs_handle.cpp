/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

#include "pkcs_handle.h"

#include <asn1/asn1_node.h>

#include <cstdlib>

namespace pkcs_internal {

void closeStructure(handle_base *object) noexcept
{
    if (object == nullptr) {
        return;
    }
    asn1_doc_destroy(object->doc);
    asn1_schema_destroy(object->schema);
    std::free(object);
}

const asn1_node_t *field(const handle_base *object,
                         const char *name) noexcept
{
    return asn1_node_child_by_name(object->root, name);
}

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

} // namespace pkcs_internal
