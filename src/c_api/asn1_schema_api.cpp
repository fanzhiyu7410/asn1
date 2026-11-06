/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 的 C ABI 边界：句柄校验与内部 schema 接口转发。
 *
 * 职责：把公共句柄转换为内部 Schema，并在入口完成空指针/魔数校验。
 * 依赖：schema/asn1_schema.h、core/asn1_context.h。
 */

#include <asn1/asn1.h>

#include <cstring>

#include "core/asn1_context.h"
#include "schema/asn1_schema.h"

namespace {

asn1::Context *contextOf(asn1_ctx_t *handle) noexcept
{
    return static_cast<asn1::Context *>(static_cast<void *>(handle));
}

asn1::Schema *schemaOf(asn1_schema_t *handle) noexcept
{
    return static_cast<asn1::Schema *>(static_cast<void *>(handle));
}

asn1::Context *validContext(asn1_ctx_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asn1::Context *ctx = contextOf(handle);
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return nullptr;
    }
    return ctx;
}

asn1::Schema *validSchema(asn1_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asn1::Schema *schema = schemaOf(handle);
    if (schema->magic != asn1::kSchemaMagic ||
        schema->ctx->m_magic != asn1::kContextMagic || schema->ctx->m_dead) {
        return nullptr;
    }
    return schema;
}

const asn1::Schema *validSchema(const asn1_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    const asn1::Schema *schema =
        static_cast<const asn1::Schema *>(static_cast<const void *>(handle));
    if (schema->magic != asn1::kSchemaMagic ||
        schema->ctx->m_magic != asn1::kContextMagic || schema->ctx->m_dead) {
        return nullptr;
    }
    return schema;
}

} /* namespace */

extern "C" asn1_err_t asn1_schema_create(asn1_ctx_t *ctxHandle,
                                         asn1_tag_mode_t default_tag_mode,
                                         asn1_schema_t **out_schema)
{
    if (out_schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_schema = nullptr;
    asn1::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    asn1::Schema *schema = nullptr;
    const asn1_err_t rc = asn1::schemaCreate(
        ctx, static_cast<uint32_t>(default_tag_mode), &schema);
    if (rc != ASN1_OK) {
        return rc;
    }
    *out_schema = reinterpret_cast<asn1_schema_t *>(schema);
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_schema_load(asn1_ctx_t *ctxHandle,
                                       const asn1_schema_table_t *table,
                                       asn1_schema_t **out_schema)
{
    if (out_schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_schema = nullptr;
    asn1::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (table == nullptr) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }

    asn1::Schema *schema = nullptr;
    const asn1_err_t rc = asn1::schemaLoad(ctx, table, &schema);
    if (rc != ASN1_OK) {
        return rc;
    }
    *out_schema = reinterpret_cast<asn1_schema_t *>(schema);
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_schema_add_type(asn1_schema_t *schemaHandle,
                                           const asn1_type_desc_t *desc,
                                           uint32_t *out_type_id)
{
    if (schemaHandle == nullptr || desc == nullptr || out_type_id == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1::schemaAddType(schema->ctx, schema, desc, out_type_id, false);
}

extern "C" asn1_err_t asn1_schema_add_field(asn1_schema_t *schemaHandle,
                                            uint32_t parent_type_id,
                                            const asn1_field_desc_t *desc)
{
    if (schemaHandle == nullptr || desc == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1::schemaAddField(schema->ctx, schema, parent_type_id, desc);
}

extern "C" asn1_err_t asn1_schema_set_root(asn1_schema_t *schemaHandle,
                                           uint32_t root_type_id)
{
    if (schemaHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1::schemaSetRoot(schema->ctx, schema, root_type_id);
}

extern "C" asn1_err_t asn1_schema_seal(asn1_schema_t *schemaHandle)
{
    if (schemaHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1::schemaSeal(schema->ctx, schema);
}

extern "C" void asn1_schema_destroy(asn1_schema_t *schemaHandle)
{
    if (schemaHandle == nullptr) {
        return;
    }
    asn1::Schema *schema = schemaOf(schemaHandle);
    if (schema->magic != asn1::kSchemaMagic) {
        return;
    }
    asn1::schemaDestroy(schema);
}

extern "C" asn1_err_t asn1_schema_name_count(const asn1_schema_t *schemaHandle,
                                             uint32_t type_id,
                                             uint32_t *out_count)
{
    if (schemaHandle == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASN1_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASN1_E_INVALID_ARG;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        if (schema->names[i].typeId == type_id) {
            ++count;
        }
    }
    *out_count = count;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_schema_name_at(const asn1_schema_t *schemaHandle,
                                          uint32_t type_id, uint32_t index,
                                          asn1_schema_name_info_t *out_info)
{
    if (schemaHandle == nullptr || out_info == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (out_info->struct_size != sizeof(asn1_schema_name_info_t)) {
        return ASN1_E_INVALID_CONFIG;
    }
    const asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASN1_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASN1_E_INVALID_ARG;
    }

    uint32_t seen = 0;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asn1::SchemaName &entry = schema->names[i];
        if (entry.typeId != type_id) {
            continue;
        }
        if (seen == index) {
            out_info->type_id = entry.typeId;
            out_info->kind = entry.kind;
            out_info->flags = entry.flags;
            out_info->value = entry.value;
            out_info->name = entry.name;
            return ASN1_OK;
        }
        ++seen;
    }
    return ASN1_E_INVALID_ARG;
}

extern "C" asn1_err_t asn1_schema_name_for_bit(
    const asn1_schema_t *schemaHandle, uint32_t type_id, uint32_t bit,
    const char **out_name)
{
    if (schemaHandle == nullptr || out_name == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASN1_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASN1_E_INVALID_ARG;
    }

    *out_name = nullptr;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asn1::SchemaName &entry = schema->names[i];
        if (entry.typeId == type_id &&
            entry.kind == ASN1_SCHEMA_NAME_KIND_BIT &&
            entry.value == static_cast<int64_t>(bit)) {
            *out_name = entry.name;
            break;
        }
    }
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_schema_name_for_value(
    const asn1_schema_t *schemaHandle, uint32_t type_id, int64_t value,
    const char **out_name)
{
    if (schemaHandle == nullptr || out_name == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASN1_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASN1_E_INVALID_ARG;
    }

    *out_name = nullptr;
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asn1::SchemaName &entry = schema->names[i];
        if (entry.typeId == type_id &&
            entry.kind == ASN1_SCHEMA_NAME_KIND_NUMBER &&
            entry.value == value) {
            *out_name = entry.name;
            break;
        }
    }
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_schema_value_for_name(
    const asn1_schema_t *schemaHandle, uint32_t type_id, const char *name,
    int64_t *out_value, int *out_found)
{
    if (schemaHandle == nullptr || name == nullptr || out_value == nullptr ||
        out_found == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Schema *schema = validSchema(schemaHandle);
    if (schema == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        return ASN1_E_INVALID_STATE;
    }
    if (type_id == 0 || type_id > schema->typeCount) {
        return ASN1_E_INVALID_ARG;
    }

    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        const asn1::SchemaName &entry = schema->names[i];
        if (entry.typeId == type_id &&
            std::strcmp(entry.name, name) == 0) {
            *out_value = entry.value;
            *out_found = 1;
            return ASN1_OK;
        }
    }
    *out_value = 0;
    *out_found = 0;
    return ASN1_OK;
}
