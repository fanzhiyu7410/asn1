/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

#include "fuzz_common.h"

#include <string.h>

asn1_ctx_t *fuzz_ctx_create(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    if (asn1_ctx_create(&config, &ctx) != ASN1_OK) {
        return NULL;
    }
    return ctx;
}

void fuzz_walk(const asn1_node_t *node)
{
    if (node == NULL) {
        return;
    }
    (void)asn1_node_tag_class(node);
    (void)asn1_node_tag_number(node);
    (void)asn1_node_encoding_form(node);
    (void)asn1_node_is_indefinite(node);
    (void)asn1_node_field_name(node);
    (void)asn1_node_offset(node);

    {
        const uint8_t *data = NULL;
        size_t size = 0;
        (void)asn1_node_tlv(node, &size);
        (void)asn1_node_content(node, &data, &size);
        (void)data;
    }

    {
        size_t i;
        const size_t count = asn1_node_child_count(node);
        for (i = 0; i < count; ++i) {
            fuzz_walk(asn1_node_child_at(node, i));
        }
    }
}

asn1_err_t fuzz_mem_read(void *user, uint8_t *dst, size_t capacity,
                         size_t *out_size)
{
    fuzz_mem_reader_t *reader = (fuzz_mem_reader_t *)user;
    size_t available = reader->size - reader->pos;
    size_t take = (available < capacity) ? available : capacity;

    if (dst != NULL && take > 0) {
        memcpy(dst, reader->data + reader->pos, take);
    }
    reader->pos += take;
    *out_size = take;
    return ASN1_OK;
}

asn1_schema_t *fuzz_min_schema_create(asn1_ctx_t *ctx)
{
    asn1_schema_t *schema = NULL;
    asn1_type_desc_t type;
    asn1_field_desc_t field;
    uint32_t oid_id = 0;
    uint32_t any_id = 0;
    uint32_t seq_id = 0;

    if (ctx == NULL ||
        asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT, &schema) != ASN1_OK) {
        return NULL;
    }

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = "Oid";
    type.kind = ASN1_TYPE_KIND_SIMPLE;
    type.tag_class = ASN1_TAG_UNIVERSAL;
    type.tag_number = 6u;
    type.tag_mode = ASN1_TAG_MODE_DEFAULT;
    if (asn1_schema_add_type(schema, &type, &oid_id) != ASN1_OK) {
        goto fail;
    }

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = "AnyType";
    type.kind = ASN1_TYPE_KIND_ANY;
    type.tag_class = ASN1_TAG_UNIVERSAL;
    type.tag_number = 0u;
    type.tag_mode = ASN1_TAG_MODE_DEFAULT;
    if (asn1_schema_add_type(schema, &type, &any_id) != ASN1_OK) {
        goto fail;
    }

    memset(&type, 0, sizeof(type));
    type.struct_size = sizeof(type);
    type.name = "AlgId";
    type.kind = ASN1_TYPE_KIND_SEQUENCE;
    type.tag_class = ASN1_TAG_UNIVERSAL;
    type.tag_number = 16u;
    type.tag_mode = ASN1_TAG_MODE_DEFAULT;
    if (asn1_schema_add_type(schema, &type, &seq_id) != ASN1_OK) {
        goto fail;
    }

    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.name = "algorithm";
    field.type_id = oid_id;
    if (asn1_schema_add_field(schema, seq_id, &field) != ASN1_OK) {
        goto fail;
    }

    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.name = "parameters";
    field.type_id = any_id;
    field.flags = ASN1_FIELD_OPTIONAL;
    if (asn1_schema_add_field(schema, seq_id, &field) != ASN1_OK) {
        goto fail;
    }

    if (asn1_schema_set_root(schema, seq_id) != ASN1_OK ||
        asn1_schema_seal(schema) != ASN1_OK) {
        goto fail;
    }
    return schema;

fail:
    asn1_schema_destroy(schema);
    return NULL;
}