/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * DOM：runtime 构树、内容设置、封存校验与只读访问。
 */
#include <asn1/asn1.h>

#include <stddef.h>

#include "check.h"

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    asn1_doc_t *doc = NULL;
    ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_doc_root(doc) == NULL);
    ASN1_TEST_CHECK(asn1_doc_source_encoding(doc) == ASN1_ENCODING_NONE);
    ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_E_INVALID_STATE);

    asn1_node_t *root = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASN1_OK);
    ASN1_TEST_CHECK(root != NULL);
    asn1_node_t *second_root = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                     &second_root) == ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(second_root == NULL);

    asn1_node_t *integer = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                     &integer) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_node_set_int64(integer, -42) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_node_set_int64(integer, 1) == ASN1_E_INVALID_STATE);

    asn1_node_t *boolean = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 1, 0,
                                     &boolean) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_node_set_bool(boolean, 1) == ASN1_OK);

    asn1_node_t *rejected = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, integer, ASN1_TAG_UNIVERSAL, 2, 0,
                                     &rejected) == ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(rejected == NULL);
    ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 0, 0,
                                     &rejected) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(rejected == NULL);

    ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);

    ASN1_TEST_CHECK(asn1_doc_root(doc) == root);
    ASN1_TEST_CHECK(asn1_node_tag_class(root) == ASN1_TAG_UNIVERSAL);
    ASN1_TEST_CHECK(asn1_node_tag_number(root) == 16);
    ASN1_TEST_CHECK(asn1_node_encoding_form(root) == ASN1_FORM_CONSTRUCTED);
    ASN1_TEST_CHECK(asn1_node_is_indefinite(root) == 0);
    ASN1_TEST_CHECK(asn1_node_child_count(root) == 2);
    ASN1_TEST_CHECK(asn1_node_child_at(root, 0) == integer);
    ASN1_TEST_CHECK(asn1_node_child_at(root, 1) == boolean);
    ASN1_TEST_CHECK(asn1_node_child_at(root, 2) == NULL);
    ASN1_TEST_CHECK(asn1_node_parent(integer) == root);
    ASN1_TEST_CHECK(asn1_node_parent(root) == NULL);
    ASN1_TEST_CHECK(asn1_node_field_name(integer) == NULL);
    ASN1_TEST_CHECK(asn1_node_child_by_name(root, "x") == NULL);

    const uint8_t *data = NULL;
    size_t size = 0;
    ASN1_TEST_CHECK(asn1_node_content(root, &data, &size) ==
                    ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(asn1_node_content(integer, &data, &size) == ASN1_OK);
    ASN1_TEST_CHECK(size == 1);
    ASN1_TEST_CHECK(data != NULL);
    ASN1_TEST_CHECK(data[0] == 0xD6); /* -42 的最小二进制补码 */

    size_t tlv_size = 123;
    ASN1_TEST_CHECK(asn1_node_tlv(integer, &tlv_size) == NULL);
    ASN1_TEST_CHECK(tlv_size == 0);
    ASN1_TEST_CHECK(asn1_node_offset(root) == SIZE_MAX);

    int64_t value = 0;
    ASN1_TEST_CHECK(asn1_node_get_int64(integer, &value) == ASN1_OK);
    ASN1_TEST_CHECK(value == -42);
    int bool_value = 0;
    ASN1_TEST_CHECK(asn1_node_get_bool(boolean, &bool_value) == ASN1_OK);
    ASN1_TEST_CHECK(bool_value == 1);

    rejected = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                     &rejected) == ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(rejected == NULL);
    ASN1_TEST_CHECK(asn1_node_set_content(integer, data, size) ==
                    ASN1_E_INVALID_STATE);

    asn1_doc_destroy(doc);
    asn1_doc_destroy(NULL);
    asn1_ctx_destroy(ctx);

    /* 未封存文档中基本节点缺少内容时封存失败。 */
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
    root = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASN1_OK);
    integer = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                     &integer) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_E_INVALID_STATE);
    asn1_doc_destroy(doc);
    asn1_ctx_destroy(ctx);

    return 0;
}
