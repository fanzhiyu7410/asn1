/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 独立消费工程（核心）：只依赖 find_package(asn1)，解码样本并读取根节点字段。
 */
#include <asn1/asn1.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asn1_ctx_config_t config;
    asn1_ctx_t *ctx = NULL;
    asn1_doc_t *doc = NULL;
    const asn1_node_t *root = NULL;
    size_t consumed = 0;
    int result = 1;

    if (argc != 2) {
        return 1;
    }
    file = fopen(argv[1], "rb");
    if (file == NULL) {
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 1;
    }
    der = (unsigned char *)malloc((size_t)length);
    if (der == NULL || fread(der, 1, (size_t)length, file) != (size_t)length) {
        free(der);
        fclose(file);
        return 1;
    }
    fclose(file);

    asn1_ctx_config_init(&config);
    if (asn1_ctx_create(&config, &ctx) != ASN1_OK) {
        free(der);
        return 1;
    }
    if (asn1_decode_buffer(ctx, der, (size_t)length, NULL, &doc, &consumed) ==
            ASN1_OK &&
        consumed == (size_t)length && asn1_doc_root(doc) != NULL) {
        root = asn1_doc_root(doc);
        if (asn1_node_tag_class(root) == ASN1_TAG_UNIVERSAL &&
            asn1_node_tag_number(root) == 16u &&
            asn1_node_child_count(root) >= 1) {
            result = 0;
        }
    }
    asn1_doc_destroy(doc);
    asn1_ctx_destroy(ctx);
    free(der);
    return result;
}
