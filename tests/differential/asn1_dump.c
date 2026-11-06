/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 差分测试辅助工具：读取一个 DER 文件，用核心严格 DER 解码后输出规范 TLV
 * 树（offset / depth / header_len / content_len / cons），供 diff_asn1.py
 * 与 OpenSSL asn1parse 结果比对。
 *
 * 用法：
 *   asn1_dump <file.der>                 # 输出 TLV 树；解码失败退出码 1
 *   asn1_dump --roundtrip <file.der> <out.der>   # DER 解码 → 编码写回 out.der
 */
#include <asn1/asn1.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int dump_node(const asn1_node_t *node, unsigned depth)
{
    const uint8_t *content = NULL;
    size_t content_size = 0;
    size_t tlv_size = 0;
    size_t header_len = 0;
    int constructed = 0;
    size_t i;
    size_t count;

    (void)asn1_node_tlv(node, &tlv_size);
    constructed = (asn1_node_encoding_form(node) == ASN1_FORM_CONSTRUCTED) ? 1 : 0;

    /* 构造节点：header = 首个子节点偏移 - 自身偏移；内容长度 = 总长 - header。
     * 基本节点（含空构造）：内容长度 = asn1_node_content 的字节数。
     * asn1_node_content 对构造节点返回 ASN1_E_INVALID_STATE，不可用。 */
    count = asn1_node_child_count(node);
    if (constructed && count > 0) {
        const asn1_node_t *first = asn1_node_child_at(node, 0);
        size_t first_off = (first != NULL) ? asn1_node_offset(first) : 0;
        size_t off = asn1_node_offset(node);
        header_len = (first_off >= off) ? (first_off - off) : 0;
        content_size = (tlv_size >= header_len) ? (tlv_size - header_len) : 0;
    } else {
        (void)asn1_node_content(node, &content, &content_size);
        (void)content;
        header_len = (tlv_size >= content_size) ? (tlv_size - content_size) : 0;
    }

    printf("%u:d=%u hl=%u l=%u %s:\n",
           (unsigned)asn1_node_offset(node), depth, (unsigned)header_len,
           (unsigned)content_size, constructed ? "cons" : "prim");

    for (i = 0; i < count; ++i) {
        const asn1_node_t *child = asn1_node_child_at(node, i);
        if (child != NULL) {
            dump_node(child, depth + 1);
        }
    }
    return 0;
}

static int run_default(const char *path)
{
    FILE *fp = NULL;
    long len = 0;
    uint8_t *buf = NULL;
    asn1_ctx_t *ctx = NULL;
    asn1_decode_options_t options;
    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    asn1_err_t rc;
    int status = 1;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "open failed: %s\n", path);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = (uint8_t *)malloc((size_t)len);
    if (buf == NULL && len > 0) {
        fclose(fp);
        return 1;
    }
    if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        fclose(fp);
        free(buf);
        return 1;
    }
    fclose(fp);

    {
        asn1_ctx_config_t config;
        asn1_ctx_config_init(&config);
        if (asn1_ctx_create(&config, &ctx) != ASN1_OK) {
            free(buf);
            return 1;
        }
    }

    asn1_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASN1_ENCODING_DER;

    rc = asn1_decode_buffer(ctx, buf, (size_t)len, &options, &doc, &consumed);
    if (rc == ASN1_OK && doc != NULL) {
        dump_node(asn1_doc_root(doc), 0);
        status = 0;
    } else {
        fprintf(stderr, "decode failed: %d\n", (int)rc);
        status = 1;
    }

    if (doc != NULL) {
        asn1_doc_destroy(doc);
    }
    asn1_ctx_destroy(ctx);
    free(buf);
    return status;
}

static int run_roundtrip(const char *in_path, const char *out_path)
{
    FILE *fp = NULL;
    long len = 0;
    uint8_t *buf = NULL;
    asn1_ctx_t *ctx = NULL;
    asn1_decode_options_t doptions;
    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    asn1_err_t rc;
    int status = 1;

    fp = fopen(in_path, "rb");
    if (fp == NULL) {
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = (uint8_t *)malloc((size_t)len);
    if (buf == NULL && len > 0) {
        fclose(fp);
        return 1;
    }
    if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        fclose(fp);
        free(buf);
        return 1;
    }
    fclose(fp);

    {
        asn1_ctx_config_t config;
        asn1_ctx_config_init(&config);
        if (asn1_ctx_create(&config, &ctx) != ASN1_OK) {
            free(buf);
            return 1;
        }
    }

    asn1_decode_options_init(&doptions);
    doptions.struct_size = sizeof(doptions);
    doptions.encoding = ASN1_ENCODING_DER;

    rc = asn1_decode_buffer(ctx, buf, (size_t)len, &doptions, &doc, &consumed);
    if (rc == ASN1_OK && doc != NULL && consumed == (size_t)len) {
        asn1_buf_t out;
        memset(&out, 0, sizeof(out));
        if (asn1_encode_buffer(ctx, doc, NULL, &out) == ASN1_OK) {
            FILE *ofp = fopen(out_path, "wb");
            if (ofp != NULL) {
                if (fwrite(out.data, 1, out.size, ofp) == out.size) {
                    status = 0;
                }
                fclose(ofp);
            }
            (void)asn1_buf_release(ctx, &out);
        }
    }

    if (doc != NULL) {
        asn1_doc_destroy(doc);
    }
    asn1_ctx_destroy(ctx);
    free(buf);
    return status;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "--roundtrip") == 0) {
        return run_roundtrip(argv[2], argv[3]);
    }
    if (argc == 2) {
        return run_default(argv[1]);
    }
    fprintf(stderr,
            "usage: %s <file.der> | %s --roundtrip <file.der> <out.der>\n",
            argv[0], argv[0]);
    return 2;
}