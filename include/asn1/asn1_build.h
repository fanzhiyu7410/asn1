/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * runtime 构树：创建文档、创建节点、设置内容与封存。契约见
 * docs/02-C-API规范.md 6.1 与 docs/04-数据与内存模型.md 2.1。
 */
#ifndef ASN1_ASN1_BUILD_H_INCLUDED
#define ASN1_ASN1_BUILD_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_decode.h>
#include <asn1/asn1_error.h>
#include <asn1/asn1_export.h>

typedef enum asn1_tag_class {
    ASN1_TAG_UNIVERSAL = 0,
    ASN1_TAG_APPLICATION = 1,
    ASN1_TAG_CONTEXT = 2,
    ASN1_TAG_PRIVATE = 3
} asn1_tag_class_t;

#ifdef __cplusplus
extern "C" {
#endif

/* 创建空文档（未封存、源编码 ASN1_ENCODING_NONE）；失败时 *out_doc 置 NULL。 */
ASN1_API asn1_err_t asn1_doc_create(asn1_ctx_t *ctx, asn1_doc_t **out_doc);

/*
 * 冻结文档并校验结构（根存在、基本节点已设置内容、构造节点无内容）。
 * 幂等：已封存文档再次调用返回 ASN1_OK。失败时文档仍可销毁。
 */
ASN1_API asn1_err_t asn1_doc_seal(asn1_doc_t *doc);

/*
 * 创建节点。parent == NULL 表示设置根节点（只能一次）；非空 parent 表示
 * 追加为最后一个子节点，parent 必须是构造节点。
 * constructed 是运行期构造位；tag_class 必须是合法枚举值。
 * UNIVERSAL + tag_number 0 非法；其他标签类下 tag_number 0 合法。
 */
ASN1_API asn1_err_t asn1_node_create(asn1_doc_t *doc,
                                     asn1_node_t *parent,
                                     asn1_tag_class_t tag_class,
                                     uint32_t tag_number,
                                     int constructed,
                                     asn1_node_t **out_node);

/*
 * 创建 ANY/开放类型节点：tlv 必须恰好是一个完整、长度确定的 TLV。
 * 字节复制进文档 arena；tag_class/tag_number/constructed 从 TLV 头推导，
 * content 指向副本内的内容切片（不含 tag/len）。
 *
 * 拒绝：空输入（ASN1_E_INVALID_ARG）、截断（ASN1_E_TRUNCATED）、
 * 不定长（ASN1_E_INDEFINITE_NOT_ALLOWED）、尾随字节
 * （ASN1_E_TRAILING_DATA）、畸形标签/长度（ASN1_E_MALFORMED_TAG /
 * ASN1_E_MALFORMED_LENGTH）。失败时 *out_node 置 NULL，并写入上下文
 * 错误 offset（TLV 内字节偏移）。
 *
 * ANY 节点不得挂子节点；对其调用 asn1_node_create 返回
 * ASN1_E_INVALID_STATE。ANY 节点也不接受 asn1_node_set_content。
 */
ASN1_API asn1_err_t asn1_node_create_any(asn1_doc_t *doc,
                                        asn1_node_t *parent,
                                        const uint8_t *tlv, size_t tlv_size,
                                        asn1_node_t **out_node);

/* 把内容复制进文档 arena；同一节点只允许设置一次内容。 */
ASN1_API asn1_err_t asn1_node_set_content(asn1_node_t *node,
                                          const uint8_t *data, size_t size);

/* 写入规范 BOOLEAN 内容（false = 0x00，true = 0xFF）。 */
ASN1_API asn1_err_t asn1_node_set_bool(asn1_node_t *node, int value);

/* 写入最小长度二进制补码 INTEGER 内容。 */
ASN1_API asn1_err_t asn1_node_set_int64(asn1_node_t *node, int64_t value);

/* 把点分十进制 OID 编码为内容字节并复制进 arena。 */
ASN1_API asn1_err_t asn1_node_set_oid(asn1_node_t *node, const char *dotted);

/* 把 UTF-8 文本字节复制进 arena；不做字符集校验。 */
ASN1_API asn1_err_t asn1_node_set_utf8(asn1_node_t *node,
                                       const char *text, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_ASN1_BUILD_H_INCLUDED */
