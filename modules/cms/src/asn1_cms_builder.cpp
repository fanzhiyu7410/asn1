/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-cms 结构构造（写）：ContentInfo / SignedData builder。
 *
 * 职责：用核心公共 ABI（runtime 构树 + ANY 入口）与随模块发布的 schema
 *       描述表组装 ContentInfo / SignedData，并输出 DER 字节。
 * 边界：不生成签名、不计算摘要、不做加解密、不校验证书链；所有密码学
 *       语义字段由调用方给值并原样承载。
 * 依赖：只使用核心公共 C ABI；不包含核心内部头，不新增第二套编码器。
 * 所有权：builder 用 malloc 持有输入副本，destroy 释放；输出缓冲由
 *         asn1_encode_buffer 在上下文分配，调用方用 asn1_buf_release 归还。
 */

#include "asn1/cms/cms.h"

#include "cms_tables.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

struct byte_span {
    uint8_t *data;
    size_t size;
};

struct alg_entry {
    char *oid;
    byte_span params;
};

struct signer_entry {
    int64_t version;
    int32_t sid_kind;
    byte_span sid1;
    byte_span sid2;
    char *digest_oid;
    byte_span digest_params;
    byte_span signed_attrs;
    char *signature_oid;
    byte_span signature_params;
    byte_span signature;
    byte_span unsigned_attrs;
};

/* 与 cms.h 的前向声明同名同域：内部状态对本翻译单元可见。 */
struct asn1_cms_builder {
    asn1_ctx_t *ctx;
    bool version_set;
    int64_t version;
    alg_entry *digests;
    size_t digest_count;
    size_t digest_capacity;
    bool econtent_type_set;
    char *econtent_type;
    bool econtent_set;
    byte_span econtent;
    byte_span *certs;
    size_t cert_count;
    size_t cert_capacity;
    byte_span *crls;
    size_t crl_count;
    size_t crl_capacity;
    signer_entry *signers;
    size_t signer_count;
    size_t signer_capacity;
};

namespace {

constexpr uint32_t kCmsTableFormatVersion = 1u << 16;
constexpr uint32_t kTagSequence = 16;
constexpr uint32_t kTagSet = 17;
constexpr uint32_t kTagOid = 6;
constexpr uint32_t kTagInteger = 2;
constexpr uint32_t kTagOctetString = 4;
constexpr uint32_t kTagContext0 = 0;
constexpr uint32_t kTagContext1 = 1;

/* id-signedData (1.2.840.113549.1.7.2)。 */
constexpr const char *kSignedDataOid = "1.2.840.113549.1.7.2";

/* ---------- 内存与基本校验 ---------- */

uint8_t *copyBytes(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return nullptr;
    }
    uint8_t *copy = static_cast<uint8_t *>(std::malloc(size));
    if (copy == nullptr) {
        return nullptr;
    }
    std::memcpy(copy, data, size);
    return copy;
}

char *copyText(const char *text)
{
    if (text == nullptr) {
        return nullptr;
    }
    const size_t length = std::strlen(text);
    if (length == SIZE_MAX) {
        return nullptr;
    }
    char *copy = static_cast<char *>(std::malloc(length + 1));
    if (copy == nullptr) {
        return nullptr;
    }
    std::memcpy(copy, text, length + 1);
    return copy;
}

/* 确保动态数组能容纳 count + 1 个元素；容量按 4/8/16… 增长。 */
template <typename T>
bool ensureCapacity(T **array, size_t count, size_t *capacity)
{
    if (count < *capacity) {
        return true;
    }
    const size_t next = *capacity == 0 ? 4 : *capacity * 2;
    if (next <= *capacity || next > SIZE_MAX / sizeof(T)) {
        return false;
    }
    void *grown = std::realloc(*array, next * sizeof(T));
    if (grown == nullptr) {
        return false;
    }
    *array = static_cast<T *>(grown);
    *capacity = next;
    return true;
}

/* 追加一个字节切片到动态数组；返回 false 表示分配失败。 */
bool appendSpan(byte_span **array, size_t *count, size_t *capacity,
                const uint8_t *data, size_t size)
{
    if (!ensureCapacity(array, *count, capacity)) {
        return false;
    }
    uint8_t *copy = copyBytes(data, size);
    if (copy == nullptr) {
        return false;
    }
    (*array)[*count].data = copy;
    (*array)[*count].size = size;
    ++*count;
    return true;
}

void freeSpans(byte_span *array, size_t count)
{
    if (array == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(array[i].data);
    }
    std::free(array);
}

void freeSigner(signer_entry *signer)
{
    std::free(signer->sid1.data);
    std::free(signer->sid2.data);
    std::free(signer->digest_oid);
    std::free(signer->digest_params.data);
    std::free(signer->signed_attrs.data);
    std::free(signer->signature_oid);
    std::free(signer->signature_params.data);
    std::free(signer->signature.data);
    std::free(signer->unsigned_attrs.data);
    std::memset(signer, 0, sizeof(*signer));
}

/*
 * 用核心 DER 解码校验输入是恰好一个完整、规范的 DER TLV。
 * 可选返回根节点的标签判别信息。
 */
struct der_root {
    asn1_tag_class_t tag_class;
    uint32_t tag_number;
    int constructed;
};

asn1_err_t validateSingleDer(asn1_ctx_t *ctx, const uint8_t *tlv, size_t size,
                            der_root *out_root)
{
    if (ctx == nullptr || tlv == nullptr || size == 0) {
        return ASN1_E_INVALID_ARG;
    }

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    options.flags = ASN1_DECODE_COPY_INPUT;

    asn1_doc_t *doc = nullptr;
    size_t consumed = 0;
    asn1_err_t rc =
        asn1_decode_buffer(ctx, tlv, size, &options, &doc, &consumed);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (consumed != size) {
        asn1_doc_destroy(doc);
        return ASN1_E_TRAILING_DATA;
    }

    if (out_root != nullptr) {
        const asn1_node_t *root = asn1_doc_root(doc);
        out_root->tag_class = asn1_node_tag_class(root);
        out_root->tag_number = asn1_node_tag_number(root);
        out_root->constructed =
            asn1_node_encoding_form(root) == ASN1_FORM_CONSTRUCTED ? 1 : 0;
    }
    asn1_doc_destroy(doc);
    return ASN1_OK;
}

bool rootMatches(const der_root &root, asn1_tag_class_t tag_class,
                 uint32_t tag_number, int constructed)
{
    return root.tag_class == tag_class && root.tag_number == tag_number &&
           root.constructed == constructed;
}

/* 校验输入是单个规范 DER TLV，且根标签符合预期。 */
asn1_err_t validateSingleDerRoot(asn1_ctx_t *ctx, const uint8_t *tlv,
                                 size_t size, asn1_tag_class_t tag_class,
                                 uint32_t tag_number, int constructed)
{
    der_root root;
    asn1_err_t rc = validateSingleDer(ctx, tlv, size, &root);
    if (rc != ASN1_OK) {
        return rc;
    }
    return rootMatches(root, tag_class, tag_number, constructed)
               ? ASN1_OK
               : ASN1_E_INVALID_VALUE;
}

/* 校验点分十进制 OID：借一次构树调用，保持与核心一致的判定。 */
asn1_err_t validateOid(asn1_ctx_t *ctx, const char *oid)
{
    if (ctx == nullptr || oid == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1_doc_t *doc = nullptr;
    asn1_err_t rc = asn1_doc_create(ctx, &doc);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_node_t *node = nullptr;
    rc = asn1_node_create(doc, nullptr, ASN1_TAG_UNIVERSAL, kTagOid, 0, &node);
    if (rc == ASN1_OK) {
        rc = asn1_node_set_oid(node, oid);
    }
    asn1_doc_destroy(doc);
    return rc;
}

/*
 * 校验输入为完整 SET OF Attribute，并把外层 0x31 改写成 rewrittenTag。
 * RFC 5652 的 signedAttrs / unsignedAttrs 为 SIZE (1..MAX)，因此空集合
 * 与元素不是 SEQUENCE 的输入按结构错误拒绝。
 */
asn1_err_t validateAndRewriteSet(asn1_ctx_t *ctx, const uint8_t *tlv,
                                 size_t size, uint8_t rewrittenTag,
                                 byte_span *out)
{
    der_root root;
    asn1_err_t rc = validateSingleDer(ctx, tlv, size, &root);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (root.tag_class != ASN1_TAG_UNIVERSAL || root.tag_number != kTagSet ||
        root.constructed == 0) {
        return ASN1_E_INVALID_VALUE;
    }

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    options.flags = ASN1_DECODE_COPY_INPUT;
    asn1_doc_t *doc = nullptr;
    size_t consumed = 0;
    rc = asn1_decode_buffer(ctx, tlv, size, &options, &doc, &consumed);
    if (rc != ASN1_OK) {
        return rc;
    }
    const asn1_node_t *root_node = asn1_doc_root(doc);
    const size_t child_count = asn1_node_child_count(root_node);
    if (child_count == 0) {
        rc = ASN1_E_INVALID_VALUE;
    }
    for (size_t i = 0; rc == ASN1_OK && i < child_count; ++i) {
        const asn1_node_t *child = asn1_node_child_at(root_node, i);
        if (child == nullptr ||
            asn1_node_tag_class(child) != ASN1_TAG_UNIVERSAL ||
            asn1_node_tag_number(child) != kTagSequence ||
            asn1_node_encoding_form(child) != ASN1_FORM_CONSTRUCTED) {
            rc = ASN1_E_INVALID_VALUE;
        }
    }
    asn1_doc_destroy(doc);
    if (rc != ASN1_OK) {
        return rc;
    }

    uint8_t *copy = copyBytes(tlv, size);
    if (copy == nullptr) {
        return ASN1_E_NOMEM;
    }
    copy[0] = rewrittenTag;
    out->data = copy;
    out->size = size;
    return ASN1_OK;
}

/* ---------- 描述表加载 ---------- */

asn1_err_t loadTable(asn1_ctx_t *ctx, cms_table_view view,
                    asn1_schema_t **out_schema)
{
    asn1_schema_table_t table;
    table.struct_size = sizeof(table);
    table.data = view.data;
    table.size = view.size;
    table.format_version = kCmsTableFormatVersion;
    table.reserved = 0;
    return asn1_schema_load(ctx, &table, out_schema);
}

/* ---------- 构树辅助 ---------- */

asn1_err_t createNode(asn1_doc_t *doc, asn1_node_t *parent, uint32_t tag_class,
                     uint32_t tag_number, int constructed,
                     asn1_node_t **out_node)
{
    return asn1_node_create(doc, parent, static_cast<asn1_tag_class_t>(tag_class),
                           tag_number, constructed, out_node);
}

asn1_err_t createOidNode(asn1_doc_t *doc, asn1_node_t *parent, const char *oid,
                        asn1_node_t **out_node)
{
    asn1_node_t *node = nullptr;
    asn1_err_t rc = createNode(doc, parent, ASN1_TAG_UNIVERSAL, kTagOid, 0,
                               &node);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = asn1_node_set_oid(node, oid);
    if (rc != ASN1_OK) {
        return rc;
    }
    *out_node = node;
    return ASN1_OK;
}

asn1_err_t createIntegerNode(asn1_doc_t *doc, asn1_node_t *parent,
                            int64_t value, asn1_node_t **out_node)
{
    asn1_node_t *node = nullptr;
    asn1_err_t rc = createNode(doc, parent, ASN1_TAG_UNIVERSAL, kTagInteger, 0,
                               &node);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = asn1_node_set_int64(node, value);
    if (rc != ASN1_OK) {
        return rc;
    }
    *out_node = node;
    return ASN1_OK;
}

asn1_err_t createOctetStringNode(asn1_doc_t *doc, asn1_node_t *parent,
                                const uint8_t *data, size_t size,
                                asn1_node_t **out_node)
{
    asn1_node_t *node = nullptr;
    asn1_err_t rc = createNode(doc, parent, ASN1_TAG_UNIVERSAL, kTagOctetString,
                               0, &node);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = asn1_node_set_content(node, data, size);
    if (rc != ASN1_OK) {
        return rc;
    }
    *out_node = node;
    return ASN1_OK;
}

/* 追加 AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters ANY OPTIONAL }。 */
asn1_err_t addAlgorithmIdentifier(asn1_doc_t *doc, asn1_node_t *parent,
                                 const char *oid, const byte_span &params)
{
    asn1_node_t *sequence = nullptr;
    asn1_err_t rc = createNode(doc, parent, ASN1_TAG_UNIVERSAL, kTagSequence, 1,
                               &sequence);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_node_t *ignored = nullptr;
    rc = createOidNode(doc, sequence, oid, &ignored);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (params.size != 0) {
        rc = asn1_node_create_any(doc, sequence, params.data, params.size,
                                  &ignored);
    }
    return rc;
}

asn1_err_t addSid(asn1_doc_t *doc, asn1_node_t *parent,
                 const signer_entry &signer, asn1_node_t **out_node)
{
    asn1_node_t *node = nullptr;
    if (signer.sid_kind == ASN1_CMS_SID_ISSUER_AND_SERIAL) {
        asn1_err_t rc = createNode(doc, parent, ASN1_TAG_UNIVERSAL,
                                   kTagSequence, 1, &node);
        if (rc != ASN1_OK) {
            return rc;
        }
        asn1_node_t *ignored = nullptr;
        rc = asn1_node_create_any(doc, node, signer.sid1.data,
                                  signer.sid1.size, &ignored);
        if (rc != ASN1_OK) {
            return rc;
        }
        rc = asn1_node_create_any(doc, node, signer.sid2.data,
                                  signer.sid2.size, &ignored);
        if (rc != ASN1_OK) {
            return rc;
        }
    } else {
        asn1_err_t rc = createNode(doc, parent, ASN1_TAG_CONTEXT,
                                   kTagContext0, 0, &node);
        if (rc != ASN1_OK) {
            return rc;
        }
        rc = asn1_node_set_content(node, signer.sid1.data, signer.sid1.size);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    *out_node = node;
    return ASN1_OK;
}

asn1_err_t addSignerInfo(asn1_doc_t *doc, asn1_node_t *parent,
                        const signer_entry &signer)
{
    asn1_node_t *sequence = nullptr;
    asn1_err_t rc = createNode(doc, parent, ASN1_TAG_UNIVERSAL, kTagSequence, 1,
                               &sequence);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_node_t *ignored = nullptr;
    rc = createIntegerNode(doc, sequence, signer.version, &ignored);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = addSid(doc, sequence, signer, &ignored);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = addAlgorithmIdentifier(doc, sequence, signer.digest_oid,
                                signer.digest_params);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (signer.signed_attrs.size != 0) {
        rc = asn1_node_create_any(doc, sequence, signer.signed_attrs.data,
                                  signer.signed_attrs.size, &ignored);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    rc = addAlgorithmIdentifier(doc, sequence, signer.signature_oid,
                                signer.signature_params);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = createOctetStringNode(doc, sequence, signer.signature.data,
                               signer.signature.size, &ignored);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (signer.unsigned_attrs.size != 0) {
        rc = asn1_node_create_any(doc, sequence, signer.unsigned_attrs.data,
                                  signer.unsigned_attrs.size, &ignored);
    }
    return rc;
}

/* 组装 SignedData 文档（不含 ContentInfo 包装）。 */
asn1_err_t buildSignedData(const asn1_cms_builder &builder, asn1_doc_t **out_doc)
{
    asn1_doc_t *doc = nullptr;
    asn1_err_t rc = asn1_doc_create(builder.ctx, &doc);
    if (rc != ASN1_OK) {
        return rc;
    }

    asn1_node_t *root = nullptr;
    asn1_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASN1_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    rc = createIntegerNode(doc, root, builder.version, &ignored);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }

    asn1_node_t *digests = nullptr;
    rc = createNode(doc, root, ASN1_TAG_UNIVERSAL, kTagSet, 1, &digests);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    for (size_t i = 0; i < builder.digest_count; ++i) {
        rc = addAlgorithmIdentifier(doc, digests, builder.digests[i].oid,
                                    builder.digests[i].params);
        if (rc != ASN1_OK) {
            asn1_doc_destroy(doc);
            return rc;
        }
    }

    asn1_node_t *encap = nullptr;
    rc = createNode(doc, root, ASN1_TAG_UNIVERSAL, kTagSequence, 1, &encap);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    rc = createOidNode(doc, encap, builder.econtent_type, &ignored);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    if (builder.econtent_set) {
        asn1_node_t *wrapper = nullptr;
        rc = createNode(doc, encap, ASN1_TAG_CONTEXT, kTagContext0, 1,
                        &wrapper);
        if (rc == ASN1_OK) {
            rc = createOctetStringNode(doc, wrapper, builder.econtent.data,
                                       builder.econtent.size, &ignored);
        }
        if (rc != ASN1_OK) {
            asn1_doc_destroy(doc);
            return rc;
        }
    }

    if (builder.cert_count != 0) {
        asn1_node_t *certificates = nullptr;
        rc = createNode(doc, root, ASN1_TAG_CONTEXT, kTagContext0, 1,
                        &certificates);
        if (rc != ASN1_OK) {
            asn1_doc_destroy(doc);
            return rc;
        }
        for (size_t i = 0; i < builder.cert_count; ++i) {
            rc = asn1_node_create_any(doc, certificates, builder.certs[i].data,
                                      builder.certs[i].size, &ignored);
            if (rc != ASN1_OK) {
                asn1_doc_destroy(doc);
                return rc;
            }
        }
    }

    if (builder.crl_count != 0) {
        asn1_node_t *crls = nullptr;
        rc = createNode(doc, root, ASN1_TAG_CONTEXT, kTagContext1, 1, &crls);
        if (rc != ASN1_OK) {
            asn1_doc_destroy(doc);
            return rc;
        }
        for (size_t i = 0; i < builder.crl_count; ++i) {
            rc = asn1_node_create_any(doc, crls, builder.crls[i].data,
                                      builder.crls[i].size, &ignored);
            if (rc != ASN1_OK) {
                asn1_doc_destroy(doc);
                return rc;
            }
        }
    }

    asn1_node_t *signer_infos = nullptr;
    rc = createNode(doc, root, ASN1_TAG_UNIVERSAL, kTagSet, 1, &signer_infos);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    for (size_t i = 0; i < builder.signer_count; ++i) {
        rc = addSignerInfo(doc, signer_infos, builder.signers[i]);
        if (rc != ASN1_OK) {
            asn1_doc_destroy(doc);
            return rc;
        }
    }

    rc = asn1_doc_seal(doc);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    return ASN1_OK;
}

/* 编码 SignedData 文档（schema 感知）。 */
asn1_err_t encodeSignedData(const asn1_cms_builder &builder,
                           const asn1_doc_t *doc, asn1_buf_t *out_buf)
{
    asn1_schema_t *schema = nullptr;
    asn1_err_t rc = loadTable(builder.ctx, cmsSignedDataTable(), &schema);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_encode_options_t options;
    asn1_encode_options_init(&options);
    options.schema = schema;
    rc = asn1_encode_buffer(builder.ctx, doc, &options, out_buf);
    asn1_schema_destroy(schema);
    return rc;
}

/*
 * 用通用编码器把 SignedData TLV 包进 `[0]` 显式包装，得到 ContentInfo.content
 * 的完整原始 TLV。避免在模块内手写长度编码。
 */
asn1_err_t encodeExplicitWrapper(const asn1_cms_builder &builder,
                                const uint8_t *inner, size_t inner_size,
                                asn1_buf_t *out_buf)
{
    asn1_doc_t *doc = nullptr;
    asn1_err_t rc = asn1_doc_create(builder.ctx, &doc);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_node_t *wrapper = nullptr;
    asn1_node_t *any_node = nullptr;
    rc = createNode(doc, nullptr, ASN1_TAG_CONTEXT, kTagContext0, 1, &wrapper);
    if (rc == ASN1_OK) {
        rc = asn1_node_create_any(doc, wrapper, inner, inner_size, &any_node);
    }
    if (rc == ASN1_OK) {
        rc = asn1_doc_seal(doc);
    }
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }

    rc = asn1_encode_buffer(builder.ctx, doc, nullptr, out_buf);
    asn1_doc_destroy(doc);
    return rc;
}

/* 组装并编码 ContentInfo。 */
asn1_err_t encodeContentInfo(const asn1_cms_builder &builder,
                            const uint8_t *signed_data, size_t signed_data_size,
                            asn1_buf_t *out_buf)
{
    asn1_buf_t wrapper;
    std::memset(&wrapper, 0, sizeof(wrapper));
    asn1_err_t rc = encodeExplicitWrapper(builder, signed_data,
                                         signed_data_size, &wrapper);
    if (rc != ASN1_OK) {
        return rc;
    }

    asn1_doc_t *doc = nullptr;
    rc = asn1_doc_create(builder.ctx, &doc);
    if (rc != ASN1_OK) {
        asn1_buf_release(builder.ctx, &wrapper);
        return rc;
    }
    asn1_node_t *root = nullptr;
    asn1_node_t *ignored = nullptr;
    rc = createNode(doc, nullptr, ASN1_TAG_UNIVERSAL, kTagSequence, 1, &root);
    if (rc == ASN1_OK) {
        rc = createOidNode(doc, root, kSignedDataOid, &ignored);
    }
    if (rc == ASN1_OK) {
        rc = asn1_node_create_any(doc, root, wrapper.data, wrapper.size,
                                  &ignored);
    }
    if (rc == ASN1_OK) {
        rc = asn1_doc_seal(doc);
    }
    asn1_buf_release(builder.ctx, &wrapper);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }

    asn1_schema_t *schema = nullptr;
    rc = loadTable(builder.ctx, cmsContentInfoTable(), &schema);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    asn1_encode_options_t options;
    asn1_encode_options_init(&options);
    options.schema = schema;
    rc = asn1_encode_buffer(builder.ctx, doc, &options, out_buf);
    asn1_schema_destroy(schema);
    asn1_doc_destroy(doc);
    return rc;
}

} /* namespace */

/* ========================================================================= */
/* 公共接口                                                                  */
/* ========================================================================= */

extern "C" asn1_err_t asn1_cms_builder_create(asn1_ctx_t *ctx,
                                             asn1_cms_builder_t **out_builder)
{
    if (ctx == nullptr || out_builder == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_builder = nullptr;
    asn1_cms_builder_t *builder =
        static_cast<asn1_cms_builder_t *>(std::malloc(sizeof(asn1_cms_builder_t)));
    if (builder == nullptr) {
        return ASN1_E_NOMEM;
    }
    std::memset(builder, 0, sizeof(*builder));
    builder->ctx = ctx;
    *out_builder = builder;
    return ASN1_OK;
}

extern "C" void asn1_cms_builder_destroy(asn1_cms_builder_t *builder)
{
    if (builder == nullptr) {
        return;
    }
    for (size_t i = 0; i < builder->digest_count; ++i) {
        std::free(builder->digests[i].oid);
        std::free(builder->digests[i].params.data);
    }
    std::free(builder->digests);
    std::free(builder->econtent_type);
    std::free(builder->econtent.data);
    freeSpans(builder->certs, builder->cert_count);
    freeSpans(builder->crls, builder->crl_count);
    for (size_t i = 0; i < builder->signer_count; ++i) {
        freeSigner(&builder->signers[i]);
    }
    std::free(builder->signers);
    std::memset(builder, 0, sizeof(*builder));
    std::free(builder);
}

extern "C" asn1_err_t asn1_cms_builder_set_version(
    asn1_cms_builder_t *builder, int64_t version)
{
    if (builder == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (builder->version_set) {
        return ASN1_E_INVALID_STATE;
    }
    builder->version = version;
    builder->version_set = true;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_cms_builder_add_digest_algorithm(
    asn1_cms_builder_t *builder, const char *oid, const uint8_t *params,
    size_t params_size)
{
    if (builder == nullptr || oid == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (params == nullptr && params_size != 0) {
        return ASN1_E_INVALID_ARG;
    }
    asn1_err_t rc = validateOid(builder->ctx, oid);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (params_size != 0) {
        rc = validateSingleDer(builder->ctx, params, params_size, nullptr);
        if (rc != ASN1_OK) {
            return rc;
        }
    }

    if (!ensureCapacity(&builder->digests, builder->digest_count,
                        &builder->digest_capacity)) {
        return ASN1_E_NOMEM;
    }

    alg_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.oid = copyText(oid);
    if (entry.oid == nullptr) {
        return ASN1_E_NOMEM;
    }
    if (params_size != 0) {
        entry.params.data = copyBytes(params, params_size);
        if (entry.params.data == nullptr) {
            std::free(entry.oid);
            return ASN1_E_NOMEM;
        }
        entry.params.size = params_size;
    }
    builder->digests[builder->digest_count] = entry;
    ++builder->digest_count;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_cms_builder_set_econtent_type(
    asn1_cms_builder_t *builder, const char *oid)
{
    if (builder == nullptr || oid == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (builder->econtent_type_set) {
        return ASN1_E_INVALID_STATE;
    }
    asn1_err_t rc = validateOid(builder->ctx, oid);
    if (rc != ASN1_OK) {
        return rc;
    }
    char *copy = copyText(oid);
    if (copy == nullptr) {
        return ASN1_E_NOMEM;
    }
    builder->econtent_type = copy;
    builder->econtent_type_set = true;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_cms_builder_set_econtent(
    asn1_cms_builder_t *builder, const uint8_t *econtent, size_t econtent_size)
{
    if (builder == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (builder->econtent_set) {
        return ASN1_E_INVALID_STATE;
    }
    if (econtent == nullptr || econtent_size == 0) {
        return ASN1_E_INVALID_ARG;
    }

    der_root root;
    root.tag_class = ASN1_TAG_UNIVERSAL;
    root.tag_number = 0;
    root.constructed = 0;
    asn1_err_t rc =
        validateSingleDer(builder->ctx, econtent, econtent_size, &root);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (root.tag_class != ASN1_TAG_UNIVERSAL ||
        root.tag_number != kTagOctetString || root.constructed != 0) {
        return ASN1_E_INVALID_VALUE;
    }

    /* 重新解码一次以取得内容字节；文档释放后指针失效，因此复制。 */
    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    options.flags = ASN1_DECODE_COPY_INPUT;
    asn1_doc_t *doc = nullptr;
    size_t consumed = 0;
    rc = asn1_decode_buffer(builder->ctx, econtent, econtent_size, &options,
                            &doc, &consumed);
    if (rc != ASN1_OK) {
        return rc;
    }
    const uint8_t *content = nullptr;
    size_t content_size = 0;
    rc = asn1_node_content(asn1_doc_root(doc), &content, &content_size);
    if (rc == ASN1_OK) {
        if (content_size == 0) {
            builder->econtent.data = nullptr;
            builder->econtent.size = 0;
            builder->econtent_set = true;
        } else {
            uint8_t *copy = copyBytes(content, content_size);
            if (copy == nullptr) {
                rc = ASN1_E_NOMEM;
            } else {
                builder->econtent.data = copy;
                builder->econtent.size = content_size;
                builder->econtent_set = true;
            }
        }
    }
    asn1_doc_destroy(doc);
    return rc;
}

extern "C" asn1_err_t asn1_cms_builder_add_certificate(
    asn1_cms_builder_t *builder, const uint8_t *tlv, size_t tlv_size)
{
    if (builder == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    der_root root;
    asn1_err_t rc = validateSingleDer(builder->ctx, tlv, tlv_size, &root);
    if (rc != ASN1_OK) {
        return rc;
    }
    /* CertificateChoices：certificate SEQUENCE，或 [0..3] IMPLICIT 备选。 */
    const bool certificate =
        rootMatches(root, ASN1_TAG_UNIVERSAL, kTagSequence, 1);
    const bool alternate = root.tag_class == ASN1_TAG_CONTEXT &&
                           root.constructed == 1 && root.tag_number <= 3;
    if (!certificate && !alternate) {
        return ASN1_E_INVALID_VALUE;
    }
    return appendSpan(&builder->certs, &builder->cert_count,
                      &builder->cert_capacity, tlv, tlv_size)
               ? ASN1_OK
               : ASN1_E_NOMEM;
}

extern "C" asn1_err_t asn1_cms_builder_add_crl(asn1_cms_builder_t *builder,
                                               const uint8_t *tlv,
                                               size_t tlv_size)
{
    if (builder == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    der_root root;
    asn1_err_t rc = validateSingleDer(builder->ctx, tlv, tlv_size, &root);
    if (rc != ASN1_OK) {
        return rc;
    }
    /* RevocationInfoChoice：crl CertificateList SEQUENCE，或 other [1]。 */
    const bool crl = rootMatches(root, ASN1_TAG_UNIVERSAL, kTagSequence, 1);
    const bool other = rootMatches(root, ASN1_TAG_CONTEXT, kTagContext1, 1);
    if (!crl && !other) {
        return ASN1_E_INVALID_VALUE;
    }
    return appendSpan(&builder->crls, &builder->crl_count,
                      &builder->crl_capacity, tlv, tlv_size)
               ? ASN1_OK
               : ASN1_E_NOMEM;
}

extern "C" asn1_err_t asn1_cms_builder_add_signer(
    asn1_cms_builder_t *builder, int64_t version, int32_t sid_kind,
    const uint8_t *sid1, size_t sid1_size, const uint8_t *sid2,
    size_t sid2_size, const char *digest_oid, const uint8_t *digest_params,
    size_t digest_params_size, const uint8_t *signed_attrs_tlv,
    size_t signed_attrs_size, const char *signature_oid,
    const uint8_t *signature_params, size_t signature_params_size,
    const uint8_t *signature, size_t signature_size,
    const uint8_t *unsigned_attrs_tlv, size_t unsigned_attrs_size)
{
    if (builder == nullptr || digest_oid == nullptr || signature_oid == nullptr ||
        signature == nullptr || signature_size == 0) {
        return ASN1_E_INVALID_ARG;
    }
    if (sid_kind != ASN1_CMS_SID_ISSUER_AND_SERIAL &&
        sid_kind != ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER) {
        return ASN1_E_INVALID_VALUE;
    }

    asn1_err_t rc = ASN1_OK;
    byte_span signed_attrs;
    byte_span unsigned_attrs;
    std::memset(&signed_attrs, 0, sizeof(signed_attrs));
    std::memset(&unsigned_attrs, 0, sizeof(unsigned_attrs));

    /* 先完成全部校验与派生，再一次性复制提交，避免半成品追加。 */
    if (sid_kind == ASN1_CMS_SID_ISSUER_AND_SERIAL) {
        /* issuer Name = RDNSequence SEQUENCE；serialNumber = INTEGER。 */
        rc = validateSingleDerRoot(builder->ctx, sid1, sid1_size,
                                   ASN1_TAG_UNIVERSAL, kTagSequence, 1);
        if (rc == ASN1_OK) {
            rc = validateSingleDerRoot(builder->ctx, sid2, sid2_size,
                                       ASN1_TAG_UNIVERSAL, kTagInteger, 0);
        }
    } else {
        if (sid1 == nullptr || sid1_size == 0 || sid2 != nullptr ||
            sid2_size != 0) {
            return ASN1_E_INVALID_ARG;
        }
    }
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateOid(builder->ctx, digest_oid);
    if (rc == ASN1_OK) {
        rc = validateOid(builder->ctx, signature_oid);
    }
    if (rc != ASN1_OK) {
        return rc;
    }
    if (digest_params_size != 0) {
        rc = validateSingleDer(builder->ctx, digest_params, digest_params_size,
                               nullptr);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    if (signature_params_size != 0) {
        rc = validateSingleDer(builder->ctx, signature_params,
                               signature_params_size, nullptr);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    if (signed_attrs_size != 0) {
        rc = validateAndRewriteSet(builder->ctx, signed_attrs_tlv,
                                   signed_attrs_size, 0xA0, &signed_attrs);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    if (unsigned_attrs_size != 0) {
        rc = validateAndRewriteSet(builder->ctx, unsigned_attrs_tlv,
                                   unsigned_attrs_size, 0xB1, &unsigned_attrs);
        if (rc != ASN1_OK) {
            std::free(signed_attrs.data);
            return rc;
        }
    }

    if (!ensureCapacity(&builder->signers, builder->signer_count,
                        &builder->signer_capacity)) {
        std::free(signed_attrs.data);
        std::free(unsigned_attrs.data);
        return ASN1_E_NOMEM;
    }

    signer_entry entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.version = version;
    entry.sid_kind = sid_kind;
    entry.sid1.data = copyBytes(sid1, sid1_size);
    entry.sid1.size = sid1_size;
    if (entry.sid1.data == nullptr) {
        std::free(signed_attrs.data);
        std::free(unsigned_attrs.data);
        return ASN1_E_NOMEM;
    }
    if (sid2_size != 0) {
        entry.sid2.data = copyBytes(sid2, sid2_size);
        if (entry.sid2.data == nullptr) {
            freeSigner(&entry);
            std::free(signed_attrs.data);
            std::free(unsigned_attrs.data);
            return ASN1_E_NOMEM;
        }
        entry.sid2.size = sid2_size;
    }
    entry.digest_oid = copyText(digest_oid);
    entry.signature_oid = copyText(signature_oid);
    if (entry.digest_oid == nullptr || entry.signature_oid == nullptr) {
        freeSigner(&entry);
        std::free(signed_attrs.data);
        std::free(unsigned_attrs.data);
        return ASN1_E_NOMEM;
    }
    if (digest_params_size != 0) {
        entry.digest_params.data =
            copyBytes(digest_params, digest_params_size);
        entry.digest_params.size = digest_params_size;
    }
    if (signature_params_size != 0) {
        entry.signature_params.data =
            copyBytes(signature_params, signature_params_size);
        entry.signature_params.size = signature_params_size;
    }
    entry.signature.data = copyBytes(signature, signature_size);
    entry.signature.size = signature_size;
    entry.signed_attrs = signed_attrs;
    entry.unsigned_attrs = unsigned_attrs;

    if ((digest_params_size != 0 && entry.digest_params.data == nullptr) ||
        (signature_params_size != 0 && entry.signature_params.data == nullptr) ||
        entry.signature.data == nullptr) {
        freeSigner(&entry);
        return ASN1_E_NOMEM;
    }

    builder->signers[builder->signer_count] = entry;
    ++builder->signer_count;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_cms_builder_encode(
    const asn1_cms_builder_t *builder, asn1_buf_t *out_buf)
{
    if (builder == nullptr || out_buf == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    if (!builder->version_set || builder->digest_count == 0 ||
        !builder->econtent_type_set || builder->signer_count == 0) {
        return ASN1_E_INVALID_STATE;
    }

    asn1_doc_t *signed_data = nullptr;
    asn1_err_t rc = buildSignedData(*builder, &signed_data);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_buf_t signed_data_buf;
    std::memset(&signed_data_buf, 0, sizeof(signed_data_buf));
    rc = encodeSignedData(*builder, signed_data, &signed_data_buf);
    asn1_doc_destroy(signed_data);
    if (rc != ASN1_OK) {
        return rc;
    }

    rc = encodeContentInfo(*builder, signed_data_buf.data, signed_data_buf.size,
                           out_buf);
    asn1_buf_release(builder->ctx, &signed_data_buf);
    return rc;
}
