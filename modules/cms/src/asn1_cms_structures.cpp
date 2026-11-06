/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-cms 只读切片的 ContentInfo / SignedData 结构访问。
 *
 * 职责：用随模块发布的描述表加载 schema，按 DER 严格模式解码
 *       ContentInfo 与 SignedData，并把结构字段投影为核心节点/值。
 * 边界：不验签、不计算摘要、不解密、不校验证书链；ANY 与属性集合只
 *       返回原始 TLV，密码学语义由调用方按 OID 二次解析。
 * 依赖：只使用核心公共 C ABI；生成表由 asn1c 产出。
 * 所有权：句柄持有 schema 与文档，close 时逆序释放；访问器返回的指针
 *         借用句柄，close 后失效。
 * 线程：模块没有全局可变状态；不同句柄/上下文互不影响。同一 ctx 的
 *       并发使用需由调用方加锁（核心错误状态挂在 ctx 上）。
 */

#include "asn1/cms/cms.h"

#include <asn1/asn1_schema.h>

#include "cms_tables.h"

#include <cstdlib>

namespace {

constexpr uint32_t kCmsFormatVersion = 1u << 16;
constexpr uint32_t kTagSequence = 16;

/* 两个句柄共享的字段；派生句柄以它为第一个成员。 */
struct handle_base {
    asn1_ctx_t *ctx;
    asn1_schema_t *schema;
    asn1_doc_t *doc;
    const asn1_node_t *root;
};

template <typename T>
asn1_err_t openStructure(asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
                         cms_table_view table, T **out_object) noexcept
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
    schema_table.format_version = kCmsFormatVersion;
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

/* 取顶层字段；不存在时返回 nullptr。 */
const asn1_node_t *field(const handle_base *object,
                         const char *name) noexcept
{
    return asn1_node_child_by_name(object->root, name);
}

const asn1_node_t *nestedField(const asn1_node_t *parent,
                               const char *name) noexcept
{
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

/* 可选集合字段：缺省时条目数为 0。 */
asn1_err_t optionalCollectionCount(const handle_base *object,
                                   const char *name,
                                   size_t *out_count) noexcept
{
    const asn1_node_t *node = field(object, name);
    *out_count = node == nullptr ? 0 : asn1_node_child_count(node);
    return ASN1_OK;
}

asn1_err_t collectionItem(const handle_base *object, const char *name,
                          size_t index,
                          const asn1_node_t **out_node) noexcept
{
    *out_node = nullptr;
    const asn1_node_t *collection = field(object, name);
    if (collection == nullptr || index >= asn1_node_child_count(collection)) {
        return ASN1_E_INVALID_ARG;
    }
    *out_node = asn1_node_child_at(collection, index);
    return (*out_node == nullptr) ? ASN1_E_INVALID_ARG : ASN1_OK;
}

/* AlgorithmIdentifier：algorithm OID + parameters（ANY 原始 TLV）。 */
asn1_err_t algorithmFields(const asn1_node_t *algorithm,
                           const char **out_oid, size_t *out_oid_size,
                           const uint8_t **out_parameters,
                           size_t *out_parameters_size) noexcept
{
    if (algorithm == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    const asn1_node_t *oid = nestedField(algorithm, "algorithm");
    if (oid == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    asn1_err_t status = asn1_node_get_oid(oid, out_oid, out_oid_size);
    if (status != ASN1_OK) {
        return status;
    }

    const asn1_node_t *parameters = nestedField(algorithm, "parameters");
    if (parameters == nullptr) {
        *out_parameters = nullptr;
        *out_parameters_size = 0;
        return ASN1_OK;
    }
    *out_parameters = asn1_node_tlv(parameters, out_parameters_size);
    return (*out_parameters == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

/*
 * CertificateChoices 分支：按实际标签判别。证书是通用 SEQUENCE；其余
 * 分支分别是 context [0..3] IMPLICIT。
 */
int certificateChoiceKind(const asn1_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asn1_node_tag_class(node) == ASN1_TAG_UNIVERSAL &&
        asn1_node_tag_number(node) == kTagSequence) {
        return ASN1_CMS_CERT_CHOICE_CERTIFICATE;
    }
    if (asn1_node_tag_class(node) == ASN1_TAG_CONTEXT) {
        switch (asn1_node_tag_number(node)) {
        case 0:
            return ASN1_CMS_CERT_CHOICE_EXTENDED;
        case 1:
            return ASN1_CMS_CERT_CHOICE_V1_ATTR_CERT;
        case 2:
            return ASN1_CMS_CERT_CHOICE_V2_ATTR_CERT;
        case 3:
            return ASN1_CMS_CERT_CHOICE_OTHER;
        default:
            break;
        }
    }
    return -1;
}

int revocationChoiceKind(const asn1_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asn1_node_tag_class(node) == ASN1_TAG_UNIVERSAL &&
        asn1_node_tag_number(node) == kTagSequence) {
        return ASN1_CMS_REVOCATION_CHOICE_CRL;
    }
    if (asn1_node_tag_class(node) == ASN1_TAG_CONTEXT &&
        asn1_node_tag_number(node) == 1) {
        return ASN1_CMS_REVOCATION_CHOICE_OTHER;
    }
    return -1;
}

int signerIdChoiceKind(const asn1_node_t *node) noexcept
{
    if (node == nullptr) {
        return -1;
    }
    if (asn1_node_tag_class(node) == ASN1_TAG_UNIVERSAL &&
        asn1_node_tag_number(node) == kTagSequence) {
        return ASN1_CMS_SID_ISSUER_AND_SERIAL;
    }
    if (asn1_node_tag_class(node) == ASN1_TAG_CONTEXT &&
        asn1_node_tag_number(node) == 0) {
        return ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER;
    }
    return -1;
}

/* TBSCertificate 字段访问：仅证书分支可用。 */
asn1_err_t certificateTbsField(const handle_base *signed_data,
                               size_t index, const char *name,
                               const asn1_node_t **out_node) noexcept
{
    const asn1_node_t *item = nullptr;
    asn1_err_t status =
        collectionItem(signed_data, "certificates", index, &item);
    if (status != ASN1_OK) {
        return status;
    }
    if (certificateChoiceKind(item) != ASN1_CMS_CERT_CHOICE_CERTIFICATE) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *tbs = nestedField(item, "toBeSigned");
    if (tbs == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_node = nestedField(tbs, name);
    return (*out_node == nullptr) ? ASN1_E_SCHEMA_FIELD : ASN1_OK;
}

asn1_err_t signerField(const handle_base *signed_data, size_t index,
                       const char *name, const asn1_node_t **out_node) noexcept
{
    const asn1_node_t *signer = nullptr;
    asn1_err_t status =
        collectionItem(signed_data, "signerInfos", index, &signer);
    if (status != ASN1_OK) {
        return status;
    }
    *out_node = nestedField(signer, name);
    return (*out_node == nullptr) ? ASN1_E_SCHEMA_FIELD : ASN1_OK;
}

} // namespace

/* ------------------------------------------------------------------------- */
/* ContentInfo                                                                */
/* ------------------------------------------------------------------------- */

struct asn1_cms_content_info : handle_base {};

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_content_info_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_cms_content_info_t **out_info)
{
    return openStructure(ctx, der, der_size, cmsContentInfoTable(), out_info);
}

extern "C" ASN1_CMS_API void asn1_cms_content_info_close(
    asn1_cms_content_info_t *info)
{
    closeStructure(info);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_content_info_content_type(
    const asn1_cms_content_info_t *info, const char **out_dotted,
    size_t *out_size)
{
    if (info == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(info, "contentType", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_content_info_content(
    const asn1_cms_content_info_t *info, const uint8_t **out_data,
    size_t *out_size)
{
    if (info == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(info, "content", &node);
    if (status != ASN1_OK) {
        return status;
    }
    /* [0] EXPLICIT ANY：content 给出内层 ANY 的完整原始 TLV。 */
    return asn1_node_content(node, out_data, out_size);
}

/* ------------------------------------------------------------------------- */
/* SignedData                                                                 */
/* ------------------------------------------------------------------------- */

struct asn1_cms_signed_data : handle_base {};

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_open(
    asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
    asn1_cms_signed_data_t **out_signed_data)
{
    return openStructure(ctx, der, der_size, cmsSignedDataTable(),
                         out_signed_data);
}

extern "C" ASN1_CMS_API void asn1_cms_signed_data_close(
    asn1_cms_signed_data_t *signed_data)
{
    closeStructure(signed_data);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_version(
    const asn1_cms_signed_data_t *signed_data, int64_t *out_version)
{
    if (signed_data == nullptr || out_version == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = requireField(signed_data, "version", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_int64(node, out_version);
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_digest_algorithm_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "digestAlgorithms",
                                   out_count);
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_digest_algorithm_at(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (signed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *algorithm = nullptr;
    asn1_err_t status =
        collectionItem(signed_data, "digestAlgorithms", index, &algorithm);
    if (status != ASN1_OK) {
        return status;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_encap_content_type(
    const asn1_cms_signed_data_t *signed_data, const char **out_dotted,
    size_t *out_size)
{
    if (signed_data == nullptr || out_dotted == nullptr ||
        out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *encap =
        field(signed_data, "encapContentInfo");
    const asn1_node_t *node = nestedField(encap, "eContentType");
    if (node == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    return asn1_node_get_oid(node, out_dotted, out_size);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_encap_content(
    const asn1_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *encap =
        field(signed_data, "encapContentInfo");
    const asn1_node_t *wrapper = nestedField(encap, "eContent");
    if (wrapper == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASN1_OK;
    }
    /*
     * eContent 为 [0] EXPLICIT OCTET STRING：节点是外层包装，
     * 唯一子节点才是 OCTET STRING。
     */
    const asn1_node_t *octets = asn1_node_child_at(wrapper, 0);
    if (octets == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    return asn1_node_get_octets(octets, out_data, out_size);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_encap_content_tlv(
    const asn1_cms_signed_data_t *signed_data, const uint8_t **out_data,
    size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *encap =
        field(signed_data, "encapContentInfo");
    const asn1_node_t *wrapper = nestedField(encap, "eContent");
    if (wrapper == nullptr) {
        *out_data = nullptr;
        *out_size = 0;
        return ASN1_OK;
    }
    const asn1_node_t *octets = asn1_node_child_at(wrapper, 0);
    if (octets == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_data = asn1_node_tlv(octets, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_certificate_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "certificates", out_count);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_certificate_at(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size)
{
    if (signed_data == nullptr || out_choice == nullptr ||
        out_tlv == nullptr || out_tlv_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *item = nullptr;
    asn1_err_t status =
        collectionItem(signed_data, "certificates", index, &item);
    if (status != ASN1_OK) {
        return status;
    }
    const int kind = certificateChoiceKind(item);
    if (kind < 0) {
        return ASN1_E_SCHEMA_TYPE;
    }
    *out_tlv = asn1_node_tlv(item, out_tlv_size);
    if (*out_tlv == nullptr) {
        return ASN1_E_INVALID_STATE;
    }
    *out_choice = kind;
    return ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_certificate_subject(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        certificateTbsField(signed_data, index, "subject", &node);
    if (status != ASN1_OK) {
        return status;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_certificate_issuer(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        certificateTbsField(signed_data, index, "issuer", &node);
    if (status != ASN1_OK) {
        return status;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_certificate_serial(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size)
{
    if (signed_data == nullptr || out_decimal == nullptr ||
        out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        certificateTbsField(signed_data, index, "serialNumber", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_bigint_decimal(node, out_decimal, out_size);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_crl_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "crls", out_count);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_crl_at(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int *out_choice, const uint8_t **out_tlv, size_t *out_tlv_size)
{
    if (signed_data == nullptr || out_choice == nullptr ||
        out_tlv == nullptr || out_tlv_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *item = nullptr;
    asn1_err_t status = collectionItem(signed_data, "crls", index, &item);
    if (status != ASN1_OK) {
        return status;
    }
    const int kind = revocationChoiceKind(item);
    if (kind < 0) {
        return ASN1_E_SCHEMA_TYPE;
    }
    *out_tlv = asn1_node_tlv(item, out_tlv_size);
    if (*out_tlv == nullptr) {
        return ASN1_E_INVALID_STATE;
    }
    *out_choice = kind;
    return ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_count(
    const asn1_cms_signed_data_t *signed_data, size_t *out_count)
{
    if (signed_data == nullptr || out_count == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    return optionalCollectionCount(signed_data, "signerInfos", out_count);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_version(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int64_t *out_version)
{
    if (signed_data == nullptr || out_version == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = signerField(signed_data, index, "version", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_int64(node, out_version);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_sid_choice(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    int *out_choice)
{
    if (signed_data == nullptr || out_choice == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status = signerField(signed_data, index, "sid", &node);
    if (status != ASN1_OK) {
        return status;
    }
    const int kind = signerIdChoiceKind(node);
    if (kind < 0) {
        return ASN1_E_SCHEMA_TYPE;
    }
    *out_choice = kind;
    return ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_sid_issuer(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *sid = nullptr;
    asn1_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASN1_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASN1_CMS_SID_ISSUER_AND_SERIAL) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *issuer = nestedField(sid, "issuer");
    if (issuer == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_data = asn1_node_tlv(issuer, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_sid_serial(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_decimal, size_t *out_size)
{
    if (signed_data == nullptr || out_decimal == nullptr ||
        out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *sid = nullptr;
    asn1_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASN1_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASN1_CMS_SID_ISSUER_AND_SERIAL) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *serial = nestedField(sid, "serialNumber");
    if (serial == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    return asn1_node_get_bigint_decimal(serial, out_decimal, out_size);
}

/* serialNumber 完整原始 TLV（供结构构造侧原样承载，避免十进制往返）。 */
extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_sid_serial_tlv(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *sid = nullptr;
    asn1_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASN1_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASN1_CMS_SID_ISSUER_AND_SERIAL) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *serial = nestedField(sid, "serialNumber");
    if (serial == nullptr) {
        return ASN1_E_SCHEMA_FIELD;
    }
    *out_data = asn1_node_tlv(serial, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

/*
 * SubjectKeyIdentifier 是 `[0] IMPLICIT OCTET STRING`：节点本身是
 * context 标签的基本类型，不满足 asn1_node_get_octets 的 UNIVERSAL 4
 * 前置条件，因此按基本节点内容读取（隐藏的 OCTET STRING 语义由 schema
 * 标签模型保证）。
 */
extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_sid_subject_key_identifier(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *sid = nullptr;
    asn1_err_t status = signerField(signed_data, index, "sid", &sid);
    if (status != ASN1_OK) {
        return status;
    }
    if (signerIdChoiceKind(sid) != ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1_node_content(sid, out_data, out_size);
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_digest_algorithm(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (signed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *algorithm = nullptr;
    asn1_err_t status =
        signerField(signed_data, index, "digestAlgorithm", &algorithm);
    if (status != ASN1_OK) {
        return status;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_signed_attrs(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        signerField(signed_data, index, "signedAttrs", &node);
    if (status == ASN1_E_SCHEMA_FIELD) {
        *out_data = nullptr;
        *out_size = 0;
        return ASN1_OK;
    }
    if (status != ASN1_OK) {
        return status;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_signature_algorithm(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const char **out_oid, size_t *out_oid_size,
    const uint8_t **out_parameters, size_t *out_parameters_size)
{
    if (signed_data == nullptr || out_oid == nullptr ||
        out_oid_size == nullptr || out_parameters == nullptr ||
        out_parameters_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *algorithm = nullptr;
    asn1_err_t status =
        signerField(signed_data, index, "signatureAlgorithm", &algorithm);
    if (status != ASN1_OK) {
        return status;
    }
    return algorithmFields(algorithm, out_oid, out_oid_size, out_parameters,
                           out_parameters_size);
}

extern "C" ASN1_CMS_API asn1_err_t asn1_cms_signed_data_signer_signature(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        signerField(signed_data, index, "signature", &node);
    if (status != ASN1_OK) {
        return status;
    }
    return asn1_node_get_octets(node, out_data, out_size);
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_signature_tlv(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        signerField(signed_data, index, "signature", &node);
    if (status != ASN1_OK) {
        return status;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}

extern "C" ASN1_CMS_API asn1_err_t
asn1_cms_signed_data_signer_unsigned_attrs(
    const asn1_cms_signed_data_t *signed_data, size_t index,
    const uint8_t **out_data, size_t *out_size)
{
    if (signed_data == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1_node_t *node = nullptr;
    asn1_err_t status =
        signerField(signed_data, index, "unsignedAttrs", &node);
    if (status == ASN1_E_SCHEMA_FIELD) {
        *out_data = nullptr;
        *out_size = 0;
        return ASN1_OK;
    }
    if (status != ASN1_OK) {
        return status;
    }
    *out_data = asn1_node_tlv(node, out_size);
    return (*out_data == nullptr) ? ASN1_E_INVALID_STATE : ASN1_OK;
}
