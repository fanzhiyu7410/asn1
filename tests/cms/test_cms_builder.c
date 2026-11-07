/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * asn1-cms 结构构造：builder 正例、负例与 5 份既有样本的
 * decode → 重建 → 编码逐字节往返。
 */

#include <asn1/asn1.h>
#include <asn1/cms/cms.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cert_rsa_selfsigned.h"
#include "../data/cms_rsa_attached.h"
#include "../data/cms_rsa_detached.h"
#include "../data/cms_rsa_ec_multicert.h"
#include "../data/cms_rsa_keyid.h"
#include "../data/cms_rsa_minimal.h"
#include "check.h"

static const char kSignedDataOid[] = "1.2.840.113549.1.7.2";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";

static const uint8_t kNullParams[2] = {0x05, 0x00};

static asn1_ctx_t *make_ctx(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    if (asn1_ctx_create(&config, &ctx) != ASN1_OK) {
        return NULL;
    }
    return ctx;
}

static int bytes_equal(const uint8_t *actual, size_t actual_size,
                       const uint8_t *expected, size_t expected_size)
{
    if (actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, expected_size) == 0;
}

static int text_equals(const char *actual, size_t actual_size,
                       const char *expected)
{
    const size_t expected_size = strlen(expected);
    if (actual == NULL || actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, actual_size) == 0;
}

/* 把 SET OF TLV 的外层 0x31 改写成目标标签，其余字节不变。 */
static int rewrite_outer_tag(const uint8_t *source, size_t source_size,
                             uint8_t tag, uint8_t **out_data,
                             size_t *out_size)
{
    uint8_t *copy = (uint8_t *)malloc(source_size);
    if (copy == NULL) {
        return ASN1_E_NOMEM;
    }
    memcpy(copy, source, source_size);
    copy[0] = tag;
    *out_data = copy;
    *out_size = source_size;
    return ASN1_OK;
}

/* 从既有样本读取全部字段并交给 builder 重建，编码后与原字节比较。 */
static int rebuild_sample(asn1_ctx_t *ctx, const uint8_t *der,
                          size_t der_size)
{
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;
    asn1_cms_builder_t *builder = NULL;
    asn1_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));

    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, der, der_size, &info) ==
                    ASN1_OK);

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        ASN1_TEST_CHECK(asn1_cms_content_info_content_type(info, &oid,
                                                           &oid_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, oid_size, kSignedDataOid));
    }

    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASN1_TEST_CHECK(asn1_cms_content_info_content(info, &content,
                                                      &content_size) == ASN1_OK);
        ASN1_TEST_CHECK(content != NULL && content_size > 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASN1_OK);
    }

    ASN1_TEST_CHECK(asn1_cms_builder_create(ctx, &builder) == ASN1_OK);

    {
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_cms_signed_data_version(signed_data, &version) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, version) ==
                        ASN1_OK);
    }

    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_digest_algorithm_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count > 0);
        for (size_t i = 0; i < count; ++i) {
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *params = NULL;
            size_t params_size = 0;
            ASN1_TEST_CHECK(asn1_cms_signed_data_digest_algorithm_at(
                                signed_data, i, &oid, &oid_size, &params,
                                &params_size) == ASN1_OK);
            ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                                builder, oid, params, params_size) == ASN1_OK);
        }
    }

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;

        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content_type(
                            signed_data, &oid, &oid_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, oid) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content(
                            signed_data, &octets, &octets_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content_tlv(
                            signed_data, &tlv, &tlv_size) == ASN1_OK);
        if (tlv != NULL) {
            ASN1_TEST_CHECK(octets != NULL);
            ASN1_TEST_CHECK(asn1_cms_builder_set_econtent(builder, tlv,
                                                          tlv_size) == ASN1_OK);
        } else {
            ASN1_TEST_CHECK(octets == NULL && octets_size == 0);
        }
    }

    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_count(signed_data,
                                                               &count) ==
                        ASN1_OK);
        for (size_t i = 0; i < count; ++i) {
            int choice = -1;
            const uint8_t *tlv = NULL;
            size_t tlv_size = 0;
            ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                                signed_data, i, &choice, &tlv, &tlv_size) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(choice == ASN1_CMS_CERT_CHOICE_CERTIFICATE);
            ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(builder, tlv,
                                                             tlv_size) ==
                            ASN1_OK);
        }
    }

    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_crl_count(signed_data, &count) ==
                        ASN1_OK);
        for (size_t i = 0; i < count; ++i) {
            int choice = -1;
            const uint8_t *tlv = NULL;
            size_t tlv_size = 0;
            ASN1_TEST_CHECK(asn1_cms_signed_data_crl_at(signed_data, i, &choice,
                                                        &tlv, &tlv_size) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(choice == ASN1_CMS_REVOCATION_CHOICE_CRL);
            ASN1_TEST_CHECK(asn1_cms_builder_add_crl(builder, tlv, tlv_size) ==
                            ASN1_OK);
        }
    }

    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_count(signed_data, &count) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(count > 0);
        for (size_t i = 0; i < count; ++i) {
            int64_t version = -1;
            int sid_choice = -1;
            const uint8_t *sid1 = NULL;
            size_t sid1_size = 0;
            const uint8_t *sid2 = NULL;
            size_t sid2_size = 0;
            const char *digest_oid = NULL;
            size_t digest_oid_size = 0;
            const uint8_t *digest_params = NULL;
            size_t digest_params_size = 0;
            const uint8_t *signed_attrs = NULL;
            size_t signed_attrs_size = 0;
            const char *sig_oid = NULL;
            size_t sig_oid_size = 0;
            const uint8_t *sig_params = NULL;
            size_t sig_params_size = 0;
            const uint8_t *signature = NULL;
            size_t signature_size = 0;
            const uint8_t *unsigned_attrs = NULL;
            size_t unsigned_attrs_size = 0;
            uint8_t *signed_attrs_in = NULL;
            uint8_t *unsigned_attrs_in = NULL;

            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_version(
                                signed_data, i, &version) == ASN1_OK);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_choice(
                                signed_data, i, &sid_choice) == ASN1_OK);
            if (sid_choice == ASN1_CMS_SID_ISSUER_AND_SERIAL) {
                ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_issuer(
                                    signed_data, i, &sid1, &sid1_size) ==
                                ASN1_OK);
                ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_serial_tlv(
                                    signed_data, i, &sid2, &sid2_size) ==
                                ASN1_OK);
            } else {
                ASN1_TEST_CHECK(
                    asn1_cms_signed_data_signer_sid_subject_key_identifier(
                        signed_data, i, &sid1, &sid1_size) == ASN1_OK);
                sid2 = NULL;
                sid2_size = 0;
            }

            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_digest_algorithm(
                                signed_data, i, &digest_oid, &digest_oid_size,
                                &digest_params, &digest_params_size) == ASN1_OK);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signed_attrs(
                                signed_data, i, &signed_attrs,
                                &signed_attrs_size) == ASN1_OK);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature_algorithm(
                                signed_data, i, &sig_oid, &sig_oid_size,
                                &sig_params, &sig_params_size) == ASN1_OK);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature(
                                signed_data, i, &signature, &signature_size) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_unsigned_attrs(
                                signed_data, i, &unsigned_attrs,
                                &unsigned_attrs_size) == ASN1_OK);

            if (signed_attrs != NULL) {
                ASN1_TEST_CHECK(rewrite_outer_tag(signed_attrs,
                                                  signed_attrs_size, 0x31,
                                                  &signed_attrs_in,
                                                  &signed_attrs_size) == ASN1_OK);
            }
            if (unsigned_attrs != NULL) {
                ASN1_TEST_CHECK(rewrite_outer_tag(unsigned_attrs,
                                                  unsigned_attrs_size, 0x31,
                                                  &unsigned_attrs_in,
                                                  &unsigned_attrs_size) ==
                                ASN1_OK);
            }

            ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                                builder, version, sid_choice, sid1, sid1_size,
                                sid2, sid2_size, digest_oid, digest_params,
                                digest_params_size, signed_attrs_in,
                                signed_attrs_size, sig_oid, sig_params,
                                sig_params_size, signature, signature_size,
                                unsigned_attrs_in, unsigned_attrs_size) ==
                            ASN1_OK);
            free(signed_attrs_in);
            free(unsigned_attrs_in);
        }
    }

    ASN1_TEST_CHECK(asn1_cms_builder_encode(builder, &encoded) == ASN1_OK);
    ASN1_TEST_CHECK(bytes_equal(encoded.data, encoded.size, der, der_size));

    asn1_buf_release(ctx, &encoded);
    asn1_cms_builder_destroy(builder);
    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    return 0;
}

static int roundtrip_all_samples(asn1_ctx_t *ctx)
{
    ASN1_TEST_CHECK(rebuild_sample(ctx, kCmsRsaAttached, kCmsRsaAttachedSize) ==
                    0);
    ASN1_TEST_CHECK(rebuild_sample(ctx, kCmsRsaDetached, kCmsRsaDetachedSize) ==
                    0);
    ASN1_TEST_CHECK(rebuild_sample(ctx, kCmsRsaEcMulticert,
                                   kCmsRsaEcMulticertSize) == 0);
    ASN1_TEST_CHECK(rebuild_sample(ctx, kCmsRsaKeyid, kCmsRsaKeyidSize) == 0);
    ASN1_TEST_CHECK(rebuild_sample(ctx, kCmsRsaMinimal, kCmsRsaMinimalSize) ==
                    0);
    return 0;
}

/* 构造一份最小 attached SignedData：无证书、issuerAndSerialNumber、无属性。 */
static int build_attached_minimal(asn1_ctx_t *ctx)
{
    static const uint8_t kEcontent[7] = {0x04, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F};
    static const uint8_t kIssuer[2] = {0x30, 0x00};
    static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
    static const uint8_t kSignature[3] = {0x01, 0x02, 0x03};

    asn1_cms_builder_t *builder = NULL;
    asn1_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASN1_TEST_CHECK(asn1_cms_builder_create(ctx, &builder) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, 1) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent(builder, kEcontent,
                                                  sizeof(kEcontent)) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                        builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial), kSha256Oid,
                        NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                        sizeof(kNullParams), kSignature, sizeof(kSignature),
                        NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_encode(builder, &encoded) == ASN1_OK);

    /* 回读结构字段。 */
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASN1_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASN1_TEST_CHECK(asn1_cms_content_info_content(info, &content,
                                                      &content_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASN1_OK);
    }
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content(
                            signed_data, &octets, &octets_size) == ASN1_OK);
        ASN1_TEST_CHECK(octets != NULL && octets_size == 5);
        ASN1_TEST_CHECK(memcmp(octets, "hello", 5) == 0);
    }
    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_count(signed_data,
                                                               &count) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(count == 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_count(signed_data,
                                                          &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
    }
    {
        const uint8_t *signature = NULL;
        size_t signature_size = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature(
                            signed_data, 0, &signature, &signature_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(signature, signature_size, kSignature,
                                    sizeof(kSignature)));
    }

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_buf_release(ctx, &encoded);
    asn1_cms_builder_destroy(builder);
    return 0;
}

/* 构造 detached：不设置 eContent。 */
static int build_detached(asn1_ctx_t *ctx)
{
    static const uint8_t kIssuer[2] = {0x30, 0x00};
    static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
    static const uint8_t kSignature[2] = {0xAA, 0xBB};

    asn1_cms_builder_t *builder = NULL;
    asn1_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASN1_TEST_CHECK(asn1_cms_builder_create(ctx, &builder) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, 1) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                        builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, kIssuer,
                        sizeof(kIssuer), kSerial, sizeof(kSerial), kSha256Oid,
                        NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                        sizeof(kNullParams), kSignature, sizeof(kSignature),
                        NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_encode(builder, &encoded) == ASN1_OK);

    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASN1_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASN1_TEST_CHECK(asn1_cms_content_info_content(info, &content,
                                                      &content_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASN1_OK);
    }
    {
        const uint8_t *octets = NULL;
        size_t octets_size = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content(
                            signed_data, &octets, &octets_size) == ASN1_OK);
        ASN1_TEST_CHECK(octets == NULL && octets_size == 0);
    }
    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_buf_release(ctx, &encoded);
    asn1_cms_builder_destroy(builder);
    return 0;
}

/* 多证书：逆序追加，输出按 DER SET OF 排序。 */
static int build_multicert(asn1_ctx_t *ctx)
{
    asn1_cms_content_info_t *source_info = NULL;
    asn1_cms_signed_data_t *source_signed = NULL;
    const uint8_t *cert0 = NULL;
    const uint8_t *cert1 = NULL;
    size_t cert0_size = 0;
    size_t cert1_size = 0;

    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, kCmsRsaEcMulticert,
                                               kCmsRsaEcMulticertSize,
                                               &source_info) == ASN1_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASN1_TEST_CHECK(asn1_cms_content_info_content(source_info, &content,
                                                      &content_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                                  &source_signed) == ASN1_OK);
    }
    {
        int choice = -1;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                            source_signed, 0, &choice, &cert0, &cert0_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                            source_signed, 1, &choice, &cert1, &cert1_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(choice == ASN1_CMS_CERT_CHOICE_CERTIFICATE);
    }

    asn1_cms_builder_t *builder = NULL;
    asn1_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASN1_TEST_CHECK(asn1_cms_builder_create(ctx, &builder) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, 1) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(builder, cert1,
                                                     cert1_size) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(builder, cert0,
                                                     cert0_size) == ASN1_OK);
    {
        static const uint8_t kIssuer[2] = {0x30, 0x00};
        static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
        static const uint8_t kSignature[2] = {0xCC, 0xDD};
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, kIssuer,
                            sizeof(kIssuer), kSerial, sizeof(kSerial),
                            kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kSignature,
                            sizeof(kSignature), NULL, 0) == ASN1_OK);
    }
    ASN1_TEST_CHECK(asn1_cms_builder_encode(builder, &encoded) == ASN1_OK);

    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASN1_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        const uint8_t *actual = NULL;
        size_t actual_size = 0;
        int choice = -1;
        ASN1_TEST_CHECK(asn1_cms_content_info_content(info, &content,
                                                      &content_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                            signed_data, 0, &choice, &actual, &actual_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(actual, actual_size, cert0, cert0_size));
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                            signed_data, 1, &choice, &actual, &actual_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(actual, actual_size, cert1, cert1_size));
    }
    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_buf_release(ctx, &encoded);
    asn1_cms_builder_destroy(builder);
    asn1_cms_signed_data_close(source_signed);
    asn1_cms_content_info_close(source_info);
    return 0;
}

/* subjectKeyIdentifier 形式 sid + signedAttrs 原样承载。 */
static int build_keyid_with_attrs(asn1_ctx_t *ctx)
{
    static const uint8_t kSki[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const uint8_t kSignature[2] = {0x11, 0x22};
    /* Attribute ::= SEQUENCE { attrType contentType OID,
       attrValues SET OF OID data }。 */
    static const uint8_t kSignedAttrs[28] = {
        0x31, 0x1A, 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31, 0x0B, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};

    asn1_cms_builder_t *builder = NULL;
    asn1_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASN1_TEST_CHECK(asn1_cms_builder_create(ctx, &builder) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, 3) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                        builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER, kSki,
                        sizeof(kSki), NULL, 0, kSha256Oid, NULL, 0,
                        kSignedAttrs, sizeof(kSignedAttrs), kRsaEncryptionOid,
                        kNullParams, sizeof(kNullParams), kSignature,
                        sizeof(kSignature), NULL, 0) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_encode(builder, &encoded) == ASN1_OK);

    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, encoded.data, encoded.size,
                                               &info) == ASN1_OK);
    {
        const uint8_t *content = NULL;
        size_t content_size = 0;
        int sid_choice = -1;
        const uint8_t *ski = NULL;
        size_t ski_size = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_cms_content_info_content(info, &content,
                                                      &content_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                                  &signed_data) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_signed_data_version(signed_data, &version) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(version == 3);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASN1_OK);
        ASN1_TEST_CHECK(sid_choice == ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER);
        ASN1_TEST_CHECK(
            asn1_cms_signed_data_signer_sid_subject_key_identifier(
                signed_data, 0, &ski, &ski_size) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(ski, ski_size, kSki, sizeof(kSki)));
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASN1_OK);
        ASN1_TEST_CHECK(attrs != NULL && attrs_size == sizeof(kSignedAttrs));
        ASN1_TEST_CHECK(attrs[0] == 0xA0);
        ASN1_TEST_CHECK(memcmp(attrs + 1, kSignedAttrs + 1,
                               attrs_size - 1) == 0);
    }
    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_buf_release(ctx, &encoded);
    asn1_cms_builder_destroy(builder);
    return 0;
}

/* 负例：必填缺失、重复设置、非法 OID / TLV / 属性集合。 */
static int builder_negative_cases(asn1_ctx_t *ctx)
{
    asn1_cms_builder_t *builder = NULL;
    asn1_buf_t encoded;
    memset(&encoded, 0, sizeof(encoded));
    ASN1_TEST_CHECK(asn1_cms_builder_create(ctx, &builder) == ASN1_OK);

    /* 必填缺失。 */
    ASN1_TEST_CHECK(asn1_cms_builder_encode(builder, &encoded) ==
                    ASN1_E_INVALID_STATE);

    ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, 1) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_version(builder, 2) ==
                    ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_builder_set_econtent_type(builder, kDataOid) ==
                    ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                        builder, "1.2.3.4.5.", NULL, 0) == ASN1_E_INVALID_VALUE);
    ASN1_TEST_CHECK(asn1_cms_builder_add_digest_algorithm(
                        builder, kSha256Oid, kNullParams, sizeof(kNullParams)) ==
                    ASN1_OK);

    {
        static const uint8_t kTruncated[3] = {0x30, 0x02, 0x02};
        static const uint8_t kTrailing[4] = {0x05, 0x00, 0xAA, 0xBB};
        static const uint8_t kNotOctets[2] = {0x05, 0x00};
        /* 两个 Attribute 逆序排列，违反 DER SET OF 排序规则。 */
        static const uint8_t kUnorderedSet[24] = {
            0x31, 0x16, 0x30, 0x09, 0x06, 0x02, 0x2A, 0x04, 0x31, 0x03,
            0x02, 0x01, 0x01, 0x30, 0x09, 0x06, 0x02, 0x2A, 0x03, 0x31,
            0x03, 0x02, 0x01, 0x01};

        ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(
                            builder, kTruncated, sizeof(kTruncated)) ==
                        ASN1_E_TRUNCATED);
        ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(
                            builder, kTrailing, sizeof(kTrailing)) ==
                        ASN1_E_TRAILING_DATA);
        ASN1_TEST_CHECK(asn1_cms_builder_set_econtent(builder, kNotOctets,
                                                      sizeof(kNotOctets)) ==
                        ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_set_econtent(builder, kTruncated,
                                                      sizeof(kTruncated)) ==
                        ASN1_E_TRUNCATED);
        /* 非法 sid_kind。 */
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, 7, kNotOctets, sizeof(kNotOctets), NULL,
                            0, kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) == ASN1_E_INVALID_VALUE);
        /* subjectKeyIdentifier 形态不接受 sid2。 */
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kNotOctets, sizeof(kNotOctets), kNotOctets,
                            sizeof(kNotOctets), kSha256Oid, NULL, 0, NULL, 0,
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) == ASN1_E_INVALID_ARG);
        /* signedAttrs 必须是 SET，非 SET 标签被拒。 */
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kNotOctets, sizeof(kNotOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kNotOctets, sizeof(kNotOctets),
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) == ASN1_E_INVALID_VALUE);
        /* 非规范（未排序）SET OF 被拒。 */
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kNotOctets, sizeof(kNotOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kUnorderedSet,
                            sizeof(kUnorderedSet), kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kNotOctets,
                            sizeof(kNotOctets), NULL, 0) ==
                        ASN1_E_NON_CANONICAL);
    }

    {
        /* CertificateChoices / RevocationInfoChoice 根标签校验。 */
        static const uint8_t kName[2] = {0x30, 0x00};
        static const uint8_t kSerial[3] = {0x02, 0x01, 0x01};
        static const uint8_t kOctets[2] = {0x04, 0x00};
        static const uint8_t kCertAlt[4] = {0xA0, 0x02, 0x30, 0x00};
        static const uint8_t kCrlOther[4] = {0xA1, 0x02, 0x30, 0x00};
        static const uint8_t kEmptySet[2] = {0x31, 0x00};
        static const uint8_t kIntSet[5] = {0x31, 0x03, 0x02, 0x01, 0x01};
        static const uint8_t kAttributeSet[9] = {
            0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04};

        ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(
                            builder, kOctets, sizeof(kOctets)) ==
                        ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_certificate(
                            builder, kCertAlt, sizeof(kCertAlt)) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_cms_builder_add_crl(builder, kOctets,
                                                 sizeof(kOctets)) ==
                        ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_crl(builder, kCrlOther,
                                                 sizeof(kCrlOther)) == ASN1_OK);

        /* issuer 必须是 SEQUENCE，serialNumber 必须是 INTEGER。 */
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, kOctets,
                            sizeof(kOctets), kSerial, sizeof(kSerial),
                            kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kOctets,
                            sizeof(kOctets), NULL, 0) == ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, kName,
                            sizeof(kName), kOctets, sizeof(kOctets), kSha256Oid,
                            NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, kName,
                            sizeof(kName), kSerial, sizeof(kSerial), kSha256Oid,
                            NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASN1_OK);

        /* signedAttrs / unsignedAttrs 必须是非空 SET OF Attribute。 */
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kEmptySet, sizeof(kEmptySet),
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kIntSet, sizeof(kIntSet),
                            kRsaEncryptionOid, kNullParams,
                            sizeof(kNullParams), kOctets, sizeof(kOctets), NULL,
                            0) == ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kAttributeSet,
                            sizeof(kAttributeSet), kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kOctets,
                            sizeof(kOctets), kEmptySet,
                            sizeof(kEmptySet)) == ASN1_E_INVALID_VALUE);
        ASN1_TEST_CHECK(asn1_cms_builder_add_signer(
                            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER,
                            kOctets, sizeof(kOctets), NULL, 0,
                            kSha256Oid, NULL, 0, kAttributeSet,
                            sizeof(kAttributeSet), kRsaEncryptionOid,
                            kNullParams, sizeof(kNullParams), kOctets,
                            sizeof(kOctets), kAttributeSet,
                            sizeof(kAttributeSet)) == ASN1_OK);
    }

    asn1_cms_builder_destroy(builder);
    asn1_cms_builder_destroy(NULL);
    return 0;
}

int main(void)
{
    asn1_ctx_t *ctx = make_ctx();
    ASN1_TEST_CHECK(ctx != NULL);

    ASN1_TEST_CHECK(roundtrip_all_samples(ctx) == 0);
    ASN1_TEST_CHECK(build_attached_minimal(ctx) == 0);
    ASN1_TEST_CHECK(build_detached(ctx) == 0);
    ASN1_TEST_CHECK(build_multicert(ctx) == 0);
    ASN1_TEST_CHECK(build_keyid_with_attrs(ctx) == 0);
    ASN1_TEST_CHECK(builder_negative_cases(ctx) == 0);

    asn1_ctx_destroy(ctx);
    return 0;
}
