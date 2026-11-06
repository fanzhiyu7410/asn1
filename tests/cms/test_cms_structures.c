/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * asn1-cms 只读结构访问：ContentInfo / SignedData。
 * 覆盖 attached/detached、多证书、无证书最小样本、SignerInfo 字段（含
 * subjectKeyIdentifier 形式的 sid）与负例。
 */

#include <asn1/asn1.h>
#include <asn1/cms/cms.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/cms_rsa_attached.h"
#include "../data/cms_rsa_detached.h"
#include "../data/cms_rsa_ec_multicert.h"
#include "../data/cms_rsa_keyid.h"
#include "../data/cms_rsa_minimal.h"
#include "../data/cert_rsa_selfsigned.h"
#include "check.h"

static const char kSignedDataOid[] = "1.2.840.113549.1.7.2";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";

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

static int text_equals(const char *actual, size_t actual_size,
                       const char *expected)
{
    size_t expected_size = strlen(expected);
    if (actual == NULL || actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, actual_size) == 0;
}

/* ContentInfo -> SignedData；两者由调用方 close。 */
static int open_signed_data(asn1_ctx_t *ctx, const unsigned char *der,
                            size_t der_size,
                            asn1_cms_content_info_t **out_info,
                            asn1_cms_signed_data_t **out_signed)
{
    const uint8_t *content = NULL;
    size_t content_size = 0;

    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, der, der_size, out_info) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_cms_content_info_content(*out_info, &content,
                                                  &content_size) == ASN1_OK);
    ASN1_TEST_CHECK(content != NULL && content_size > 0);
    ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, content, content_size,
                                              out_signed) == ASN1_OK);
    return 0;
}

/* ---------- attached：完整内容 + 单证书 ---------- */

static int test_attached(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(open_signed_data(ctx, kCmsRsaAttached,
                                     kCmsRsaAttachedSize, &info,
                                     &signed_data) == 0);

    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_cms_content_info_content_type(info, &oid,
                                                           &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, kSignedDataOid));
    }

    {
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_cms_signed_data_version(
                            signed_data, &version) == ASN1_OK);
        ASN1_TEST_CHECK(version == 1);
    }

    {
        size_t count = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;

        ASN1_TEST_CHECK(asn1_cms_signed_data_digest_algorithm_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
        ASN1_TEST_CHECK(asn1_cms_signed_data_digest_algorithm_at(
                            signed_data, 0, &oid, &oid_size, &params,
                            &params_size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
        /* 本样本的摘要算法省略 parameters，缺省返回 NULL/0。 */
        ASN1_TEST_CHECK(params == NULL && params_size == 0);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t data_size = 0;
        size_t tlv_size = 0;

        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content_type(
                            signed_data, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, kDataOid));
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content(
                            signed_data, &data, &data_size) == ASN1_OK);
        ASN1_TEST_CHECK(data != NULL && data_size > 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content_tlv(
                            signed_data, &tlv, &tlv_size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv != NULL && tlv_size > data_size);
        ASN1_TEST_CHECK(tlv[0] == 0x04);
    }

    {
        size_t count = 0;
        int choice = -1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *subject = NULL;
        const uint8_t *issuer = NULL;
        size_t subject_size = 0;
        size_t issuer_size = 0;
        const char *serial = NULL;
        size_t serial_size = 0;

        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                            signed_data, 0, &choice, &tlv, &tlv_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(choice == ASN1_CMS_CERT_CHOICE_CERTIFICATE);
        ASN1_TEST_CHECK(tlv != NULL && tlv_size > 0 && tlv[0] == 0x30);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_subject(
                            signed_data, 0, &subject, &subject_size) == ASN1_OK);
        ASN1_TEST_CHECK(subject != NULL && subject_size > 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_issuer(
                            signed_data, 0, &issuer, &issuer_size) == ASN1_OK);
        ASN1_TEST_CHECK(issuer != NULL && issuer_size > 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_serial(
                            signed_data, 0, &serial, &serial_size) == ASN1_OK);
        ASN1_TEST_CHECK(serial != NULL && serial_size > 0);
    }

    {
        size_t count = 99;
        ASN1_TEST_CHECK(asn1_cms_signed_data_crl_count(signed_data, &count) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(count == 0);
    }

    {
        size_t count = 0;
        int64_t version = -1;
        int sid_choice = -1;
        const uint8_t *issuer = NULL;
        size_t issuer_size = 0;
        const char *serial = NULL;
        size_t serial_size = 0;
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        const uint8_t *signature = NULL;
        size_t signature_size = 0;

        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_version(
                            signed_data, 0, &version) == ASN1_OK);
        ASN1_TEST_CHECK(version == 1);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASN1_OK);
        ASN1_TEST_CHECK(sid_choice == ASN1_CMS_SID_ISSUER_AND_SERIAL);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_issuer(
                            signed_data, 0, &issuer, &issuer_size) == ASN1_OK);
        ASN1_TEST_CHECK(issuer != NULL && issuer_size > 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_serial(
                            signed_data, 0, &serial, &serial_size) == ASN1_OK);
        ASN1_TEST_CHECK(serial != NULL && serial_size > 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_digest_algorithm(
                            signed_data, 0, &oid, &oid_size, &params,
                            &params_size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, oid_size, kSha256Oid));
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASN1_OK);
        ASN1_TEST_CHECK(attrs != NULL && attrs_size > 0 && attrs[0] == 0xA0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature_algorithm(
                            signed_data, 0, &oid, &oid_size, &params,
                            &params_size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, oid_size, kRsaEncryptionOid));
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature(
                            signed_data, 0, &signature,
                            &signature_size) == ASN1_OK);
        ASN1_TEST_CHECK(signature != NULL && signature_size > 0);
        /* OpenSSL 默认不写 unsignedAttrs。 */
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_unsigned_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASN1_OK);
        ASN1_TEST_CHECK(attrs == NULL && attrs_size == 0);
    }

    /* 越界与错误分支判别。 */
    {
        int choice = -1;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        const uint8_t *subject = NULL;
        size_t subject_size = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                            signed_data, 99, &choice, &tlv, &tlv_size) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_subject(
                            signed_data, 99, &subject, &subject_size) ==
                        ASN1_E_INVALID_ARG);
        int64_t out_of_range_version = -1;
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_version(
                            signed_data, 99, &out_of_range_version) ==
                        ASN1_E_INVALID_ARG);
    }

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- detached：无 eContent，仍有证书与 signedAttrs ---------- */

static int test_detached(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(open_signed_data(ctx, kCmsRsaDetached,
                                     kCmsRsaDetachedSize, &info,
                                     &signed_data) == 0);

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t data_size = 99;
        size_t tlv_size = 99;

        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content_type(
                            signed_data, &oid, &oid_size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, oid_size, kDataOid));
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content(
                            signed_data, &data, &data_size) == ASN1_OK);
        ASN1_TEST_CHECK(data == NULL && data_size == 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content_tlv(
                            signed_data, &tlv, &tlv_size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv == NULL && tlv_size == 0);
    }

    {
        size_t count = 0;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASN1_OK);
        ASN1_TEST_CHECK(attrs != NULL && attrs_size > 0 && attrs[0] == 0xA0);
    }

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- 最小样本：无证书、无 signedAttrs ---------- */

static int test_minimal(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(open_signed_data(ctx, kCmsRsaMinimal,
                                     kCmsRsaMinimalSize, &info,
                                     &signed_data) == 0);

    {
        size_t count = 99;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_crl_count(signed_data, &count) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(count == 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_count(signed_data,
                                                          &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 1);
    }

    {
        const uint8_t *data = NULL;
        size_t data_size = 99;
        const uint8_t *attrs = NULL;
        size_t attrs_size = 99;
        const uint8_t *signature = NULL;
        size_t signature_size = 0;
        int sid_choice = -1;

        ASN1_TEST_CHECK(asn1_cms_signed_data_encap_content(
                            signed_data, &data, &data_size) == ASN1_OK);
        ASN1_TEST_CHECK(data == NULL && data_size == 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signed_attrs(
                            signed_data, 0, &attrs, &attrs_size) == ASN1_OK);
        ASN1_TEST_CHECK(attrs == NULL && attrs_size == 0);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASN1_OK);
        ASN1_TEST_CHECK(sid_choice == ASN1_CMS_SID_ISSUER_AND_SERIAL);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature(
                            signed_data, 0, &signature,
                            &signature_size) == ASN1_OK);
        ASN1_TEST_CHECK(signature != NULL && signature_size > 0);
    }

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- 多证书：逐项访问两个证书与两个 SignerInfo ---------- */

static int test_multicert(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(open_signed_data(ctx, kCmsRsaEcMulticert,
                                     kCmsRsaEcMulticertSize, &info,
                                     &signed_data) == 0);

    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_count(
                            signed_data, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 2);

        for (size_t i = 0; i < count; ++i) {
            int choice = -1;
            const uint8_t *tlv = NULL;
            size_t tlv_size = 0;
            const uint8_t *subject = NULL;
            const uint8_t *issuer = NULL;
            size_t subject_size = 0;
            size_t issuer_size = 0;
            const char *serial = NULL;
            size_t serial_size = 0;

            ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_at(
                                signed_data, i, &choice, &tlv,
                                &tlv_size) == ASN1_OK);
            ASN1_TEST_CHECK(choice == ASN1_CMS_CERT_CHOICE_CERTIFICATE);
            ASN1_TEST_CHECK(tlv != NULL && tlv_size > 0 && tlv[0] == 0x30);
            ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_subject(
                                signed_data, i, &subject, &subject_size) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(subject != NULL && subject_size > 0);
            ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_issuer(
                                signed_data, i, &issuer, &issuer_size) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(issuer != NULL && issuer_size > 0);
            ASN1_TEST_CHECK(asn1_cms_signed_data_certificate_serial(
                                signed_data, i, &serial, &serial_size) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(serial != NULL && serial_size > 0);
        }
    }

    {
        size_t count = 0;
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_count(signed_data,
                                                          &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 2);
        for (size_t i = 0; i < count; ++i) {
            int sid_choice = -1;
            const uint8_t *signature = NULL;
            size_t signature_size = 0;
            const char *oid = NULL;
            size_t oid_size = 0;
            const uint8_t *params = NULL;
            size_t params_size = 0;

            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_choice(
                                signed_data, i, &sid_choice) == ASN1_OK);
            ASN1_TEST_CHECK(sid_choice == ASN1_CMS_SID_ISSUER_AND_SERIAL);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature_algorithm(
                                signed_data, i, &oid, &oid_size, &params,
                                &params_size) == ASN1_OK);
            ASN1_TEST_CHECK(oid != NULL && oid_size > 0);
            ASN1_TEST_CHECK(asn1_cms_signed_data_signer_signature(
                                signed_data, i, &signature,
                                &signature_size) == ASN1_OK);
            ASN1_TEST_CHECK(signature != NULL && signature_size > 0);
        }
    }

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- subjectKeyIdentifier 形式的 sid ---------- */

static int test_keyid(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(open_signed_data(ctx, kCmsRsaKeyid, kCmsRsaKeyidSize, &info,
                                     &signed_data) == 0);

    {
        int sid_choice = -1;
        const uint8_t *key_id = NULL;
        size_t key_id_size = 0;
        const uint8_t *issuer = NULL;
        size_t issuer_size = 0;
        const char *serial = NULL;
        size_t serial_size = 0;

        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_choice(
                            signed_data, 0, &sid_choice) == ASN1_OK);
        ASN1_TEST_CHECK(sid_choice == ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER);
        ASN1_TEST_CHECK(
            asn1_cms_signed_data_signer_sid_subject_key_identifier(
                signed_data, 0, &key_id, &key_id_size) == ASN1_OK);
        ASN1_TEST_CHECK(key_id != NULL && key_id_size > 0);
        /* 两种 issuerAndSerialNumber 访问器在该分支必须拒绝。 */
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_issuer(
                            signed_data, 0, &issuer, &issuer_size) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_sid_serial(
                            signed_data, 0, &serial, &serial_size) ==
                        ASN1_E_INVALID_ARG);
    }

    {
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_cms_signed_data_signer_version(
                            signed_data, 0, &version) == ASN1_OK);
        /* subjectKeyIdentifier 形式的 sid 对应 CMSVersion v3。 */
        ASN1_TEST_CHECK(version == 3);
    }

    asn1_cms_signed_data_close(signed_data);
    asn1_cms_content_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_cms_content_info_t *info = NULL;
    asn1_cms_signed_data_t *signed_data = NULL;
    uint8_t *truncated = NULL;

    ASN1_TEST_CHECK(ctx != NULL);

    /* 空参。 */
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, NULL, 1, &info) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, kCmsRsaAttached, 0,
                                               &info) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, kCmsRsaAttached,
                                               kCmsRsaAttachedSize,
                                               NULL) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, NULL, 1, &signed_data) ==
                    ASN1_E_INVALID_ARG);

    /* 非 CMS 输入（X.509 证书 DER）。 */
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &info) != ASN1_OK);
    ASN1_TEST_CHECK(info == NULL);

    /* 用 ContentInfo 整段喂给 SignedData：根结构不符。 */
    ASN1_TEST_CHECK(asn1_cms_signed_data_open(ctx, kCmsRsaAttached,
                                              kCmsRsaAttachedSize,
                                              &signed_data) != ASN1_OK);
    ASN1_TEST_CHECK(signed_data == NULL);

    /* 截断（保留外层头与 contentType，丢掉 content）。 */
    truncated = (uint8_t *)malloc(40);
    ASN1_TEST_CHECK(truncated != NULL);
    memcpy(truncated, kCmsRsaAttached, 40);
    ASN1_TEST_CHECK(asn1_cms_content_info_open(ctx, truncated, 40, &info) !=
                    ASN1_OK);
    ASN1_TEST_CHECK(info == NULL);
    free(truncated);

    /* 访问器空参。 */
    ASN1_TEST_CHECK(asn1_cms_content_info_content_type(NULL, NULL, NULL) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_cms_content_info_content(NULL, NULL, NULL) ==
                    ASN1_E_INVALID_ARG);

    asn1_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_attached() != 0) {
        return 1;
    }
    if (test_detached() != 0) {
        return 1;
    }
    if (test_minimal() != 0) {
        return 1;
    }
    if (test_multicert() != 0) {
        return 1;
    }
    if (test_keyid() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
