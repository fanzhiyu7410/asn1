/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * asn1-pkix 模块：真实证书字段访问、ANY 三形态、句柄隔离与负例。
 */

#include <asn1/asn1.h>
#include <asn1/pkix/pkix.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_pss_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "../data/key_rsa_pkcs8.h"
#include "check.h"

/* ---------- 辅助 ---------- */

/* 版本同源：CMake 生成头宏、模块运行时字符串与核心运行时字符串一致。 */
static int test_module_version(void)
{
    const char *runtime = asn1_pkix_version_string();
    asn1_version_info_t info;

    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASN1_TEST_CHECK(runtime != NULL);
    ASN1_TEST_CHECK(strcmp(runtime, ASN1_PKIX_VERSION_STRING) == 0);
    ASN1_TEST_CHECK(asn1_version(&info) == ASN1_OK);
    ASN1_TEST_CHECK(info.string != NULL);
    ASN1_TEST_CHECK(strcmp(runtime, info.string) == 0);
    return 0;
}

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
                       const void *expected, size_t expected_size)
{
    if (actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, expected_size) == 0;
}

/* 在 RDNSequence 中查找与 expected 完全相等的文本（本测试用它定位 CN）。 */
static int find_text(const asn1_node_t *name, const char *expected)
{
    size_t sets = asn1_node_child_count(name);
    size_t i;
    for (i = 0; i < sets; ++i) {
        const asn1_node_t *set = asn1_node_child_at(name, i);
        size_t j;
        for (j = 0; j < asn1_node_child_count(set); ++j) {
            const asn1_node_t *pair = asn1_node_child_at(set, j);
            const char *text = NULL;
            size_t text_size = 0;
            if (asn1_node_child_count(pair) != 2) {
                continue;
            }
            if (asn1_node_get_utf8(asn1_node_child_at(pair, 1), &text,
                                   &text_size) != ASN1_OK) {
                continue;
            }
            if (text_size == strlen(expected) &&
                memcmp(text, expected, text_size) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* [n] EXPLICIT 包装内的 SEQUENCE 元素数，否则直接返回子节点数。 */
static size_t sequence_item_count(const asn1_node_t *node)
{
    if (asn1_node_tag_class(node) == ASN1_TAG_CONTEXT &&
        asn1_node_child_count(node) == 1) {
        node = asn1_node_child_at(node, 0);
    }
    return asn1_node_child_count(node);
}

typedef struct cert_expectation {
    const uint8_t *der;
    size_t der_size;
    const char *signature_oid;
    const char *serial_decimal;
    const char *cn;
    int32_t not_before_year;
    uint8_t not_before_month;
    uint8_t not_before_day;
    uint8_t not_before_second;
    int32_t not_after_year;
    uint8_t not_after_month;
    uint8_t not_after_day;
    uint8_t not_after_second;
} cert_expectation_t;

static int check_certificate(const cert_expectation_t *expected,
                             int check_any_shapes)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkix_certificate_t *cert = NULL;
    asn1_err_t status;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx, expected->der,
                                               expected->der_size,
                                               &cert) == ASN1_OK);
    ASN1_TEST_CHECK(cert != NULL);

    {
        uint32_t version = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_version(cert, &version) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(version == 2);
    }

    {
        const char *serial = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_serial_number(cert, &serial,
                                                            &size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(serial != NULL);
        ASN1_TEST_CHECK(size == strlen(expected->serial_decimal));
        ASN1_TEST_CHECK(memcmp(serial, expected->serial_decimal, size) == 0);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_signature_algorithm_oid(
                            cert, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(oid != NULL);
        ASN1_TEST_CHECK(size == strlen(expected->signature_oid));
        ASN1_TEST_CHECK(memcmp(oid, expected->signature_oid, size) == 0);
    }

    {
        const uint8_t *bits = NULL;
        size_t size = 0;
        size_t bit_length = 0;
        uint8_t unused = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_signature_value(
                            cert, &bits, &size, &bit_length, &unused) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bits != NULL);
        ASN1_TEST_CHECK(size > 0);
        ASN1_TEST_CHECK(unused <= 7);
        ASN1_TEST_CHECK(bit_length == size * 8 - unused);
    }

    {
        const uint8_t *subject = NULL;
        const uint8_t *issuer = NULL;
        size_t subject_size = 0;
        size_t issuer_size = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_subject_der(
                            cert, &subject, &subject_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_pkix_certificate_issuer_der(
                            cert, &issuer, &issuer_size) == ASN1_OK);
        ASN1_TEST_CHECK(subject != NULL && issuer != NULL);
        ASN1_TEST_CHECK(subject_size == issuer_size);
        ASN1_TEST_CHECK(bytes_equal(subject, subject_size, issuer,
                                    issuer_size));
    }

    {
        asn1_time_t before;
        asn1_time_t after;
        memset(&before, 0, sizeof(before));
        memset(&after, 0, sizeof(after));
        before.struct_size = sizeof(before);
        after.struct_size = sizeof(after);
        ASN1_TEST_CHECK(asn1_pkix_certificate_validity(cert, &before,
                                                       &after) == ASN1_OK);
        ASN1_TEST_CHECK(before.year == expected->not_before_year);
        ASN1_TEST_CHECK(before.month == expected->not_before_month);
        ASN1_TEST_CHECK(before.day == expected->not_before_day);
        ASN1_TEST_CHECK(before.second == expected->not_before_second);
        ASN1_TEST_CHECK((before.flags & ASN1_TIME_UTC) != 0);
        ASN1_TEST_CHECK((before.flags & ASN1_TIME_HAS_OFFSET) == 0);
        ASN1_TEST_CHECK((before.flags & ASN1_TIME_LOCAL) == 0);
        ASN1_TEST_CHECK(after.year == expected->not_after_year);
        ASN1_TEST_CHECK(after.month == expected->not_after_month);
        ASN1_TEST_CHECK(after.day == expected->not_after_day);
        ASN1_TEST_CHECK(after.second == expected->not_after_second);
        ASN1_TEST_CHECK((after.flags & ASN1_TIME_UTC) != 0);
    }

    {
        const asn1_node_t *node = NULL;
        ASN1_TEST_CHECK(asn1_pkix_certificate_find(
                            cert, "tbsCertificate.subject", &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(node != NULL);
        ASN1_TEST_CHECK(find_text(node, expected->cn));

        ASN1_TEST_CHECK(asn1_pkix_certificate_find(
                            cert, "tbsCertificate.issuer", &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(node != NULL);
        ASN1_TEST_CHECK(find_text(node, expected->cn));

        ASN1_TEST_CHECK(asn1_pkix_certificate_find(
                            cert, "tbsCertificate.validity", &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(node != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(node) == 2);

        ASN1_TEST_CHECK(asn1_pkix_certificate_find(
                            cert, "tbsCertificate.extensions", &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(node != NULL);
        ASN1_TEST_CHECK(sequence_item_count(node) == 3);
    }

    if (check_any_shapes) {
        const asn1_node_t *any_node = NULL;
        size_t size = 0;
        const uint8_t *tlv = NULL;
        ASN1_TEST_CHECK(asn1_pkix_certificate_find(
                            cert, "signatureAlgorithm.parameters",
                            &any_node) == ASN1_OK);

        if (strcmp(expected->signature_oid, "1.2.840.113549.1.1.11") == 0) {
            /* RSA：parameters 为 NULL，完整 TLV 05 00。 */
            ASN1_TEST_CHECK(any_node != NULL);
            ASN1_TEST_CHECK(asn1_node_child_count(any_node) == 0);
            tlv = asn1_node_tlv(any_node, &size);
            ASN1_TEST_CHECK(tlv != NULL && size == 2);
            ASN1_TEST_CHECK(tlv[0] == 0x05 && tlv[1] == 0x00);
        } else if (strcmp(expected->signature_oid,
                          "1.2.840.113549.1.1.10") == 0) {
            /* RSA-PSS：parameters 为内层 SEQUENCE，ANY 只给完整 TLV。 */
            ASN1_TEST_CHECK(any_node != NULL);
            ASN1_TEST_CHECK(asn1_node_child_count(any_node) == 0);
            tlv = asn1_node_tlv(any_node, &size);
            ASN1_TEST_CHECK(tlv != NULL && size > 2);
            ASN1_TEST_CHECK(tlv[0] == 0x30);
        } else {
            /* EC：parameters 缺省，find 返回无节点且不报错。 */
            ASN1_TEST_CHECK(any_node == NULL);
        }
    }

    asn1_pkix_certificate_close(cert);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- 正例：三张真实证书 ---------- */

static int test_real_certificates(void)
{
    const cert_expectation_t rsa = {
        kCertRsaSelfsigned, kCertRsaSelfsignedSize,
        "1.2.840.113549.1.1.11",
        "651241625021466612160683104114604757680343021109",
        "ASN1 RSA Self Signed", 2026, 11, 4, 49, 2036, 11, 1, 49};
    const cert_expectation_t pss = {
        kCertRsaPssSelfsigned, kCertRsaPssSelfsignedSize,
        "1.2.840.113549.1.1.10",
        "191865463882548997427553112368273144303752527720",
        "ASN1 RSA-PSS Self Signed", 2026, 11, 4, 50, 2036, 11, 1, 50};
    const cert_expectation_t ec = {
        kCertEcSelfsigned, kCertEcSelfsignedSize,
        "1.2.840.10045.4.3.2",
        "638742892805164721513090762070971563210776089362",
        "ASN1 EC Self Signed", 2026, 11, 4, 50, 2036, 11, 1, 50};

    ASN1_TEST_CHECK(check_certificate(&rsa, 1) == 0);
    ASN1_TEST_CHECK(check_certificate(&pss, 1) == 0);
    ASN1_TEST_CHECK(check_certificate(&ec, 1) == 0);
    return 0;
}

/* ---------- 句柄隔离：两个上下文同时持有一份 ---------- */

static int test_handle_isolation(void)
{
    asn1_ctx_t *ctx_a = make_ctx();
    asn1_ctx_t *ctx_b = make_ctx();
    asn1_pkix_certificate_t *cert_a = NULL;
    asn1_pkix_certificate_t *cert_b = NULL;

    ASN1_TEST_CHECK(ctx_a != NULL && ctx_b != NULL);
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx_a, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &cert_a) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx_b, kCertEcSelfsigned,
                                               kCertEcSelfsignedSize,
                                               &cert_b) == ASN1_OK);

    {
        const char *serial = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_serial_number(cert_a, &serial,
                                                            &size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(size ==
                        strlen("651241625021466612160683104114604757680343021109"));
        ASN1_TEST_CHECK(memcmp(serial,
                               "651241625021466612160683104114604757680343021109",
                               size) == 0);
        ASN1_TEST_CHECK(asn1_pkix_certificate_serial_number(cert_b, &serial,
                                                            &size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(size ==
                        strlen("638742892805164721513090762070971563210776089362"));
        ASN1_TEST_CHECK(memcmp(serial,
                               "638742892805164721513090762070971563210776089362",
                               size) == 0);
    }

    asn1_pkix_certificate_close(cert_a);

    {
        const char *serial = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkix_certificate_serial_number(cert_b, &serial,
                                                            &size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(memcmp(serial,
                               "638742892805164721513090762070971563210776089362",
                               size) == 0);
    }

    asn1_pkix_certificate_close(cert_b);
    asn1_ctx_destroy(ctx_b);
    asn1_ctx_destroy(ctx_a);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkix_certificate_t *cert = NULL;
    const asn1_node_t *node_out = NULL;

    ASN1_TEST_CHECK(ctx != NULL);

    /* 空参与空句柄。 */
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(NULL, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &cert) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx, NULL,
                                               kCertRsaSelfsignedSize,
                                               &cert) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx, kCertRsaSelfsigned, 0,
                                               &cert) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               NULL) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkix_certificate_find(NULL,
                                               "tbsCertificate.subject",
                                               &node_out) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkix_certificate_find(cert, NULL, &node_out) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkix_certificate_version(NULL, NULL) ==
                    ASN1_E_INVALID_ARG);
    asn1_pkix_certificate_close(NULL);

    /* 非证书 DER：PKCS#8 私钥。 */
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx, kKeyRsaPkcs8,
                                               kKeyRsaPkcs8Size, &cert) !=
                    ASN1_OK);
    ASN1_TEST_CHECK(cert == NULL);

    /* 截断的证书。 */
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(
                        ctx, kCertRsaSelfsigned,
                        kCertRsaSelfsignedSize - 10, &cert) != ASN1_OK);
    ASN1_TEST_CHECK(cert == NULL);

    /* 合法 DER 后附加尾随字节。 */
    {
        static uint8_t trailing[kCertRsaSelfsignedSize + 1];
        memcpy(trailing, kCertRsaSelfsigned, kCertRsaSelfsignedSize);
        trailing[kCertRsaSelfsignedSize] = 0x00;
        ASN1_TEST_CHECK(asn1_pkix_certificate_open(
                            ctx, trailing, kCertRsaSelfsignedSize + 1,
                            &cert) != ASN1_OK);
        ASN1_TEST_CHECK(cert == NULL);
    }

    /* 合法证书上的路径/参数负例。 */
    ASN1_TEST_CHECK(asn1_pkix_certificate_open(ctx, kCertRsaSelfsigned,
                                               kCertRsaSelfsignedSize,
                                               &cert) == ASN1_OK);
    {
        const asn1_node_t *found = NULL;

        ASN1_TEST_CHECK(asn1_pkix_certificate_find(
                            cert, "tbsCertificate..subject", &found) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_pkix_certificate_find(cert, "noSuchField",
                                                   &found) == ASN1_OK);
        ASN1_TEST_CHECK(found == NULL);
        ASN1_TEST_CHECK(asn1_pkix_certificate_find(cert, "", &found) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(found != NULL);

        ASN1_TEST_CHECK(asn1_pkix_certificate_signature_algorithm_oid(
                            cert, NULL, NULL) == ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_pkix_certificate_signature_value(
                            cert, NULL, NULL, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_pkix_certificate_serial_number(cert, NULL,
                                                            NULL) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_pkix_certificate_issuer_der(cert, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_pkix_certificate_subject_der(cert, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_pkix_certificate_validity(cert, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
    }
    asn1_pkix_certificate_close(cert);

    asn1_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_module_version() != 0) {
        return 1;
    }
    if (test_real_certificates() != 0) {
        return 1;
    }
    if (test_handle_isolation() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
