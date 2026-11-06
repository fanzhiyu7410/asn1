/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * asn1-pkcs 只读结构访问：PKCS#8 / PKCS#1 / PKCS#10。
 * 覆盖 PKCS#8 明文与加密、RSA-PSS 参数 ANY、PKCS#1 公私钥字段、
 * PKCS#10 CSR 字段与负例。
 */

#include <asn1/asn1.h>
#include <asn1/pkcs/pkcs.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../data/csr_ec.h"
#include "../data/csr_rsa.h"
#include "../data/key_rsa_pkcs1_private.h"
#include "../data/key_rsa_pkcs1_public.h"
#include "../data/key_rsa_pkcs8.h"
#include "../data/key_rsa_pkcs8_encrypted.h"
#include "../data/key_rsa_pss_pkcs8.h"
#include "check.h"

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

static int tlv_is(const uint8_t *tlv, size_t size, const uint8_t *expected,
                  size_t expected_size)
{
    if (tlv == NULL || size != expected_size) {
        return 0;
    }
    return memcmp(tlv, expected, expected_size) == 0;
}

/* ---------- PKCS#8 明文 PrivateKeyInfo ---------- */

static int test_private_key_info_clear(void)
{
    static const uint8_t null_parameters[] = {0x05, 0x00};
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_private_key_info_t *info = NULL;
    asn1_pkcs_rsa_private_key_t *inner = NULL;
    const char *inner_modulus = NULL;
    size_t inner_modulus_size = 0;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &info) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(info != NULL);

    {
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_version(info, &version) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(version == 0);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_algorithm_oid(
                            info, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.1"));
    }

    {
        /* RSA 的 parameters 是 NULL，ANY 只给完整原始 TLV 05 00。 */
        const uint8_t *tlv = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_algorithm_parameters(
                            info, &tlv, &size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv_is(tlv, size, null_parameters,
                               sizeof(null_parameters)));
    }

    {
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t size = 0;
        size_t tlv_size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_private_key(
                            info, &data, &size) == ASN1_OK);
        ASN1_TEST_CHECK(data != NULL && size > 0);
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_private_key_tlv(
                            info, &tlv, &tlv_size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv != NULL && tlv_size > size);
        ASN1_TEST_CHECK(tlv[0] == 0x04);
    }

    {
        size_t count = 99;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_attribute_count(
                            info, &count) == ASN1_OK);
        ASN1_TEST_CHECK(count == 0);
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_attribute_at(
                            info, 0, NULL, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
    }

    /* 内层 privateKey 就是 PKCS#1 RSAPrivateKey，可再用 PKCS#1 API 打开。 */
    {
        const uint8_t *der = NULL;
        size_t der_size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_private_key(
                            info, &der, &der_size) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_open(ctx, der, der_size,
                                                       &inner) == ASN1_OK);
        ASN1_TEST_CHECK(inner != NULL);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_modulus(
                            inner, &inner_modulus, &inner_modulus_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(inner_modulus != NULL);
    }

    /* 与独立 PKCS#1 样本的模数逐字节一致。 */
    {
        asn1_pkcs_rsa_private_key_t *sample = NULL;
        const char *sample_modulus = NULL;
        size_t sample_size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_open(
                            ctx, kKeyRsaPkcs1Private,
                            kKeyRsaPkcs1PrivateSize, &sample) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_modulus(
                            sample, &sample_modulus, &sample_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(sample_size == inner_modulus_size);
        ASN1_TEST_CHECK(memcmp(sample_modulus, inner_modulus,
                               sample_size) == 0);
        asn1_pkcs_rsa_private_key_close(sample);
    }

    asn1_pkcs_rsa_private_key_close(inner);
    asn1_pkcs_private_key_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#8 RSA-PSS：parameters 缺省 ---------- */

static int test_private_key_info_pss(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_private_key_info_t *info = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(
                        ctx, kKeyRsaPssPkcs8, kKeyRsaPssPkcs8Size, &info) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(info != NULL);

    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_algorithm_oid(
                            info, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.10"));
    }

    {
        /* 该样本的 AlgorithmIdentifier 只含 algorithm OID，parameters 缺省。 */
        const uint8_t *tlv = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_private_key_info_algorithm_parameters(
                            info, &tlv, &size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv == NULL);
        ASN1_TEST_CHECK(size == 0);
    }

    asn1_pkcs_private_key_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#8 EncryptedPrivateKeyInfo ---------- */

static int test_encrypted_private_key_info(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_encrypted_private_key_info_t *info = NULL;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(asn1_pkcs_encrypted_private_key_info_open(
                        ctx, kKeyRsaPkcs8Encrypted,
                        kKeyRsaPkcs8EncryptedSize, &info) == ASN1_OK);
    ASN1_TEST_CHECK(info != NULL);

    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_encrypted_private_key_info_algorithm_oid(
                            info, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.5.13"));
    }

    {
        const uint8_t *tlv = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_encrypted_private_key_info_algorithm_parameters(
                info, &tlv, &size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv != NULL && size > 2);
        ASN1_TEST_CHECK(tlv[0] == 0x30);
    }

    {
        const uint8_t *data = NULL;
        const uint8_t *tlv = NULL;
        size_t size = 0;
        size_t tlv_size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_encrypted_private_key_info_encrypted_data(
                info, &data, &size) == ASN1_OK);
        ASN1_TEST_CHECK(data != NULL && size > 0);
        ASN1_TEST_CHECK(
            asn1_pkcs_encrypted_private_key_info_encrypted_data_tlv(
                info, &tlv, &tlv_size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv != NULL && tlv_size > size);
        ASN1_TEST_CHECK(tlv[0] == 0x04);
    }

    asn1_pkcs_encrypted_private_key_info_close(info);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#1 公私钥 ---------- */

static int test_rsa_keys(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_rsa_public_key_t *pub = NULL;
    asn1_pkcs_rsa_private_key_t *priv = NULL;
    const char *pub_modulus = NULL;
    const char *priv_modulus = NULL;
    size_t pub_size = 0;
    size_t priv_size = 0;

    ASN1_TEST_CHECK(ctx != NULL);
    ASN1_TEST_CHECK(asn1_pkcs_rsa_public_key_open(
                        ctx, kKeyRsaPkcs1Public, kKeyRsaPkcs1PublicSize,
                        &pub) == ASN1_OK);
    ASN1_TEST_CHECK(pub != NULL);

    {
        const char *exponent = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_rsa_public_key_modulus(
                            pub, &pub_modulus, &pub_size) == ASN1_OK);
        ASN1_TEST_CHECK(pub_modulus != NULL && pub_size > 0);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_public_key_public_exponent(
                            pub, &exponent, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(exponent, size, "65537"));
    }

    ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_open(
                        ctx, kKeyRsaPkcs1Private, kKeyRsaPkcs1PrivateSize,
                        &priv) == ASN1_OK);
    ASN1_TEST_CHECK(priv != NULL);

    {
        int64_t version = -1;
        const char *exponent = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_version(priv, &version) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(version == 0);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_modulus(
                            priv, &priv_modulus, &priv_size) == ASN1_OK);
        ASN1_TEST_CHECK(priv_size == pub_size);
        ASN1_TEST_CHECK(memcmp(priv_modulus, pub_modulus, pub_size) == 0);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_public_exponent(
                            priv, &exponent, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(exponent, size, "65537"));
    }

    {
        const char *field = NULL;
        size_t field_size = 0;
        const char *prime2 = NULL;
        size_t prime2_size = 0;

        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_private_exponent(
                            priv, &field, &field_size) == ASN1_OK);
        ASN1_TEST_CHECK(field != NULL && field_size > 0);

        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_prime1(
                            priv, &field, &field_size) == ASN1_OK);
        ASN1_TEST_CHECK(field != NULL && field_size > 0);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_prime2(
                            priv, &prime2, &prime2_size) == ASN1_OK);
        ASN1_TEST_CHECK(prime2 != NULL && prime2_size > 0);
        ASN1_TEST_CHECK(field_size != prime2_size ||
                        memcmp(field, prime2, field_size) != 0);

        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_exponent1(
                            priv, &field, &field_size) == ASN1_OK);
        ASN1_TEST_CHECK(field != NULL && field_size > 0);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_exponent2(
                            priv, &field, &field_size) == ASN1_OK);
        ASN1_TEST_CHECK(field != NULL && field_size > 0);
        ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_coefficient(
                            priv, &field, &field_size) == ASN1_OK);
        ASN1_TEST_CHECK(field != NULL && field_size > 0);
    }

    asn1_pkcs_rsa_private_key_close(priv);
    asn1_pkcs_rsa_public_key_close(pub);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- 负例 ---------- */

static int test_negative(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_private_key_info_t *info = NULL;
    asn1_pkcs_rsa_public_key_t *pub = NULL;
    asn1_pkcs_rsa_private_key_t *truncated = NULL;
    uint8_t *trailing = NULL;

    ASN1_TEST_CHECK(ctx != NULL);

    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(NULL, kKeyRsaPkcs8,
                                                    kKeyRsaPkcs8Size,
                                                    &info) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(ctx, NULL,
                                                    kKeyRsaPkcs8Size,
                                                    &info) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(ctx, kKeyRsaPkcs8, 0,
                                                    &info) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(ctx, kKeyRsaPkcs8,
                                                    kKeyRsaPkcs8Size,
                                                    NULL) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_version(NULL, NULL) ==
                    ASN1_E_INVALID_ARG);
    asn1_pkcs_private_key_info_close(NULL);
    asn1_pkcs_rsa_public_key_close(NULL);
    asn1_pkcs_rsa_private_key_close(NULL);
    asn1_pkcs_encrypted_private_key_info_close(NULL);

    /* 用 PKCS#8 私钥去打开 RSAPublicKey 必须失败。 */
    ASN1_TEST_CHECK(asn1_pkcs_rsa_public_key_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &pub) != ASN1_OK);
    ASN1_TEST_CHECK(pub == NULL);

    /* 截断的 PKCS#1 私钥。 */
    ASN1_TEST_CHECK(asn1_pkcs_rsa_private_key_open(
                        ctx, kKeyRsaPkcs1Private,
                        kKeyRsaPkcs1PrivateSize - 8, &truncated) != ASN1_OK);
    ASN1_TEST_CHECK(truncated == NULL);

    /* 合法 DER 后附加尾随字节。 */
    trailing = (uint8_t *)malloc(kKeyRsaPkcs8Size + 1);
    ASN1_TEST_CHECK(trailing != NULL);
    memcpy(trailing, kKeyRsaPkcs8, kKeyRsaPkcs8Size);
    trailing[kKeyRsaPkcs8Size] = 0x00;
    ASN1_TEST_CHECK(asn1_pkcs_private_key_info_open(
                        ctx, trailing, kKeyRsaPkcs8Size + 1, &info) !=
                    ASN1_OK);
    ASN1_TEST_CHECK(info == NULL);
    free(trailing);

    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#10 CSR 正例：RSA 与 EC ---------- */

static int test_certification_request(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_certification_request_t *csr = NULL;

    ASN1_TEST_CHECK(ctx != NULL);

    /* RSA CSR：sha256WithRSAEncryption、rsaEncryption + NULL、空 attributes。 */
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, kCsrRsa, kCsrRsaSize, &csr) == ASN1_OK);
    ASN1_TEST_CHECK(csr != NULL);

    {
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_version(csr, &version) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(version == 0);
    }

    {
        const uint8_t *subject = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_subject_der(
                            csr, &subject, &size) == ASN1_OK);
        ASN1_TEST_CHECK(subject != NULL && size == 58);
        ASN1_TEST_CHECK(subject[0] == 0x30);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
                csr, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.1"));
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
                csr, &params, &params_size) == ASN1_OK);
        ASN1_TEST_CHECK(params != NULL && params_size == 2);
        ASN1_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
    }

    {
        const uint8_t *key = NULL;
        size_t size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_subject_public_key(
                            csr, &key, &size) == ASN1_OK);
        ASN1_TEST_CHECK(key != NULL && size == 270);
        ASN1_TEST_CHECK(key[0] == 0x30);
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_subject_public_key_tlv(
                csr, &tlv, &tlv_size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv != NULL && tlv_size == 275);
        ASN1_TEST_CHECK(tlv[0] == 0x03);
    }

    {
        size_t count = 1;
        const char *oid = NULL;
        size_t oid_size = 0;
        const asn1_node_t *values = NULL;
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_attribute_count(csr, &count) ==
            ASN1_OK);
        ASN1_TEST_CHECK(count == 0);
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_attribute_at(
                csr, 0, &oid, &oid_size, &values) == ASN1_E_INVALID_ARG);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *signature = NULL;
        size_t signature_size = 0;
        const uint8_t *tlv = NULL;
        size_t tlv_size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_signature_algorithm_oid(
                csr, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.11"));
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_signature_algorithm_parameters(
                csr, &params, &params_size) == ASN1_OK);
        ASN1_TEST_CHECK(params != NULL && params_size == 2);
        ASN1_TEST_CHECK(params[0] == 0x05 && params[1] == 0x00);
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_signature_value(
                            csr, &signature, &signature_size) == ASN1_OK);
        ASN1_TEST_CHECK(signature != NULL && signature_size == 256);
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_signature_value_tlv(
                csr, &tlv, &tlv_size) == ASN1_OK);
        ASN1_TEST_CHECK(tlv != NULL && tlv_size == 261);
        ASN1_TEST_CHECK(tlv[0] == 0x03);
    }

    asn1_pkcs_certification_request_close(csr);
    csr = NULL;

    /* EC CSR：参数为 curve OID，公钥为未压缩点。 */
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, kCsrEc, kCsrEcSize, &csr) == ASN1_OK);
    ASN1_TEST_CHECK(csr != NULL);

    {
        const uint8_t *subject = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_subject_der(
                            csr, &subject, &size) == ASN1_OK);
        ASN1_TEST_CHECK(subject != NULL && size == 57);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        const uint8_t *params = NULL;
        size_t params_size = 0;
        const uint8_t *key = NULL;
        size_t key_size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
                csr, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.10045.2.1"));
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
                csr, &params, &params_size) == ASN1_OK);
        ASN1_TEST_CHECK(params != NULL && params_size == 10);
        ASN1_TEST_CHECK(params[0] == 0x06);
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_subject_public_key(
                            csr, &key, &key_size) == ASN1_OK);
        ASN1_TEST_CHECK(key != NULL && key_size == 65);
        ASN1_TEST_CHECK(key[0] == 0x04);
    }

    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_signature_algorithm_oid(
                csr, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.10045.4.3.2"));
    }

    asn1_pkcs_certification_request_close(csr);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#10 非 0 版本：原样给出值 ---------- */

static int test_certification_request_nonzero_version(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_certification_request_t *csr = NULL;
    uint8_t *patched = NULL;

    ASN1_TEST_CHECK(ctx != NULL);

    /*
     * CSR DER：0 SEQUENCE，4 certificationRequestInfo，8 INTEGER 0；
     * 内容字节位于偏移 10。改为 1，构造“非 v1”的不常见输入。
     */
    patched = (uint8_t *)malloc(kCsrRsaSize);
    ASN1_TEST_CHECK(patched != NULL);
    memcpy(patched, kCsrRsa, kCsrRsaSize);
    patched[10] = 0x01;

    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, patched, kCsrRsaSize, &csr) == ASN1_OK);
    ASN1_TEST_CHECK(csr != NULL);

    {
        int64_t version = -1;
        ASN1_TEST_CHECK(asn1_pkcs_certification_request_version(csr, &version) ==
                        ASN1_OK);
        /* 不做范围校验、不静默改写为 0。 */
        ASN1_TEST_CHECK(version == 1);
    }

    /* 其余字段不受版本影响，仍可正常读取。 */
    {
        const char *oid = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(
            asn1_pkcs_certification_request_signature_algorithm_oid(
                csr, &oid, &size) == ASN1_OK);
        ASN1_TEST_CHECK(text_equals(oid, size, "1.2.840.113549.1.1.11"));
    }

    asn1_pkcs_certification_request_close(csr);
    free(patched);
    asn1_ctx_destroy(ctx);
    return 0;
}

/* ---------- PKCS#10 负例 ---------- */

static int test_certification_request_negative(void)
{
    asn1_ctx_t *ctx = make_ctx();
    asn1_pkcs_certification_request_t *csr = NULL;
    uint8_t *trailing = NULL;

    ASN1_TEST_CHECK(ctx != NULL);

    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        NULL, kCsrRsa, kCsrRsaSize, &csr) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, NULL, kCsrRsaSize, &csr) == ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, kCsrRsa, kCsrRsaSize, NULL) ==
                    ASN1_E_INVALID_ARG);
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_version(NULL, NULL) ==
                    ASN1_E_INVALID_ARG);
    asn1_pkcs_certification_request_close(NULL);

    /* 非 CSR 输入（PKCS#8 私钥）必须失败。 */
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, kKeyRsaPkcs8, kKeyRsaPkcs8Size, &csr) != ASN1_OK);
    ASN1_TEST_CHECK(csr == NULL);

    /* 截断 CSR。 */
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, kCsrRsa, kCsrRsaSize - 20, &csr) != ASN1_OK);
    ASN1_TEST_CHECK(csr == NULL);

    /* 合法 DER 后附加尾随字节。 */
    trailing = (uint8_t *)malloc(kCsrRsaSize + 1);
    ASN1_TEST_CHECK(trailing != NULL);
    memcpy(trailing, kCsrRsa, kCsrRsaSize);
    trailing[kCsrRsaSize] = 0x00;
    ASN1_TEST_CHECK(asn1_pkcs_certification_request_open(
                        ctx, trailing, kCsrRsaSize + 1, &csr) != ASN1_OK);
    ASN1_TEST_CHECK(csr == NULL);
    free(trailing);

    asn1_ctx_destroy(ctx);
    return 0;
}

int main(void)
{
    if (test_private_key_info_clear() != 0) {
        return 1;
    }
    if (test_private_key_info_pss() != 0) {
        return 1;
    }
    if (test_encrypted_private_key_info() != 0) {
        return 1;
    }
    if (test_rsa_keys() != 0) {
        return 1;
    }
    if (test_certification_request() != 0) {
        return 1;
    }
    if (test_certification_request_nonzero_version() != 0) {
        return 1;
    }
    if (test_certification_request_negative() != 0) {
        return 1;
    }
    if (test_negative() != 0) {
        return 1;
    }
    return 0;
}
