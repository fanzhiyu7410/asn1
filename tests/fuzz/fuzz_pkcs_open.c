/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asn1-pkcs 五个只读结构的打开与访问面。
 *
 * 同一份输入依次尝试 PrivateKeyInfo / EncryptedPrivateKeyInfo /
 * RSAPublicKey / RSAPrivateKey / CertificationRequest；任一 open 成功就
 * 遍历该句柄的全部访问器。带下标的访问器按 0 / count / SIZE_MAX 探测。
 */
#include <asn1/pkcs/pkcs.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "fuzz_module_common.h"

/* open 参数边界：NULL ctx / NULL 输入 / 空输入 / NULL 输出 / 超长声明。
 * 不传 size + 1：API 按 (data, size) 契约有权读取 size 字节，放大声明是
 * 调用方 UB，ASan 会把它误报成库内越界。 */
#define FUZZ_OPEN_ARG_PROBES(open_fn, handle_type, ctx, data, size)           \
    do {                                                                      \
        handle_type *probe_ = NULL;                                           \
        (void)open_fn(NULL, (data), (size), &probe_);                         \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), NULL, (size), &probe_);                          \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), (data), 0, &probe_);                             \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), (data), (size), NULL);                           \
        probe_ = NULL;                                                        \
        (void)open_fn((ctx), (data), SIZE_MAX, &probe_);                      \
        probe_ = NULL;                                                        \
    } while (0)

static void scan_private_key_info_attributes(
    const asn1_pkcs_private_key_info_t *info)
{
    size_t count = 0;
    int probe;

    if (asn1_pkcs_private_key_info_attribute_count(info, &count) != ASN1_OK) {
        return;
    }
    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asn1_node_t *values = NULL;
        size_t index = fuzz_probe_index(count, probe);
        (void)asn1_pkcs_private_key_info_attribute_at(
            info, index, &oid, &oid_size, &values);
        fuzz_walk(values);
    }

    /* NULL 输出参数单独探测。 */
    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asn1_node_t *values = NULL;
        (void)asn1_pkcs_private_key_info_attribute_at(
            info, 0, NULL, &oid_size, &values);
        (void)asn1_pkcs_private_key_info_attribute_at(
            info, 0, &oid, NULL, &values);
        (void)asn1_pkcs_private_key_info_attribute_at(
            info, 0, &oid, &oid_size, NULL);
    }
}

static void scan_private_key_info(const asn1_pkcs_private_key_info_t *info)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t count = 0;

    (void)asn1_pkcs_private_key_info_version(info, &version);
    (void)asn1_pkcs_private_key_info_version(info, NULL);

    (void)asn1_pkcs_private_key_info_algorithm_oid(info, &text, &text_size);
    (void)asn1_pkcs_private_key_info_algorithm_oid(info, NULL, &text_size);
    (void)asn1_pkcs_private_key_info_algorithm_oid(info, &text, NULL);

    (void)asn1_pkcs_private_key_info_algorithm_parameters(
        info, &bytes, &bytes_size);
    (void)asn1_pkcs_private_key_info_algorithm_parameters(
        info, NULL, &bytes_size);
    (void)asn1_pkcs_private_key_info_algorithm_parameters(info, &bytes, NULL);

    (void)asn1_pkcs_private_key_info_private_key(
        info, &bytes, &bytes_size);
    (void)asn1_pkcs_private_key_info_private_key(info, NULL, &bytes_size);
    (void)asn1_pkcs_private_key_info_private_key(info, &bytes, NULL);

    (void)asn1_pkcs_private_key_info_private_key_tlv(
        info, &bytes, &bytes_size);
    (void)asn1_pkcs_private_key_info_private_key_tlv(info, NULL, &bytes_size);
    (void)asn1_pkcs_private_key_info_private_key_tlv(info, &bytes, NULL);

    (void)asn1_pkcs_private_key_info_attribute_count(info, &count);
    (void)asn1_pkcs_private_key_info_attribute_count(info, NULL);
    scan_private_key_info_attributes(info);
}

static void scan_encrypted_private_key_info(
    const asn1_pkcs_encrypted_private_key_info_t *info)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;

    (void)asn1_pkcs_encrypted_private_key_info_algorithm_oid(
        info, &text, &text_size);
    (void)asn1_pkcs_encrypted_private_key_info_algorithm_oid(
        info, NULL, &text_size);
    (void)asn1_pkcs_encrypted_private_key_info_algorithm_oid(
        info, &text, NULL);

    (void)asn1_pkcs_encrypted_private_key_info_algorithm_parameters(
        info, &bytes, &bytes_size);
    (void)asn1_pkcs_encrypted_private_key_info_algorithm_parameters(
        info, NULL, &bytes_size);
    (void)asn1_pkcs_encrypted_private_key_info_algorithm_parameters(
        info, &bytes, NULL);

    (void)asn1_pkcs_encrypted_private_key_info_encrypted_data(
        info, &bytes, &bytes_size);
    (void)asn1_pkcs_encrypted_private_key_info_encrypted_data(
        info, NULL, &bytes_size);
    (void)asn1_pkcs_encrypted_private_key_info_encrypted_data(
        info, &bytes, NULL);

    (void)asn1_pkcs_encrypted_private_key_info_encrypted_data_tlv(
        info, &bytes, &bytes_size);
    (void)asn1_pkcs_encrypted_private_key_info_encrypted_data_tlv(
        info, NULL, &bytes_size);
    (void)asn1_pkcs_encrypted_private_key_info_encrypted_data_tlv(
        info, &bytes, NULL);
}

static void scan_rsa_public_key(const asn1_pkcs_rsa_public_key_t *key)
{
    const char *text = NULL;
    size_t text_size = 0;

    (void)asn1_pkcs_rsa_public_key_modulus(key, &text, &text_size);
    (void)asn1_pkcs_rsa_public_key_modulus(key, NULL, &text_size);
    (void)asn1_pkcs_rsa_public_key_modulus(key, &text, NULL);

    (void)asn1_pkcs_rsa_public_key_public_exponent(key, &text, &text_size);
    (void)asn1_pkcs_rsa_public_key_public_exponent(key, NULL, &text_size);
    (void)asn1_pkcs_rsa_public_key_public_exponent(key, &text, NULL);
}

#define FUZZ_SCAN_RSA_DECIMAL(fn)                                             \
    do {                                                                      \
        const char *text_ = NULL;                                             \
        size_t text_size_ = 0;                                                \
        (void)fn(key, &text_, &text_size_);                                   \
        (void)fn(key, NULL, &text_size_);                                     \
        (void)fn(key, &text_, NULL);                                          \
    } while (0)

static void scan_rsa_private_key(const asn1_pkcs_rsa_private_key_t *key)
{
    int64_t version = 0;

    (void)asn1_pkcs_rsa_private_key_version(key, &version);
    (void)asn1_pkcs_rsa_private_key_version(key, NULL);

    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_modulus);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_public_exponent);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_private_exponent);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_prime1);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_prime2);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_exponent1);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_exponent2);
    FUZZ_SCAN_RSA_DECIMAL(asn1_pkcs_rsa_private_key_coefficient);
}

#undef FUZZ_SCAN_RSA_DECIMAL

static void scan_certification_request_attributes(
    const asn1_pkcs_certification_request_t *request)
{
    size_t count = 0;
    int probe;

    if (asn1_pkcs_certification_request_attribute_count(request, &count) !=
        ASN1_OK) {
        return;
    }
    for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asn1_node_t *values = NULL;
        size_t index = fuzz_probe_index(count, probe);
        (void)asn1_pkcs_certification_request_attribute_at(
            request, index, &oid, &oid_size, &values);
        fuzz_walk(values);
    }

    {
        const char *oid = NULL;
        size_t oid_size = 0;
        const asn1_node_t *values = NULL;
        (void)asn1_pkcs_certification_request_attribute_at(
            request, 0, NULL, &oid_size, &values);
        (void)asn1_pkcs_certification_request_attribute_at(
            request, 0, &oid, NULL, &values);
        (void)asn1_pkcs_certification_request_attribute_at(
            request, 0, &oid, &oid_size, NULL);
    }
}

static void scan_certification_request(
    const asn1_pkcs_certification_request_t *request)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t count = 0;

    (void)asn1_pkcs_certification_request_version(request, &version);
    (void)asn1_pkcs_certification_request_version(request, NULL);

    (void)asn1_pkcs_certification_request_subject_der(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_der(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_der(
        request, &bytes, NULL);

    (void)asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
        request, &text, &text_size);
    (void)asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
        request, NULL, &text_size);
    (void)asn1_pkcs_certification_request_subject_public_key_algorithm_oid(
        request, &text, NULL);

    (void)asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_public_key_algorithm_parameters(
        request, &bytes, NULL);

    (void)asn1_pkcs_certification_request_subject_public_key(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_public_key(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_public_key(
        request, &bytes, NULL);

    (void)asn1_pkcs_certification_request_subject_public_key_tlv(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_public_key_tlv(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_subject_public_key_tlv(
        request, &bytes, NULL);

    (void)asn1_pkcs_certification_request_attribute_count(request, &count);
    (void)asn1_pkcs_certification_request_attribute_count(request, NULL);
    scan_certification_request_attributes(request);

    (void)asn1_pkcs_certification_request_signature_algorithm_oid(
        request, &text, &text_size);
    (void)asn1_pkcs_certification_request_signature_algorithm_oid(
        request, NULL, &text_size);
    (void)asn1_pkcs_certification_request_signature_algorithm_oid(
        request, &text, NULL);

    (void)asn1_pkcs_certification_request_signature_algorithm_parameters(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_signature_algorithm_parameters(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_signature_algorithm_parameters(
        request, &bytes, NULL);

    (void)asn1_pkcs_certification_request_signature_value(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_signature_value(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_signature_value(
        request, &bytes, NULL);

    (void)asn1_pkcs_certification_request_signature_value_tlv(
        request, &bytes, &bytes_size);
    (void)asn1_pkcs_certification_request_signature_value_tlv(
        request, NULL, &bytes_size);
    (void)asn1_pkcs_certification_request_signature_value_tlv(
        request, &bytes, NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asn1_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    FUZZ_OPEN_ARG_PROBES(asn1_pkcs_private_key_info_open,
                         asn1_pkcs_private_key_info_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asn1_pkcs_encrypted_private_key_info_open,
                         asn1_pkcs_encrypted_private_key_info_t, ctx, data,
                         size);
    FUZZ_OPEN_ARG_PROBES(asn1_pkcs_rsa_public_key_open,
                         asn1_pkcs_rsa_public_key_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asn1_pkcs_rsa_private_key_open,
                         asn1_pkcs_rsa_private_key_t, ctx, data, size);
    FUZZ_OPEN_ARG_PROBES(asn1_pkcs_certification_request_open,
                         asn1_pkcs_certification_request_t, ctx, data, size);

    /* 同一输入按五种结构依次尝试；只扫描打开成功的句柄。
     * 每个句柄 close 一次；置空后再 close 覆盖 close(NULL) 重复调用。
     * 同一非空指针的重复 close 不在契约内，不在此构造。 */
    {
        asn1_pkcs_private_key_info_t *handle = NULL;
        if (asn1_pkcs_private_key_info_open(ctx, data, size, &handle) ==
                ASN1_OK &&
            handle != NULL) {
            scan_private_key_info(handle);
        }
        asn1_pkcs_private_key_info_close(handle);
        handle = NULL;
        asn1_pkcs_private_key_info_close(handle);
    }
    {
        asn1_pkcs_encrypted_private_key_info_t *handle = NULL;
        if (asn1_pkcs_encrypted_private_key_info_open(ctx, data, size,
                                                      &handle) == ASN1_OK &&
            handle != NULL) {
            scan_encrypted_private_key_info(handle);
        }
        asn1_pkcs_encrypted_private_key_info_close(handle);
        handle = NULL;
        asn1_pkcs_encrypted_private_key_info_close(handle);
    }
    {
        asn1_pkcs_rsa_public_key_t *handle = NULL;
        if (asn1_pkcs_rsa_public_key_open(ctx, data, size, &handle) ==
                ASN1_OK &&
            handle != NULL) {
            scan_rsa_public_key(handle);
        }
        asn1_pkcs_rsa_public_key_close(handle);
        handle = NULL;
        asn1_pkcs_rsa_public_key_close(handle);
    }
    {
        asn1_pkcs_rsa_private_key_t *handle = NULL;
        if (asn1_pkcs_rsa_private_key_open(ctx, data, size, &handle) ==
                ASN1_OK &&
            handle != NULL) {
            scan_rsa_private_key(handle);
        }
        asn1_pkcs_rsa_private_key_close(handle);
        handle = NULL;
        asn1_pkcs_rsa_private_key_close(handle);
    }
    {
        asn1_pkcs_certification_request_t *handle = NULL;
        if (asn1_pkcs_certification_request_open(ctx, data, size, &handle) ==
                ASN1_OK &&
            handle != NULL) {
            scan_certification_request(handle);
        }
        asn1_pkcs_certification_request_close(handle);
        handle = NULL;
        asn1_pkcs_certification_request_close(handle);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
