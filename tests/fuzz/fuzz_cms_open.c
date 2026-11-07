/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asn1-cms ContentInfo / SignedData 只读访问面与 builder 写路径。
 *
 * 输入先按 ContentInfo 打开；成功后把 content 字段的内层 TLV 再交给
 * SignedData open，覆盖两级结构。所有带下标的访问器按 0 / count /
 * SIZE_MAX 探测，并对 NULL 输出参数做边界调用。随后用同一份输入驱动
 * builder 的单 TLV 入口与 signer 路径并尝试编码，覆盖写侧校验与组装。
 */
#include <asn1/cms/cms.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "fuzz_module_common.h"

static const char kSha256Oid[] = "2.16.840.1.101.3.4.2.1";
static const char kDataOid[] = "1.2.840.113549.1.7.1";
static const char kRsaEncryptionOid[] = "1.2.840.113549.1.1.1";
static const uint8_t kNullParams[2] = {0x05, 0x00};

static void scan_signer(const asn1_cms_signed_data_t *signed_data,
                        size_t index)
{
    int64_t version = 0;
    int choice = -1;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    const uint8_t *params = NULL;
    size_t params_size = 0;

    (void)asn1_cms_signed_data_signer_version(signed_data, index, &version);
    (void)asn1_cms_signed_data_signer_version(signed_data, index, NULL);

    (void)asn1_cms_signed_data_signer_sid_choice(signed_data, index, &choice);
    (void)asn1_cms_signed_data_signer_sid_choice(signed_data, index, NULL);

    (void)asn1_cms_signed_data_signer_sid_issuer(signed_data, index, &bytes,
                                                 &bytes_size);
    (void)asn1_cms_signed_data_signer_sid_issuer(signed_data, index, NULL,
                                                 &bytes_size);
    (void)asn1_cms_signed_data_signer_sid_issuer(signed_data, index, &bytes,
                                                 NULL);

    (void)asn1_cms_signed_data_signer_sid_serial(signed_data, index, &text,
                                                 &text_size);
    (void)asn1_cms_signed_data_signer_sid_serial(signed_data, index, NULL,
                                                 &text_size);
    (void)asn1_cms_signed_data_signer_sid_serial(signed_data, index, &text,
                                                 NULL);

    (void)asn1_cms_signed_data_signer_sid_serial_tlv(
        signed_data, index, &bytes, &bytes_size);
    (void)asn1_cms_signed_data_signer_sid_serial_tlv(
        signed_data, index, NULL, &bytes_size);
    (void)asn1_cms_signed_data_signer_sid_serial_tlv(
        signed_data, index, &bytes, NULL);

    (void)asn1_cms_signed_data_signer_sid_subject_key_identifier(
        signed_data, index, &bytes, &bytes_size);
    (void)asn1_cms_signed_data_signer_sid_subject_key_identifier(
        signed_data, index, NULL, &bytes_size);
    (void)asn1_cms_signed_data_signer_sid_subject_key_identifier(
        signed_data, index, &bytes, NULL);

    (void)asn1_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, &text_size, &params, &params_size);
    (void)asn1_cms_signed_data_signer_digest_algorithm(
        signed_data, index, NULL, &text_size, &params, &params_size);
    (void)asn1_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, NULL, &params, &params_size);
    (void)asn1_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, &text_size, NULL, &params_size);
    (void)asn1_cms_signed_data_signer_digest_algorithm(
        signed_data, index, &text, &text_size, &params, NULL);

    (void)asn1_cms_signed_data_signer_signed_attrs(signed_data, index, &bytes,
                                                   &bytes_size);
    (void)asn1_cms_signed_data_signer_signed_attrs(signed_data, index, NULL,
                                                   &bytes_size);
    (void)asn1_cms_signed_data_signer_signed_attrs(signed_data, index, &bytes,
                                                   NULL);

    (void)asn1_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, &text_size, &params, &params_size);
    (void)asn1_cms_signed_data_signer_signature_algorithm(
        signed_data, index, NULL, &text_size, &params, &params_size);
    (void)asn1_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, NULL, &params, &params_size);
    (void)asn1_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, &text_size, NULL, &params_size);
    (void)asn1_cms_signed_data_signer_signature_algorithm(
        signed_data, index, &text, &text_size, &params, NULL);

    (void)asn1_cms_signed_data_signer_signature(signed_data, index, &bytes,
                                                &bytes_size);
    (void)asn1_cms_signed_data_signer_signature(signed_data, index, NULL,
                                                &bytes_size);
    (void)asn1_cms_signed_data_signer_signature(signed_data, index, &bytes,
                                                NULL);

    (void)asn1_cms_signed_data_signer_signature_tlv(
        signed_data, index, &bytes, &bytes_size);
    (void)asn1_cms_signed_data_signer_signature_tlv(
        signed_data, index, NULL, &bytes_size);
    (void)asn1_cms_signed_data_signer_signature_tlv(
        signed_data, index, &bytes, NULL);

    (void)asn1_cms_signed_data_signer_unsigned_attrs(
        signed_data, index, &bytes, &bytes_size);
    (void)asn1_cms_signed_data_signer_unsigned_attrs(
        signed_data, index, NULL, &bytes_size);
    (void)asn1_cms_signed_data_signer_unsigned_attrs(
        signed_data, index, &bytes, NULL);
}

static void scan_signed_data(const asn1_cms_signed_data_t *signed_data)
{
    int64_t version = 0;
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;
    size_t count = 0;
    int probe;

    (void)asn1_cms_signed_data_version(signed_data, &version);
    (void)asn1_cms_signed_data_version(signed_data, NULL);

    if (asn1_cms_signed_data_digest_algorithm_count(signed_data, &count) ==
        ASN1_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            const uint8_t *params = NULL;
            size_t params_size = 0;
            size_t index = fuzz_probe_index(count, probe);
            (void)asn1_cms_signed_data_digest_algorithm_at(
                signed_data, index, &text, &text_size, &params,
                &params_size);
        }
    }
    (void)asn1_cms_signed_data_digest_algorithm_count(signed_data, NULL);

    (void)asn1_cms_signed_data_encap_content_type(signed_data, &text,
                                                  &text_size);
    (void)asn1_cms_signed_data_encap_content_type(signed_data, NULL,
                                                  &text_size);
    (void)asn1_cms_signed_data_encap_content_type(signed_data, &text, NULL);

    (void)asn1_cms_signed_data_encap_content(signed_data, &bytes,
                                             &bytes_size);
    (void)asn1_cms_signed_data_encap_content(signed_data, NULL, &bytes_size);
    (void)asn1_cms_signed_data_encap_content(signed_data, &bytes, NULL);

    (void)asn1_cms_signed_data_encap_content_tlv(signed_data, &bytes,
                                                 &bytes_size);
    (void)asn1_cms_signed_data_encap_content_tlv(signed_data, NULL,
                                                 &bytes_size);
    (void)asn1_cms_signed_data_encap_content_tlv(signed_data, &bytes, NULL);

    if (asn1_cms_signed_data_certificate_count(signed_data, &count) ==
        ASN1_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            int choice = -1;
            size_t index = fuzz_probe_index(count, probe);
            (void)asn1_cms_signed_data_certificate_at(
                signed_data, index, &choice, &bytes, &bytes_size);
            (void)asn1_cms_signed_data_certificate_subject(
                signed_data, index, &bytes, &bytes_size);
            (void)asn1_cms_signed_data_certificate_issuer(
                signed_data, index, &bytes, &bytes_size);
            (void)asn1_cms_signed_data_certificate_serial(
                signed_data, index, &text, &text_size);
        }
    }
    (void)asn1_cms_signed_data_certificate_count(signed_data, NULL);

    if (asn1_cms_signed_data_crl_count(signed_data, &count) == ASN1_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            int choice = -1;
            size_t index = fuzz_probe_index(count, probe);
            (void)asn1_cms_signed_data_crl_at(signed_data, index, &choice,
                                              &bytes, &bytes_size);
        }
    }
    (void)asn1_cms_signed_data_crl_count(signed_data, NULL);

    if (asn1_cms_signed_data_signer_count(signed_data, &count) == ASN1_OK) {
        for (probe = 0; probe < FUZZ_INDEX_PROBES; ++probe) {
            scan_signer(signed_data, fuzz_probe_index(count, probe));
        }
    }
    (void)asn1_cms_signed_data_signer_count(signed_data, NULL);
}

static void scan_content_info(asn1_ctx_t *ctx,
                              const asn1_cms_content_info_t *info)
{
    const char *text = NULL;
    size_t text_size = 0;
    const uint8_t *bytes = NULL;
    size_t bytes_size = 0;

    (void)asn1_cms_content_info_content_type(info, &text, &text_size);
    (void)asn1_cms_content_info_content_type(info, NULL, &text_size);
    (void)asn1_cms_content_info_content_type(info, &text, NULL);

    (void)asn1_cms_content_info_content(info, &bytes, &bytes_size);
    (void)asn1_cms_content_info_content(info, NULL, &bytes_size);
    (void)asn1_cms_content_info_content(info, &bytes, NULL);

    if (bytes != NULL && bytes_size != 0) {
        asn1_cms_signed_data_t *signed_data = NULL;
        if (asn1_cms_signed_data_open(ctx, bytes, bytes_size, &signed_data) ==
                ASN1_OK &&
            signed_data != NULL) {
            scan_signed_data(signed_data);
        }
        asn1_cms_signed_data_close(signed_data);
        signed_data = NULL;
        asn1_cms_signed_data_close(signed_data);
    }
}

/*
 * 写路径：固定合法骨架保证 encode 可达，模糊输入只进入单 TLV 校验入口
 * （eContent / 证书 / CRL / 参数 / sid / 属性集合 / 签名内容）。
 */
static void scan_builder(asn1_ctx_t *ctx, const uint8_t *data, size_t size)
{
    asn1_cms_builder_t *builder = NULL;
    if (asn1_cms_builder_create(ctx, &builder) != ASN1_OK) {
        return;
    }

    (void)asn1_cms_builder_set_version(builder, (int64_t)size);
    (void)asn1_cms_builder_add_digest_algorithm(builder, kSha256Oid, NULL, 0);
    (void)asn1_cms_builder_set_econtent_type(builder, kDataOid);

    if (size != 0) {
        (void)asn1_cms_builder_set_econtent(builder, data, size);
        (void)asn1_cms_builder_add_certificate(builder, data, size);
        (void)asn1_cms_builder_add_crl(builder, data, size);
        (void)asn1_cms_builder_add_digest_algorithm(builder, kSha256Oid, data,
                                                   size);
        (void)asn1_cms_builder_add_signer(
            builder, 1, ASN1_CMS_SID_SUBJECT_KEY_IDENTIFIER, data, size, NULL,
            0, kSha256Oid, NULL, 0, data, size, kRsaEncryptionOid,
            kNullParams, sizeof(kNullParams), data, size, data, size);
        (void)asn1_cms_builder_add_signer(
            builder, 1, ASN1_CMS_SID_ISSUER_AND_SERIAL, data, size, data, size,
            kSha256Oid, NULL, 0, NULL, 0, kRsaEncryptionOid, kNullParams,
            sizeof(kNullParams), data, size, NULL, 0);
    }

    {
        asn1_buf_t encoded;
        memset(&encoded, 0, sizeof(encoded));
        (void)asn1_cms_builder_encode(builder, &encoded);
        (void)asn1_buf_release(ctx, &encoded);
    }
    asn1_cms_builder_destroy(builder);
    asn1_cms_builder_destroy(NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asn1_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    /* ContentInfo open 参数边界。 */
    {
        asn1_cms_content_info_t *probe = NULL;
        (void)asn1_cms_content_info_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asn1_cms_content_info_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asn1_cms_content_info_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asn1_cms_content_info_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asn1_cms_content_info_open(ctx, data, SIZE_MAX, &probe);
    }

    /* SignedData open 参数边界（输入既可来自 ContentInfo，也可独立给入）。 */
    {
        asn1_cms_signed_data_t *probe = NULL;
        (void)asn1_cms_signed_data_open(NULL, data, size, &probe);
        probe = NULL;
        (void)asn1_cms_signed_data_open(ctx, NULL, size, &probe);
        probe = NULL;
        (void)asn1_cms_signed_data_open(ctx, data, 0, &probe);
        probe = NULL;
        (void)asn1_cms_signed_data_open(ctx, data, size, NULL);
        probe = NULL;
        (void)asn1_cms_signed_data_open(ctx, data, SIZE_MAX, &probe);
    }

    {
        asn1_cms_content_info_t *info = NULL;
        if (asn1_cms_content_info_open(ctx, data, size, &info) == ASN1_OK &&
            info != NULL) {
            scan_content_info(ctx, info);
        }
        /* 置空后再 close 覆盖 close(NULL) 重复调用；同一非空指针的重复
         * close 不在契约内，不在此构造。 */
        asn1_cms_content_info_close(info);
        info = NULL;
        asn1_cms_content_info_close(info);
    }

    /* 独立 SignedData 输入：部分语料直接给 SignedData，不带 ContentInfo。 */
    {
        asn1_cms_signed_data_t *signed_data = NULL;
        if (asn1_cms_signed_data_open(ctx, data, size, &signed_data) ==
                ASN1_OK &&
            signed_data != NULL) {
            scan_signed_data(signed_data);
        }
        asn1_cms_signed_data_close(signed_data);
        signed_data = NULL;
        asn1_cms_signed_data_close(signed_data);
    }

    scan_builder(ctx, data, size);

    asn1_ctx_destroy(ctx);
    return 0;
}
