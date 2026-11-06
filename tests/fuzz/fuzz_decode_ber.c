/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：BER 解码（asn1_decode_buffer，encoding=BER）。
 * 返回错误码是正常行为，仅崩溃/泄漏/超时/ASan 报错算失败。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asn1_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASN1_ENCODING_BER;

    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    (void)asn1_decode_buffer(ctx, data, size, &options, &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asn1_doc_root(doc));
        asn1_doc_destroy(doc);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}