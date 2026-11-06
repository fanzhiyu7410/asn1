/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asn1c 词法/语法/语义/描述表生成入口。
 * 任意 .asn1 文本；返回错误码/诊断属正常行为。仅崩溃/泄漏/超时算失败。
 */
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "parser.h"
#include "semantic.h"
#include "table.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string source(reinterpret_cast<const char *>(data), size);
    asn1c::Diagnostics diag;
    asn1c::ModuleAst module;

    (void)asn1c::parseModule("fuzz.asn1", source, module, diag);

    if (!diag.hasError()) {
        std::unique_ptr<asn1c::SchemaModel> model =
            asn1c::analyzeModule("fuzz.asn1", module, "", diag);
        if (!diag.hasError() && model) {
            asn1c::TableOutput output =
                asn1c::buildTable(*model, module.name);
            (void)asn1c::renderCArray(output);
        }
    }

    return 0;
}