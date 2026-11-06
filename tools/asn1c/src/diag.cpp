/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

#include "diag.h"

#include <algorithm>

namespace asn1c {

void Diagnostics::add(const std::string &file, uint32_t line, uint32_t column,
                      Severity severity, DiagCode code,
                      const std::string &message)
{
    Diagnostic item;
    item.file = file;
    item.line = line;
    item.column = column;
    item.severity = severity;
    item.code = code;
    item.message = message;
    items_.push_back(item);
}

bool Diagnostics::hasError() const noexcept
{
    for (const Diagnostic &item : items_) {
        if (item.severity == Severity::Error) {
            return true;
        }
    }
    return false;
}

size_t Diagnostics::size() const noexcept { return items_.size(); }

const std::vector<Diagnostic> &Diagnostics::items() const noexcept
{
    return items_;
}

const char *codeName(DiagCode code) noexcept
{
    switch (code) {
    case DiagCode::Syntax:
        return "ASN1C_E_SYNTAX";
    case DiagCode::UndefinedType:
        return "ASN1C_E_UNDEFINED_TYPE";
    case DiagCode::DuplicateType:
        return "ASN1C_E_DUPLICATE_TYPE";
    case DiagCode::DuplicateField:
        return "ASN1C_E_DUPLICATE_FIELD";
    case DiagCode::TagConflict:
        return "ASN1C_E_TAG_CONFLICT";
    case DiagCode::UnsupportedConstruct:
        return "ASN1C_E_UNSUPPORTED_CONSTRUCT";
    case DiagCode::ImportUnresolved:
        return "ASN1C_E_IMPORT_UNRESOLVED";
    case DiagCode::ParamInstantiation:
        return "ASN1C_E_PARAM_INSTANTIATION";
    case DiagCode::ConstraintInvalid:
        return "ASN1C_E_CONSTRAINT_INVALID";
    case DiagCode::OutputIo:
        return "ASN1C_E_OUTPUT_IO";
    case DiagCode::Internal:
        return "ASN1C_E_INTERNAL";
    case DiagCode::UnusedImport:
        return "ASN1C_W_UNUSED_IMPORT";
    case DiagCode::DeprecatedSyntax:
        return "ASN1C_W_DEPRECATED_SYNTAX";
    }
    return "ASN1C_E_INTERNAL";
}

const char *severityName(Severity severity) noexcept
{
    return severity == Severity::Error ? "error" : "warning";
}

void printDiagnostics(const Diagnostics &diagnostics, DiagLevel level,
                      std::FILE *out)
{
    std::vector<Diagnostic> sorted = diagnostics.items();
    std::stable_sort(sorted.begin(), sorted.end(),
                     [](const Diagnostic &a, const Diagnostic &b) {
                         if (a.file != b.file) {
                             return a.file < b.file;
                         }
                         if (a.line != b.line) {
                             return a.line < b.line;
                         }
                         if (a.column != b.column) {
                             return a.column < b.column;
                         }
                         if (static_cast<uint32_t>(a.code) !=
                             static_cast<uint32_t>(b.code)) {
                             return static_cast<uint32_t>(a.code) <
                                    static_cast<uint32_t>(b.code);
                         }
                         return false;
                     });

    for (const Diagnostic &item : sorted) {
        if (level == DiagLevel::Minimal && item.severity != Severity::Error) {
            continue;
        }
        std::fprintf(out, "%s:%u:%u: %s: %s: %s\n", item.file.c_str(),
                     static_cast<unsigned>(item.line),
                     static_cast<unsigned>(item.column),
                     severityName(item.severity), codeName(item.code),
                     item.message.c_str());
    }
}

} /* namespace asn1c */
