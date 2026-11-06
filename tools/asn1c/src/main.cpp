/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1c 命令行入口：只做 CLI 编排，具体工作委托给词法/语法/语义/表生成模块。
 * 退出码：0 成功，1 存在 error 诊断，2 命令行用法错误，3 IO 失败。
 */

#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "asn1c_version.h"

#include "diag.h"
#include "parser.h"
#include "semantic.h"
#include "table.h"

namespace {

void printUsage(std::FILE *out)
{
    std::fprintf(
        out,
        "Usage: asn1c [OPTIONS] <input.asn1>\n"
        "  -o, --output-bin <PATH>   写二进制描述表\n"
        "  -c, --output-c <PATH>     写 C 数组源文件\n"
        "      --root <TYPE-NAME>    设置根类型（默认不设）\n"
        "      --diagnostics <LEVEL> minimal|normal|verbose（默认 normal）\n"
        "      --version             打印版本\n"
        "  -h, --help                打印本帮助\n");
}

bool startsWith(const std::string &text, const char *prefix)
{
    const size_t length = std::strlen(prefix);
    return text.size() >= length &&
           text.compare(0, length, prefix) == 0;
}

bool readFile(const std::string &path, std::string &out)
{
    std::ifstream stream(path.c_str(), std::ios::binary);
    /* 某些 MinGW/libstdc++ 组合在 open 失败时不置 failbit，is_open 仍需检查。 */
    if (!stream || !stream.is_open()) {
        return false;
    }
    std::string data;
    char ch = 0;
    while (stream.get(ch)) {
        data.push_back(ch);
    }
    if (stream.bad()) {
        return false;
    }
    out = std::move(data);
    return true;
}

bool writeBinary(const std::string &path, const std::vector<uint8_t> &bytes)
{
    std::ofstream stream(path.c_str(),
                         std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    stream.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    stream.flush();
    if (!stream.good()) {
        stream.close();
        std::remove(path.c_str());
        return false;
    }
    stream.close();
    return true;
}

bool writeText(const std::string &path, const std::string &text)
{
    std::ofstream stream(path.c_str(),
                         std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    stream.flush();
    if (!stream.good()) {
        stream.close();
        std::remove(path.c_str());
        return false;
    }
    stream.close();
    return true;
}

int usageError(const std::string &message)
{
    std::fprintf(stderr, "asn1c: %s\n", message.c_str());
    printUsage(stderr);
    return 2;
}

} /* namespace */

int main(int argc, char **argv)
{
    std::string inputPath;
    std::string outputBin;
    std::string outputC;
    std::string rootName;
    bool haveInput = false;
    bool haveMinimal = false;
    bool haveNormal = false;
    bool haveVerbose = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--version") {
            std::printf("asn1c %s\n", ASN1C_VERSION_STRING);
            return 0;
        }
        if (argument == "-h" || argument == "--help") {
            printUsage(stdout);
            return 0;
        }
        if (argument == "-o" || argument == "--output-bin") {
            if (i + 1 >= argc) {
                return usageError("missing value for " + argument);
            }
            outputBin = argv[++i];
        } else if (startsWith(argument, "--output-bin=")) {
            outputBin = argument.substr(std::strlen("--output-bin="));
        } else if (argument == "-c" || argument == "--output-c") {
            if (i + 1 >= argc) {
                return usageError("missing value for " + argument);
            }
            outputC = argv[++i];
        } else if (startsWith(argument, "--output-c=")) {
            outputC = argument.substr(std::strlen("--output-c="));
        } else if (argument == "--root") {
            if (i + 1 >= argc) {
                return usageError("missing value for --root");
            }
            rootName = argv[++i];
        } else if (startsWith(argument, "--root=")) {
            rootName = argument.substr(std::strlen("--root="));
        } else if (argument == "--diagnostics") {
            if (i + 1 >= argc) {
                return usageError("missing value for --diagnostics");
            }
            const std::string level = argv[++i];
            if (level == "minimal") {
                haveMinimal = true;
            } else if (level == "normal") {
                haveNormal = true;
            } else if (level == "verbose") {
                haveVerbose = true;
            } else {
                return usageError("invalid --diagnostics level '" + level +
                                  "'");
            }
        } else if (startsWith(argument, "--diagnostics=")) {
            const std::string level =
                argument.substr(std::strlen("--diagnostics="));
            if (level == "minimal") {
                haveMinimal = true;
            } else if (level == "normal") {
                haveNormal = true;
            } else if (level == "verbose") {
                haveVerbose = true;
            } else {
                return usageError("invalid --diagnostics level '" + level +
                                  "'");
            }
        } else if (!argument.empty() && argument[0] == '-') {
            return usageError("unknown option '" + argument + "'");
        } else {
            if (haveInput) {
                return usageError("multiple input files are not supported");
            }
            inputPath = argument;
            haveInput = true;
        }
    }

    if (!haveInput) {
        return usageError("missing input file");
    }
    if (outputBin.empty() && outputC.empty()) {
        return usageError("at least one of -o/--output-bin or -c/--output-c "
                          "is required");
    }
    if (haveMinimal && (haveNormal || haveVerbose)) {
        return usageError("conflicting --diagnostics levels");
    }
    if (haveNormal && haveVerbose) {
        return usageError("conflicting --diagnostics levels");
    }
    const asn1c::DiagLevel level =
        haveMinimal ? asn1c::DiagLevel::Minimal
                    : (haveVerbose ? asn1c::DiagLevel::Verbose
                                   : asn1c::DiagLevel::Normal);

    asn1c::Diagnostics diagnostics;
    std::string source;
    if (!readFile(inputPath, source)) {
        diagnostics.add(inputPath, 0, 0, asn1c::Severity::Error,
                        asn1c::DiagCode::OutputIo,
                        "cannot read input file");
        asn1c::printDiagnostics(diagnostics, level, stderr);
        return 3;
    }

    asn1c::ModuleAst module;
    const bool parsed =
        asn1c::parseModule(inputPath, source, module, diagnostics);
    if (!parsed || diagnostics.hasError()) {
        asn1c::printDiagnostics(diagnostics, level, stderr);
        return 1;
    }

    std::unique_ptr<asn1c::SchemaModel> model =
        asn1c::analyzeModule(inputPath, module, rootName, diagnostics);
    if (diagnostics.hasError()) {
        asn1c::printDiagnostics(diagnostics, level, stderr);
        return 1;
    }

    const asn1c::TableOutput output =
        asn1c::buildTable(*model, module.name);

    bool ioFailed = false;
    if (!outputBin.empty() && !writeBinary(outputBin, output.bytes)) {
        diagnostics.add(outputBin, 0, 0, asn1c::Severity::Error,
                        asn1c::DiagCode::OutputIo,
                        "cannot write output file");
        ioFailed = true;
    }
    if (!outputC.empty() && !ioFailed) {
        const std::string text = asn1c::renderCArray(output);
        if (!writeText(outputC, text)) {
            diagnostics.add(outputC, 0, 0, asn1c::Severity::Error,
                            asn1c::DiagCode::OutputIo,
                            "cannot write output file");
            ioFailed = true;
        }
    }
    if (ioFailed) {
        asn1c::printDiagnostics(diagnostics, level, stderr);
        return 3;
    }

    if (level == asn1c::DiagLevel::Verbose) {
        std::fprintf(stderr, "asn1c: %u types (%u named, %u synthesized), "
                             "%zu bytes\n",
                     static_cast<unsigned>(output.typeCount),
                     static_cast<unsigned>(output.namedTypeCount),
                     static_cast<unsigned>(output.typeCount -
                                           output.namedTypeCount),
                     output.bytes.size());
    }
    asn1c::printDiagnostics(diagnostics, level, stderr);
    return 0;
}
