/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 递归下降解析器：模块头、类型赋值、值赋值、字段、标签、约束与 DEFAULT。
 * 一期不支持的构造在任何位置都产生明确的 ASN1C_E_UNSUPPORTED_CONSTRUCT。
 */
#ifndef ASN1C_PARSER_H_INCLUDED
#define ASN1C_PARSER_H_INCLUDED

#include <string>

#include "ast.h"
#include "diag.h"

namespace asn1c {

bool parseModule(const std::string &file, const std::string &source,
                 ModuleAst &out, Diagnostics &diagnostics);

} /* namespace asn1c */

#endif /* ASN1C_PARSER_H_INCLUDED */
