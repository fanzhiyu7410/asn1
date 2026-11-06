# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
#
# asn1c CLI 行为测试（CTest 脚本模式）。
# 需要 -DASN1C_EXE=、-DSOURCE_DIR=、-DWORK_DIR=。

cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED ASN1C_EXE OR NOT DEFINED SOURCE_DIR OR NOT DEFINED WORK_DIR)
  message(FATAL_ERROR "ASN1C_EXE / SOURCE_DIR / WORK_DIR must be provided")
endif()
if(NOT EXISTS "${ASN1C_EXE}")
  message(FATAL_ERROR "asn1c executable not found: ${ASN1C_EXE}")
endif()

set(PKIX_SOURCE
    "${SOURCE_DIR}/modules/pkix/asn1/PKIX-Flattened-2009.asn1")
set(NEGATIVE_DIR "${SOURCE_DIR}/tests/data/asn1c/negative")

file(MAKE_DIRECTORY "${WORK_DIR}")

# ---- 1. 两次运行的输出必须逐字节一致 -------------------------------------
execute_process(
  COMMAND "${ASN1C_EXE}" -o "${WORK_DIR}/det_a.bin" -c "${WORK_DIR}/det_a.h"
          --root Certificate "${PKIX_SOURCE}"
  RESULT_VARIABLE rc_a
  OUTPUT_VARIABLE out_a
  ERROR_VARIABLE err_a
)
if(NOT rc_a EQUAL 0)
  message(FATAL_ERROR "first run failed (${rc_a}): ${out_a}${err_a}")
endif()

execute_process(
  COMMAND "${ASN1C_EXE}" -o "${WORK_DIR}/det_b.bin" -c "${WORK_DIR}/det_b.h"
          --root Certificate "${PKIX_SOURCE}"
  RESULT_VARIABLE rc_b
  OUTPUT_VARIABLE out_b
  ERROR_VARIABLE err_b
)
if(NOT rc_b EQUAL 0)
  message(FATAL_ERROR "second run failed (${rc_b}): ${out_b}${err_b}")
endif()

file(SHA256 "${WORK_DIR}/det_a.bin" hash_a)
file(SHA256 "${WORK_DIR}/det_b.bin" hash_b)
if(NOT hash_a STREQUAL hash_b)
  message(FATAL_ERROR "asn1c output is not deterministic: ${hash_a} != ${hash_b}")
endif()

# ---- 2. C 头中的字节序列必须与 .bin 完全一致 -----------------------------
file(READ "${WORK_DIR}/det_a.h" header_text)
string(REGEX MATCHALL "0x[0-9A-Fa-f][0-9A-Fa-f]" header_tokens
       "${header_text}")
string(REPLACE "0x" "" header_hex "${header_tokens}")
string(REPLACE ";" "" header_hex "${header_hex}")
string(TOLOWER "${header_hex}" header_hex)

file(READ "${WORK_DIR}/det_a.bin" bin_hex HEX)
string(TOLOWER "${bin_hex}" bin_hex)

if(header_hex STREQUAL "")
  message(FATAL_ERROR "generated C header contains no byte sequence")
endif()
string(LENGTH "${header_hex}" header_len)
string(LENGTH "${bin_hex}" bin_len)
if(NOT header_len EQUAL bin_len)
  message(FATAL_ERROR
          "header byte count (${header_len}) != binary size (${bin_len})")
endif()
if(NOT header_hex STREQUAL bin_hex)
  message(FATAL_ERROR "generated C header bytes differ from .bin content")
endif()

# ---- 3. 负例：退出码 1 + 诊断格式 ----------------------------------------
# 每项：样本文件名|符号错误码|文档中的数字错误码
set(NEGATIVE_CASES
    "unsupported_class.asn1|ASN1C_E_UNSUPPORTED_CONSTRUCT|9006"
    "any_defined_by.asn1|ASN1C_E_UNSUPPORTED_CONSTRUCT|9006"
    "missing_end.asn1|ASN1C_E_SYNTAX|9001"
    "undefined_type.asn1|ASN1C_E_UNDEFINED_TYPE|9002"
    "duplicate_type.asn1|ASN1C_E_DUPLICATE_TYPE|9003"
    "invalid_default.asn1|ASN1C_E_CONSTRAINT_INVALID|9009"
    "duplicate_named_value.asn1|ASN1C_E_DUPLICATE_FIELD|9004"
    "duplicate_named_bit.asn1|ASN1C_E_DUPLICATE_FIELD|9004"
    "bit_out_of_range.asn1|ASN1C_E_CONSTRAINT_INVALID|9009"
    "parameterized.asn1|ASN1C_E_UNSUPPORTED_CONSTRUCT|9006"
)

foreach(case IN LISTS NEGATIVE_CASES)
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 sample)
  list(GET parts 1 code_name)
  list(GET parts 2 code_number)
  set(sample_path "${NEGATIVE_DIR}/${sample}")

  execute_process(
    COMMAND "${ASN1C_EXE}" -o "${WORK_DIR}/neg_${sample}.bin"
            "${sample_path}"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
  )
  if(NOT rc EQUAL 1)
    message(FATAL_ERROR
            "${sample}: expected exit code 1, got ${rc}\n${out}${err}")
  endif()

  set(combined "${out}${err}")
  string(FIND "${combined}" "${code_name}" found_pos)
  if(found_pos EQUAL -1)
    message(FATAL_ERROR
            "${sample}: missing ${code_name} (${code_number}) in diagnostics:\n${combined}")
  endif()

  # 诊断行必须形如 <file>:<line>:<col>: error: <code>: <msg>
  string(REGEX MATCH "[^ :]+:([0-9]+):([0-9]+): error: ${code_name}: "
         location "${combined}")
  if(location STREQUAL "")
    message(FATAL_ERROR
            "${sample}: diagnostic line is not in '<file>:<line>:<col>: error: <code>: <msg>' form:\n${combined}")
  endif()
  # 位置必须指向源码（行号 >= 1），不能退化成未知位置 0:0
  set(diag_line "${CMAKE_MATCH_1}")
  set(diag_column "${CMAKE_MATCH_2}")
  if(diag_line LESS 1 OR diag_column LESS 1)
    message(FATAL_ERROR
            "${sample}: diagnostic position must be >= 1:1, got ${diag_line}:${diag_column}")
  endif()
endforeach()

# ---- 4. 版本、参数与缺失输入的退出码 -------------------------------------
execute_process(
  COMMAND "${ASN1C_EXE}" --version
  RESULT_VARIABLE version_rc
  OUTPUT_VARIABLE version_out
  ERROR_VARIABLE version_err
)
if(NOT version_rc EQUAL 0)
  message(FATAL_ERROR "--version failed (${version_rc}): ${version_err}")
endif()
string(REGEX MATCH "^asn1c " version_prefix "${version_out}")
if(version_prefix STREQUAL "")
  message(FATAL_ERROR "--version output must start with 'asn1c ': ${version_out}")
endif()

execute_process(
  COMMAND "${ASN1C_EXE}"
  RESULT_VARIABLE noarg_rc
  OUTPUT_VARIABLE noarg_out
  ERROR_VARIABLE noarg_err
)
if(NOT noarg_rc EQUAL 2)
  message(FATAL_ERROR
          "no-argument invocation: expected exit code 2, got ${noarg_rc}\n${noarg_out}${noarg_err}")
endif()

execute_process(
  COMMAND "${ASN1C_EXE}" -o "${WORK_DIR}/missing.bin"
          "${WORK_DIR}/does_not_exist.asn1"
  RESULT_VARIABLE missing_rc
  OUTPUT_VARIABLE missing_out
  ERROR_VARIABLE missing_err
)
if(NOT missing_rc EQUAL 3)
  message(FATAL_ERROR
          "missing input: expected exit code 3, got ${missing_rc}\n${missing_out}${missing_err}")
endif()

message(STATUS "asn1c CLI behaviour verified")
