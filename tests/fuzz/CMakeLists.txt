# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
#
# fuzz 目录：
#  - tests 模式：注册确定性冒烟用例（随 ASN1_BUILD_TESTS）。
#  - fuzz 模式：构建 libFuzzer harness（随 ASN1_BUILD_FUZZ，需 Clang + 静态核心）。
#
# 构建方式（全套以覆盖率 + ASan/UBSan 插桩）：
#   cmake -S . -B build-fuzz -G Ninja \
#     -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
#     -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
#     -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
#     -DASN1_BUILD_STATIC=ON -DASN1_BUILD_SHARED=OFF \
#     -DASN1_BUILD_TESTS=OFF -DASN1_BUILD_TOOLS=ON -DASN1_BUILD_FUZZ=ON
#   cmake --build build-fuzz

if(ASN1_BUILD_TESTS)
  asn1_add_test(test_fuzz_smoke test_fuzz_smoke.c)
  target_link_libraries(test_fuzz_smoke PRIVATE asn1_test_support)
endif()

if(NOT ASN1_BUILD_FUZZ)
  return()
endif()

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(WARNING "ASN1_BUILD_FUZZ 需要 Clang（libFuzzer）；跳过 fuzz harness 构建")
  return()
endif()

if(NOT TARGET asn1::static)
  message(WARNING "ASN1_BUILD_FUZZ 需要静态核心库 asn1::static；跳过 fuzz harness 构建")
  return()
endif()

function(asn1_add_fuzz_harness name source)
  add_executable(${name} ${source} fuzz_common.c)
  target_link_libraries(${name} PRIVATE asn1::static)
  set_target_properties(
    ${name}
    PROPERTIES
      C_STANDARD 99
      C_STANDARD_REQUIRED ON
  )
  # 覆盖率插桩由全局 -fsanitize=fuzzer-no-link,... 提供；此处补一份无副作用。
  target_compile_options(${name} PRIVATE -fsanitize=fuzzer-no-link -fno-omit-frame-pointer)
  # 只在此处链接 libFuzzer 运行时（提供 main 与 fuzzing 循环）。
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  # harness 不进 CTest：由 CI 或手动按固定时间预算运行并记录迭代数。
endfunction()

asn1_add_fuzz_harness(fuzz_decode_ber fuzz_decode_ber.c)
asn1_add_fuzz_harness(fuzz_decode_der fuzz_decode_der.c)
asn1_add_fuzz_harness(fuzz_reader fuzz_reader.c)
asn1_add_fuzz_harness(fuzz_roundtrip fuzz_roundtrip.c)
asn1_add_fuzz_harness(fuzz_schema_load fuzz_schema_load.c)

# schema-aware 解码使用真实 PKIX 生成表头。
asn1_add_fuzz_harness(fuzz_schema_decode fuzz_schema_decode.c)
target_include_directories(fuzz_schema_decode PRIVATE
  ${PROJECT_SOURCE_DIR}/modules/pkix/generated)

# 模块级 open/accessor harness：链接对应模块静态库，覆盖只读访问面。
if(TARGET asn1::pkix::static)
  asn1_add_fuzz_harness(fuzz_pkix_open fuzz_pkix_open.c)
  target_link_libraries(fuzz_pkix_open PRIVATE asn1::pkix::static)
else()
  message(WARNING "fuzz_pkix_open 需要 asn1::pkix::static；跳过")
endif()

if(TARGET asn1::pkcs::static)
  asn1_add_fuzz_harness(fuzz_pkcs_open fuzz_pkcs_open.c)
  target_link_libraries(fuzz_pkcs_open PRIVATE asn1::pkcs::static)
else()
  message(WARNING "fuzz_pkcs_open 需要 asn1::pkcs::static；跳过")
endif()

if(TARGET asn1::cms::static)
  asn1_add_fuzz_harness(fuzz_cms_open fuzz_cms_open.c)
  target_link_libraries(fuzz_cms_open PRIVATE asn1::cms::static)
else()
  message(WARNING "fuzz_cms_open 需要 asn1::cms::static；跳过")
endif()

# asn1c 工具入口 harness（C++，链接 asn1c_lib 静态库）。
if(TARGET asn1c_lib)
  add_executable(fuzz_asn1c fuzz_asn1c.cpp)
  target_link_libraries(fuzz_asn1c PRIVATE asn1c_lib)
  target_include_directories(fuzz_asn1c PRIVATE
    ${PROJECT_SOURCE_DIR}/tools/asn1c/src)
  set_target_properties(
    fuzz_asn1c
    PROPERTIES
      CXX_STANDARD 17
      CXX_STANDARD_REQUIRED ON
      CXX_EXTENSIONS OFF
  )
  target_compile_options(fuzz_asn1c PRIVATE
    -fsanitize=fuzzer-no-link -fno-exceptions -fno-rtti -fno-omit-frame-pointer)
  target_link_options(fuzz_asn1c PRIVATE -fsanitize=fuzzer)
endif()