# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 消费示例：分别以 C 与 C++ 编译，验证公共头文件只依赖 C ABI。
if(TARGET asn1::shared)
  set(ASN1_EXAMPLE_LIBRARY asn1::shared)
else()
  set(ASN1_EXAMPLE_LIBRARY asn1::static)
endif()

add_executable(asn1_example_c c/example_decode.c)
target_link_libraries(asn1_example_c PRIVATE ${ASN1_EXAMPLE_LIBRARY})
set_target_properties(asn1_example_c PROPERTIES LINKER_LANGUAGE CXX)

add_executable(asn1_example_cpp cpp/example_usage.cpp)
target_compile_features(asn1_example_cpp PRIVATE cxx_std_17)
target_link_libraries(asn1_example_cpp PRIVATE ${ASN1_EXAMPLE_LIBRARY})

if(MSVC)
  target_compile_options(asn1_example_c PRIVATE /utf-8)
  target_compile_options(asn1_example_cpp PRIVATE /utf-8)
endif()
