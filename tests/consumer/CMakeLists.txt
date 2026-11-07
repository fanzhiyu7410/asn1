# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 三个独立消费工程：核心、PKCS、CMS。每个只依赖对应的 find_package，
# 安装到临时前缀后以共享/静态两种形态构建并运行，再整体移动前缀验证可重定位。

function(asn1_add_consumer_test name namespace package main sample)
  if(namespace STREQUAL "asn1")
    set(shared_target asn1::shared)
    set(static_target asn1::static)
    set(has_shared FALSE)
    set(has_static FALSE)
    if(TARGET asn1::shared)
      set(has_shared TRUE)
    endif()
    if(TARGET asn1::static)
      set(has_static TRUE)
    endif()
  else()
    set(shared_target asn1::${namespace}::shared)
    set(static_target asn1::${namespace}::static)
    set(has_shared FALSE)
    set(has_static FALSE)
    if(TARGET asn1::${namespace}::shared)
      set(has_shared TRUE)
    endif()
    if(TARGET asn1::${namespace}::static)
      set(has_static TRUE)
    endif()
  endif()

  set(link_modes "")
  if(has_shared)
    list(APPEND link_modes shared)
  endif()
  if(has_static)
    list(APPEND link_modes static)
  endif()
  if(NOT link_modes)
    return()
  endif()
  string(REPLACE ";" "," link_modes_arg "${link_modes}")

  add_test(
    NAME ${name}
    COMMAND
      ${CMAKE_COMMAND}
      -DASN1_CONSUMER_BUILD_DIR=${CMAKE_BINARY_DIR}
      -DASN1_CONSUMER_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/${name}-work
      -DASN1_CONSUMER_PACKAGE=${package}
      -DASN1_CONSUMER_TARGET_SHARED=${shared_target}
      -DASN1_CONSUMER_TARGET_STATIC=${static_target}
      -DASN1_CONSUMER_MAIN=${CMAKE_CURRENT_SOURCE_DIR}/${main}
      -DASN1_CONSUMER_SAMPLE=${CMAKE_SOURCE_DIR}/tests/data/${sample}
      -DASN1_CONSUMER_CONFIG=$<CONFIG>
      -DASN1_CONSUMER_GENERATOR=${CMAKE_GENERATOR}
      -DASN1_CONSUMER_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}
      -DASN1_CONSUMER_C_COMPILER=${CMAKE_C_COMPILER}
      -DASN1_CONSUMER_RC_COMPILER=${CMAKE_RC_COMPILER}
      -DASN1_CONSUMER_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      -DASN1_CONSUMER_LINK_MODES=${link_modes_arg}
      -DASN1_CONSUMER_C_FLAGS=${CMAKE_C_FLAGS}
      -DASN1_CONSUMER_CXX_FLAGS=${CMAKE_CXX_FLAGS}
      -DASN1_CONSUMER_EXE_LINKER_FLAGS=${CMAKE_EXE_LINKER_FLAGS}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/test_consumer.cmake
  )
  set_tests_properties(${name} PROPERTIES TIMEOUT 420)
endfunction()

asn1_add_consumer_test(
  test_consumer_core asn1 asn1 consumer_core.c cert_rsa_selfsigned.der)
asn1_add_consumer_test(
  test_consumer_pkix pkix asn1-pkix consumer_pkix.c cert_rsa_selfsigned.der)
asn1_add_consumer_test(
  test_consumer_pkcs pkcs asn1-pkcs consumer_pkcs.c pfx_rsa_unencrypted.der)
asn1_add_consumer_test(
  test_consumer_cms cms asn1-cms consumer_cms.c cms_rsa_attached.der)
