# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
#
# 模块独立消费：安装到临时前缀，用独立工程 find_package(asn1-pkix CONFIG)
# 分别以共享、静态链接构建并运行，验证导出包、头文件与运行期依赖。

foreach(required IN ITEMS ASN1_PKIX_BUILD_DIR ASN1_PKIX_WORK_DIR
                           ASN1_PKIX_CERT_PATH ASN1_PKIX_CONFIG)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "缺少参数 ${required}")
  endif()
endforeach()

if(NOT DEFINED ASN1_PKIX_LINK_MODES OR ASN1_PKIX_LINK_MODES STREQUAL "")
  set(ASN1_PKIX_LINK_MODES "shared,static")
endif()
string(REPLACE "," ";" link_modes "${ASN1_PKIX_LINK_MODES}")

set(prefix "${ASN1_PKIX_WORK_DIR}/prefix")
file(REMOVE_RECURSE "${ASN1_PKIX_WORK_DIR}")
file(MAKE_DIRECTORY "${ASN1_PKIX_WORK_DIR}")

set(install_command
    ${CMAKE_COMMAND} --install "${ASN1_PKIX_BUILD_DIR}" --prefix "${prefix}"
)
if(ASN1_PKIX_CONFIG)
  list(APPEND install_command --config "${ASN1_PKIX_CONFIG}")
endif()
execute_process(COMMAND ${install_command}
                RESULT_VARIABLE install_result)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "安装失败：${install_result}")
endif()

set(consumer_main "${ASN1_PKIX_WORK_DIR}/main.c")
file(WRITE "${consumer_main}" "
#include <asn1/asn1.h>
#include <asn1/pkix/pkix.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    FILE *file = NULL;
    unsigned char *der = NULL;
    long length = 0;
    asn1_ctx_config_t config;
    asn1_ctx_t *ctx = NULL;
    asn1_pkix_certificate_t *cert = NULL;
    const asn1_node_t *subject = NULL;
    uint32_t version = 0;
    int result = 1;

    if (argc != 2) {
        return 1;
    }
    file = fopen(argv[1], \"rb\");
    if (file == NULL) {
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 1;
    }
    der = (unsigned char *)malloc((size_t)length);
    if (der == NULL || fread(der, 1, (size_t)length, file) != (size_t)length) {
        free(der);
        fclose(file);
        return 1;
    }
    fclose(file);

    asn1_ctx_config_init(&config);
    if (asn1_ctx_create(&config, &ctx) != ASN1_OK) {
        free(der);
        return 1;
    }
    if (asn1_pkix_certificate_open(ctx, der, (size_t)length, &cert) == ASN1_OK &&
        asn1_pkix_certificate_version(cert, &version) == ASN1_OK &&
        version == 2 &&
        asn1_pkix_certificate_find(cert, \"tbsCertificate.subject\",
                                   &subject) == ASN1_OK &&
        subject != NULL) {
        result = 0;
    }
    asn1_pkix_certificate_close(cert);
    asn1_ctx_destroy(ctx);
    free(der);
    return result;
}
")

set(consumer_cmake "${ASN1_PKIX_WORK_DIR}/CMakeLists.txt")
file(WRITE "${consumer_cmake}" "
cmake_minimum_required(VERSION 3.20)
project(pkix_consumer C)

find_package(asn1-pkix CONFIG REQUIRED)

if(LINK_MODE STREQUAL \"static\")
  add_executable(consumer main.c)
  target_link_libraries(consumer PRIVATE asn1::pkix::static)
else()
  add_executable(consumer main.c)
  target_link_libraries(consumer PRIVATE asn1::pkix::shared)
endif()
")

foreach(link_mode IN LISTS link_modes)
  set(mode_dir "${ASN1_PKIX_WORK_DIR}/${link_mode}")
  file(MAKE_DIRECTORY "${mode_dir}")

  set(configure_command
      ${CMAKE_COMMAND} -S "${ASN1_PKIX_WORK_DIR}" -B "${mode_dir}"
      -DLINK_MODE=${link_mode} -DCMAKE_PREFIX_PATH=${prefix}
  )
  if(ASN1_PKIX_GENERATOR)
    list(APPEND configure_command -G "${ASN1_PKIX_GENERATOR}")
  endif()
  if(ASN1_PKIX_GENERATOR_PLATFORM)
    list(APPEND configure_command -A "${ASN1_PKIX_GENERATOR_PLATFORM}")
  endif()
  if(ASN1_PKIX_C_COMPILER)
    list(APPEND configure_command -DCMAKE_C_COMPILER=${ASN1_PKIX_C_COMPILER})
  endif()
  if(ASN1_PKIX_BUILD_TYPE)
    list(APPEND configure_command -DCMAKE_BUILD_TYPE=${ASN1_PKIX_BUILD_TYPE})
  endif()
  # 父工程带插桩标志（如 ASan/UBSan）时，独立消费工程必须同步，
  # 否则链接已插桩静态库会缺运行时符号。
  if(ASN1_PKIX_C_FLAGS)
    list(APPEND configure_command "-DCMAKE_C_FLAGS=${ASN1_PKIX_C_FLAGS}")
  endif()
  if(ASN1_PKIX_CXX_FLAGS)
    list(APPEND configure_command "-DCMAKE_CXX_FLAGS=${ASN1_PKIX_CXX_FLAGS}")
  endif()
  if(ASN1_PKIX_EXE_LINKER_FLAGS)
    list(APPEND configure_command
         "-DCMAKE_EXE_LINKER_FLAGS=${ASN1_PKIX_EXE_LINKER_FLAGS}")
  endif()

  execute_process(
    COMMAND ${configure_command}
    RESULT_VARIABLE configure_result
  )
  if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "${link_mode} 配置失败：${configure_result}")
  endif()

  set(build_command ${CMAKE_COMMAND} --build "${mode_dir}")
  if(ASN1_PKIX_CONFIG)
    list(APPEND build_command --config "${ASN1_PKIX_CONFIG}")
  endif()
  execute_process(COMMAND ${build_command} RESULT_VARIABLE build_result)
  if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "${link_mode} 构建失败：${build_result}")
  endif()

  set(consumer_exe "${mode_dir}/consumer")
  if(WIN32)
    set(consumer_exe "${mode_dir}/${ASN1_PKIX_CONFIG}/consumer.exe")
    if(NOT EXISTS "${consumer_exe}")
      set(consumer_exe "${mode_dir}/consumer.exe")
    endif()
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env
            "PATH=${prefix}/bin;$ENV{PATH}"
            "${consumer_exe}" "${ASN1_PKIX_CERT_PATH}"
    RESULT_VARIABLE run_result
  )
  if(NOT run_result EQUAL 0)
    message(FATAL_ERROR "${link_mode} 运行失败：${run_result}")
  endif()
endforeach()

message(STATUS "asn1-pkix 独立消费通过：${link_modes}")
