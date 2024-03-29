cmake_minimum_required(VERSION 3.10)
project(rgcp VERSION 1.1.0 DESCRIPTION "RGCP networking library")
include(GNUInstallDirs)

set(TARGET_NAME rgcp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -shared -g")

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib/)

add_library(${TARGET_NAME} SHARED
    src/details/logger.c
    src/details/rgcp_peer.c
    src/details/rgcp_group.c
    src/details/rgcp_socket.c
    src/rgcp_api.c
    src/rgcp.c
)

find_package(Threads)

target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -Werror -pedantic -g)

target_link_libraries(${TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${TARGET_NAME} dl)

set_target_properties(${TARGET_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/rgcp.h;include/rgcp_api.h;include/rgcp_group.h;include/rgcp_peer.h;include/rgcp_crc32.h"
)

target_include_directories(${TARGET_NAME} PRIVATE src)
target_include_directories(${TARGET_NAME} PRIVATE include)

install(TARGETS ${TARGET_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rgcp/
)
