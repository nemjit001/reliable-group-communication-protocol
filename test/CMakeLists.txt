cmake_minimum_required(VERSION 3.10)
project(rgcp_test VERSION 1.0.0 DESCRIPTION "RGCP networking library tests")
include(CTest)

# Testing Setup
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin/)

add_executable(ApiTest
    ./ApiTest.c
)
target_link_libraries(ApiTest dl pthread rgcp)

add_executable(StartupShutdown
    ./StartupShutdown.c
)
target_link_libraries(StartupShutdown dl pthread rgcp)

add_executable(MultiClient
    ./MultiClient.c
)
target_link_libraries(MultiClient dl pthread rgcp)

add_executable(MultiGroup
    ./MultiGroup.c
)
target_link_libraries(MultiGroup dl pthread rgcp)

add_executable(ConnectDisconnect
    ./ConnectDisconnect.c
)
target_link_libraries(ConnectDisconnect dl pthread rgcp)

add_executable(LivenessCheck
    ./LivenessCheck.c
)
target_link_libraries(LivenessCheck dl pthread rgcp)

add_executable(ClientSimCrash
    ./ClientSimCrash.c
)
target_link_libraries(ClientSimCrash dl pthread rgcp)

add_executable(DataTransfer
    ./DataTransfer.c
)
target_link_libraries(DataTransfer dl pthread rgcp)

add_executable(ThreadSafety
    ./ThreadSafety.c
)
target_link_libraries(ThreadSafety dl pthread rgcp)

add_test(NAME "StartupShutdown" COMMAND StartupShutdown)
add_test(NAME "API" COMMAND ApiTest)
add_test(NAME "MultiGroup" COMMAND MultiGroup)
add_test(NAME "MultiClient" COMMAND MultiClient)
add_test(NAME "ConnectDisconnect" COMMAND ConnectDisconnect)
add_test(NAME "LivenessCheck" COMMAND LivenessCheck)
add_test(NAME "ClientSimCrash" COMMAND ClientSimCrash)
add_test(NAME "DataTransfer" COMMAND DataTransfer)
add_test(NAME "ThreadSafety" COMMAND ThreadSafety)
add_test(NAME "MultiClientLarge" COMMAND MultiClient 30)