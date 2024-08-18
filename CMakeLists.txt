cmake_minimum_required(VERSION 3.20)

project(PacketStorm LANGUAGES CXX)

#BUILD_SHARED_LIBS:BOOL=ON
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall -Werror -Wpedantic -Ofast")


# Include libpcap.
include(FetchContent)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")
FetchContent_Declare(
    Pcap
    GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
    GIT_TAG libpcap-1.10.4
)
FetchContent_MakeAvailable(Pcap)

add_executable(pstorm src/main.cpp)
set_property(TARGET pstorm PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
target_link_libraries(pstorm PRIVATE Pcap)