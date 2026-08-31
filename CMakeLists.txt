cmake_minimum_required(VERSION 3.20)
project(Gamepad_Socket)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# ViGEmClient.lib is built with the Release MSVC runtime and without iterator
# debugging. Use the same ABI for every configuration, including Debug.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")

add_executable(Gamepad_Socket main.cpp)
target_compile_definitions(Gamepad_Socket PRIVATE _ITERATOR_DEBUG_LEVEL=0)

if (NOT WIN32)
    message(FATAL_ERROR "Gamepad_Socket requires Windows and ViGEm")
endif()

FetchContent_Declare(
    ViGEmClient
    GIT_REPOSITORY https://github.com/ViGEm/ViGEmClient.git
    GIT_TAG b66d02d57e32cc8595369c53418b843e958649b4
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(ViGEmClient)

target_link_libraries(Gamepad_Socket PRIVATE ws2_32 setupapi ViGEmClient::ViGEmClient)
