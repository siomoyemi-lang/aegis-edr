cmake_minimum_required(VERSION 3.10)
project(aegis_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost REQUIRED)   # Boost.Asio is header-only
find_package(Threads REQUIRED)

add_executable(aegis_agent src/main.cpp)
target_include_directories(aegis_agent PRIVATE include)
target_compile_definitions(aegis_agent PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0A00)
target_link_libraries(aegis_agent PRIVATE Boost::boost Threads::Threads ws2_32 mswsock tdh advapi32 bcrypt)

if(MSVC)
  target_compile_options(aegis_agent PRIVATE /W4 /permissive-)
endif()

# Keep the documented path  build/Release/aegis_agent.exe  working whichever directory CMake is run from.
set_target_properties(aegis_agent PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY         "${CMAKE_BINARY_DIR}/Release"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/Debug")
