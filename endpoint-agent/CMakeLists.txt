cmake_minimum_required(VERSION 3.10)
project(aegis_agent)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost REQUIRED COMPONENTS system thread)
find_package(krabsetw CONFIG REQUIRED)

add_executable(aegis_agent src/main.cpp)

target_link_libraries(aegis_agent PRIVATE Boost::boost Boost::system Boost::thread krabsetw::krabsetw)
