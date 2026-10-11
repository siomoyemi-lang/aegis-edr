cmake_minimum_required(VERSION 3.20)
project(aegis_agent CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system thread)
find_package(Threads REQUIRED)

include_directories(include ${Boost_INCLUDE_DIRS})

add_executable(aegis_agent src/main.cpp)
target_link_libraries(aegis_agent ${Boost_LIBRARIES} Threads::Threads)
