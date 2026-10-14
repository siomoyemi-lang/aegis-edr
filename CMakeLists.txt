cmake_minimum_required(VERSION 3.10)
project(aegis LANGUAGES CXX)

# Top-level entry point so `cmake -B build && cmake --build build --config Release` works from the repo root.
add_subdirectory(endpoint-agent)
