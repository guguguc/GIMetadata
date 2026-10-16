cmake_minimum_required(VERSION 3.16)
project(GIMetadata LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LIEF REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

add_executable(gi-dump src/main.cpp)

target_include_directories(gi-dump PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_directories(gi-dump PRIVATE ${CAPSTONE_LIBRARY_DIRS})
target_link_libraries(gi-dump PRIVATE LIEF::PE ${CAPSTONE_LIBRARIES})

if(NOT MSVC)
  target_compile_options(gi-dump PRIVATE -Wall)
target_include_directories(gi-dump PRIVATE src)
endif()

# 32 位目标需要运行时库标志
link_libraries(${CAPSTONE_LDFLAGS})