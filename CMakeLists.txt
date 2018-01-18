cmake_minimum_required(VERSION 3.5.1)

project(sdcp C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

if (MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
endif ()

add_subdirectory(src)
