CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(cpp_py_frame)
#dependency

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
endif(MSVC)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

ADD_EXECUTABLE(unwind_c_stack ${CMAKE_SOURCE_DIR}/test/unwind_c_stack.cpp)
ADD_EXECUTABLE(unwind_cpp_stack ${CMAKE_SOURCE_DIR}/test/unwind_cpp_stack.cpp)
ADD_EXECUTABLE(unwind_ptrace_stack ${CMAKE_SOURCE_DIR}/test/unwind_ptrace_stack.cpp)

target_link_libraries(unwind_c_stack unwind)
target_link_libraries(unwind_cpp_stack unwind)
target_link_libraries(unwind_ptrace_stack unwind unwind-ptrace unwind-generic)