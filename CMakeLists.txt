cmake_minimum_required(VERSION 2.8)
project(libhcs)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ".cmake")

execute_process(COMMAND ${CMAKE_C_COMPILER} -v)
find_package(GMP REQUIRED)
find_package(OpenMP)
if (OPENMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CXXMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

set(LIBRARY_NAME "hcs")
set(LIBRARY_DIR "lib/")
set(INCLUDE_DIR "include/")
set(SOURCE_DIR  "src/")
set(TEST_DIR    "test/")
set(BINARY_DIR  "bin/")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BINARY_DIR})

# BEGIN: Project configuration
file(GLOB srcs "src/*.c" "src/com/*.c")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=c++11")

include(TestBigEndian)
test_big_endian(IsBigEndian)
if (${IsBigEndian})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHCS_BIG_ENDIAN")
endif (${IsBigEndian})
# END: Project configuration

# BEGIN: Build commands
add_library(${LIBRARY_NAME} SHARED ${srcs})
target_link_libraries(${LIBRARY_NAME} ${GMP_LIBRARIES})
# END: Build commands

# BEGIN: Install commands
install(DIRECTORY ${LIBRARY_DIR} DESTINATION lib USE_SOURCE_PERMISSIONS)
install(DIRECTORY ${INCLUDE_DIR} DESTINATION include)
# END: Install commands

# BEGIN: Test commands
enable_testing()
set(CMAKE_CTEST_COMMAND "${CMAKE_CTEST_COMMAND} --verbose")

file(GLOB test_srcs "${TEST_DIR}/*.cpp")
foreach(f ${test_srcs})
    get_filename_component(test_prog ${f} NAME_WE)
    add_executable(${test_prog} "${TEST_DIR}/${test_prog}.cpp")
    target_link_libraries(${test_prog} hcs ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
    add_test(${test_prog} "${BINARY_DIR}/${test_prog}")
endforeach()
# EN: Test commands
