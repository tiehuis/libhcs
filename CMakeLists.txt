cmake_minimum_required(VERSION 3.0) # Require 3.0 for endian test
project(libhcs)
include(TestBigEndian)

# BEGIN: dependencies
# BEGIN: FindGMP.cmake
if (GMP_INCLUDE_DIR AND GMP_LIBRARIES)
    # Already in cache, be silent
    set(GMP_FIND_QUIETLY TRUE)
endif (GMP_INCLUDE_DIR AND GMP_LIBRARIES)

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_path(GMPXX_INCLUDE_DIR NAMES gmpxx.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)
message(STATUS "GMP libs: " ${GMP_LIBRARIES} " " ${GMPXX_LIBRARIES} )

mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARIES GMPXX_INCLUDE_DIR GMPXX_LIBRARIES)
# END: FindGMP.cmake
# END: dependencies

set(LIBRARY_NAME "hcs")
set(LIBRARY_DIR "lib")
set(INCLUDE_DIR "include")
set(SOURCE_DIR  "src")
set(TEST_DIR    "test")
set(BINARY_DIR  "bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BINARY_DIR})

# BEGIN: Project configuration
file(GLOB srcs "src/*.c" "src/com/*.c")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -std=c99 -Iinclude")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -std=c++11 -Iinclude")

test_big_endian(IsBigEndian)
if (${IsBigEndian})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBIG_ENDIAN=4321 -DBYTE_ORDER=BIG_ENDIAN")
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN")
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
# END: Test commands
