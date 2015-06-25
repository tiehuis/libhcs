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
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)
message(STATUS "GMP libs: " ${GMP_LIBRARIES} " " ${GMPXX_LIBRARIES} )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG GMP_INCLUDE_DIR GMP_LIBRARIES)
mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARIES)
# END: FindGMP.cmake
# END: dependencies

# BEGIN: Project configuration
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY lib)
file(GLOB srcs "src/*.c" "src/com/*.c")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -std=c99 -Iinclude")

test_big_endian(IsBigEndian)
if (${IsBigEndian})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBIG_ENDIAN=4321 -DBYTE_ORDER=BIG_ENDIAN")
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN")
endif (${IsBigEndian})
# END: Project configuration

# BEGIN: Build commands
add_library(hcs SHARED ${srcs})
target_link_libraries(hcs ${GMP_LIBRARIES})
# END: Build commands

# BEGIN: Install commands
install(DIRECTORY lib/ DESTINATION lib USE_SOURCE_PERMISSIONS)
install(DIRECTORY include/ DESTINATION include)
# END: Install commands
