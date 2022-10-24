cmake_minimum_required(VERSION 3.20)
project(ssedb C)

find_library( BFD_LIBRARY bfd )

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

set(CMAKE_C_STANDARD 99)

add_executable(ssedb ast.c cmdFuncs.c main.c Get_Symbols_address.c)

# Have CMake link our project executable against Zydis.
target_link_libraries( ssedb PRIVATE ${IBERTY_LIBRARY} ${BFD_LIBRARY} )
target_link_libraries("ssedb" PRIVATE "Zydis")