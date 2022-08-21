cmake_minimum_required( VERSION 3.15 )
project( Crypto VERSION 0.0.1 )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

add_compile_options( -std=c++14 -Wall )
if( BUILD_TESTING )
   # -pg    enable profiling
   add_compile_options( -fprofile-arcs -ftest-coverage -pg --no-pie -no-pie -fno-pie )
   add_link_options( -fprofile-arcs --coverage -pg --no-pie -no-pie -fno-pie )
   #set( CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qc -o <TARGET> <OBJECTS>" )
endif( )

add_subdirectory( src )

if( BUILD_TESTING )
   add_subdirectory( tst )
endif( )

