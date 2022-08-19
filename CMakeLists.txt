cmake_minimum_required( VERSION 3.15 )
project( Crypto VERSION 0.0.1 )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

if( BUILD_TESTING )
   add_compile_options( -fprofile-arcs -ftest-coverage )
   add_link_options( -fprofile-arcs --coverage )
endif( )

add_subdirectory( src )

if( BUILD_TESTING )
   add_subdirectory( tst )
endif( )

