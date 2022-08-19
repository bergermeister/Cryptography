include( FetchContent )

FetchContent_Declare(
   googletest
   GIT_REPOSITORY https://github.com/google/googletest.git
   GIT_TAG release-1.12.1
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set( gtest_force_shared_crt ON CACHE BOOL "" FORCE )
FetchContent_MakeAvailable( googletest )

enable_testing( )

add_executable( GTestCrypto )

add_subdirectory( Crypto )

target_include_directories( GTestCrypto 
   PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
   PUBLIC
      # where top-level project will look for the library's public headers
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      # where external projects will look for the library's public headers
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(
  GTestCrypto
  GTest::gtest_main
  Crypto
)

include( GoogleTest )
gtest_discover_tests( GTestCrypto )