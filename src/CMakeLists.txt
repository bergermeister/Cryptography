add_library( Crypto STATIC )

add_subdirectory( Crypto )

target_include_directories( Crypto 
   PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
   PUBLIC
      # where top-level project will look for the library's public headers
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      # where external projects will look for the library's public headers
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)