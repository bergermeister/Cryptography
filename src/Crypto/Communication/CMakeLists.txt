target_sources( Crypto 
   PRIVATE
      Session.cpp 
)

set( publicHeaders
   Session.h
)

add_subdirectory( Messages )

# install( FILES )