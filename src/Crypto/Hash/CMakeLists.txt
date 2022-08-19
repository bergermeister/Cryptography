target_sources( Crypto 
   PRIVATE
      Algorithm.cpp 
      SHA.cpp
      SHA512.cpp
)

set( publicHeaders
   Algorithm.h
   SHA.h
   SHA512.h   
)

# install( FILES )