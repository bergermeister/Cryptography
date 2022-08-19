target_sources( Crypto 
   PRIVATE
      GCD.cpp 
      Prime.cpp
)

set( publicHeaders
   GCD.h
   Prime.h
)

# install( FILES )