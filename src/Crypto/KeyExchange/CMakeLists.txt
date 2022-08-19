target_sources( Crypto 
   PRIVATE
      DiffieHellman.cpp 
      PublicKey.cpp
)

set( publicHeaders
   DiffieHellman.h
   PublicKey.h
)

# install( FILES )