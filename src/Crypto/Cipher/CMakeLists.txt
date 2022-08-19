target_sources( Crypto 
   PRIVATE
      RSA.cpp 
)

set( publicHeaders
   ICipher.h
   RSA.h
)

# install( FILES )