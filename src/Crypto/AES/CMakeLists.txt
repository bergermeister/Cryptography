target_sources( Crypto 
   PRIVATE
      Configuration.cpp 
      Encryptor.cpp
      Decryptor.cpp
)

set( publicHeaders
   Configuration.h
   Decryptor.h
   Encryptor.h   
)

# install( FILES )