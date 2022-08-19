target_sources( Crypto 
   PRIVATE
      EstablishSession.cpp 
      Message.cpp
)

set( publicHeaders
   EstablishSession.h
   Message.h
)

# install( FILES )