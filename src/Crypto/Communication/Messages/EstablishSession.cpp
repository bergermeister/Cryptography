// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/Communication/Messages/Message.h>
#include <Crypto/Communication/Messages/EstablishSession.h>

using namespace Crypto;
using namespace Crypto::Communication::Messages;

EstablishSession::EstablishSession( void ) 
   : Message( XuiCountKeys * sizeof( KeyExchange::PublicKey ) + sizeof( uint32_t ), XuiType )
{
   // Nothing to construct
}
EstablishSession::EstablishSession( const EstablishSession& aorEstablish )
   : Message( XuiCountKeys * sizeof( KeyExchange::PublicKey ) + sizeof( uint32_t ), XuiType )
{
   // Call assignment operator
   *this = aorEstablish;
}

EstablishSession::~EstablishSession( void )
{
   // Nothing to destruct
}

EstablishSession& EstablishSession::operator=( const EstablishSession& aorEstablish )
{
   uint32_t kuiIdx;

   if( this != &aorEstablish )
   {
      // Call base class operator=
      Message::operator=( static_cast< const Message& >( aorEstablish ) );

      for( kuiIdx = 0; kuiIdx < XuiCountKeys; kuiIdx++ )
      {
         this->voSharedKey[ kuiIdx ] = aorEstablish.voSharedKey[ kuiIdx ];
      }
   }

   return( *this );
}

KeyExchange::PublicKey& EstablishSession::SharedKey( const uint32_t auiIndex )
{
   return( this->voSharedKey[ auiIndex ] );
}

const KeyExchange::PublicKey& EstablishSession::SharedKey( const uint32_t auiIndex ) const
{
   return( this->voSharedKey[ auiIndex ] );
}

