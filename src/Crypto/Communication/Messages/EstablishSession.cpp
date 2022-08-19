// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/Communication/Messages/Message.h>
#include <Crypto/Communication/Messages/EstablishSession.h>

using namespace Crypto;
using namespace Crypto::NCommunication::NMessages;

TcEstablishSession::TcEstablishSession( void ) 
   : TcMessage( XuiCountKeys * sizeof( NKeyExchange::TcPublicKey ) + sizeof( uint32_t ), XuiType )
{
   // Nothing to construct
}
TcEstablishSession::TcEstablishSession( const TcEstablishSession& aorEstablish )
   : TcMessage( XuiCountKeys * sizeof( NKeyExchange::TcPublicKey ) + sizeof( uint32_t ), XuiType )
{
   // Call assignment operator
   *this = aorEstablish;
}

TcEstablishSession::~TcEstablishSession( void )
{
   // Nothing to destruct
}

TcEstablishSession& TcEstablishSession::operator=( const TcEstablishSession& aorEstablish )
{
   uint32_t kuiIdx;

   if( this != &aorEstablish )
   {
      // Call base class operator=
      TcMessage::operator=( static_cast< const TcMessage& >( aorEstablish ) );

      for( kuiIdx = 0; kuiIdx < XuiCountKeys; kuiIdx++ )
      {
         this->voSharedKey[ kuiIdx ] = aorEstablish.voSharedKey[ kuiIdx ];
      }
   }

   return( *this );
}

NKeyExchange::TcPublicKey& TcEstablishSession::MSharedKey( const uint32_t auiIndex )
{
   return( this->voSharedKey[ auiIndex ] );
}

const NKeyExchange::TcPublicKey& TcEstablishSession::MSharedKey( const uint32_t auiIndex ) const
{
   return( this->voSharedKey[ auiIndex ] );
}

