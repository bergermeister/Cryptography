// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/Communication/Messages/Message.h>
#include <Crypto/Communication/Messages/EstablishSession.h>

using namespace Crypto;
using namespace Crypto::NCommunication::NMessages;

TcEstablishSession::TcEstablishSession( void ) 
   : TcMessage( XuiCountKeys * sizeof( NKeyExchange::TcPublicKey ) + sizeof( Tu32 ), XuiType )
{
   // Nothing to construct
}
TcEstablishSession::TcEstablishSession( const TcEstablishSession& aorEstablish )
   : TcMessage( XuiCountKeys * sizeof( NKeyExchange::TcPublicKey ) + sizeof( Tu32 ), XuiType )
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
   Tu32 kuiIdx;

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

NKeyExchange::TcPublicKey& TcEstablishSession::MSharedKey( const Tu32 auiIndex )
{
   return( this->voSharedKey[ auiIndex ] );
}

const NKeyExchange::TcPublicKey& TcEstablishSession::MSharedKey( const Tu32 auiIndex ) const
{
   return( this->voSharedKey[ auiIndex ] );
}

