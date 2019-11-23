/**
 * @file
 * @brief
 * Encrypted Communication Session Package
 *
 * @details
 * @par
 * This package contains the Encrypted Communication Session class.
 */
#include <Types.h>
#include <AES/Configuration.h>
#include <AES/Encryptor.h>
#include <AES/Decryptor.h>
#include <KeyExchange/DiffieHellman.h>
#include <Communication/Messages/EstablishSession.h>
#include <Communication/Session.h>
#include <cstring>

using namespace GNCrypto;
using namespace GNCrypto::NKeyExchange;
using namespace GNCrypto::NCommunication;

TcSession::TcSession( const Tu64 aulpPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ] )
   : voEncryptor( voConfig ), voDecryptor( voConfig )
{
   std::memcpy( reinterpret_cast< void* >( this->vulPrivateKey ),
                reinterpret_cast< const void* >( aulpPrivateKey ),
                NMessages::TcEstablishSession::XuiCountKeys * sizeof( Tu64 ) );

   std::memset( reinterpret_cast< void* >( this->vulSharedSecret ), 0, 
                NMessages::TcEstablishSession::XuiCountKeys * sizeof( Tu64 ) );
}

TcSession::TcSession( const TcSession& aorSession )
   : voEncryptor( voConfig ), voDecryptor( voConfig )
{
   *this = aorSession;
}

TcSession::~TcSession( void )
{
   // Nothing to destruct
}

TcSession& TcSession::operator=( const TcSession& aorSession )
{
   if( this != &aorSession )
   {
      this->voConfig    = aorSession.voConfig;
      this->voEncryptor = aorSession.voEncryptor;
      this->voDecryptor = aorSession.voDecryptor;
   }

   return( *this );
}

NMessages::TcEstablishSession TcSession::MRequest( void )
{
   NMessages::TcEstablishSession koMsg;
   Tu32                          kuiIdx;

   for( kuiIdx = 0; kuiIdx < NMessages::TcEstablishSession::XuiCountKeys; kuiIdx++ )
   {
      koMsg.MSharedKey( kuiIdx ).MUpdate( 97, 92, this->vulPrivateKey[ kuiIdx ] );
   }

   return( koMsg );
}

NMessages::TcEstablishSession TcSession::MEstablish( const NMessages::TcEstablishSession& aorRequest )
{
   NMessages::TcEstablishSession koMsg;
   Tu32                          kuiIdx;

   for( kuiIdx = 0; kuiIdx < NMessages::TcEstablishSession::XuiCountKeys; kuiIdx++ )
   {
      const TcPublicKey& korPub = aorRequest.MSharedKey( kuiIdx );
      koMsg.MSharedKey( kuiIdx ).MUpdate( korPub.MP( ), korPub.MG( ), this->vulPrivateKey[ kuiIdx ] );
      this->vulSharedSecret[ kuiIdx ] = NDiffieHellman::MCalculate( korPub.MSharedKey( ), 
                                                                    this->vulPrivateKey[ kuiIdx ], 
                                                                    korPub.MP( ) );
      
   }

   return( koMsg );
}

