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

   // Configure AES Algorithm using the first 128-bits of SharedSecret[ 0 ] as the key
   this->voConfig.MExpandKey( reinterpret_cast< const Tu8* >( &this->vulSharedSecret[ 0 ] ) );

   return( koMsg );
}

void TcSession::MEncrypt( const Tu8* aucpPlaintext, Tu8* aucpCiphertext, const Tu32 auiBytes )
{
   Tu8  kucpBuffer[ NAES128::TcConfiguration::XuiSizeKey ];
   Tu32 kuiRemaining = auiBytes;
   Tu32 kuiOffset    = 0;

   while( kuiRemaining >= NAES128::TcConfiguration::XuiSizeKey )
   {
      this->voEncryptor.MEncrypt( &aucpPlaintext[ kuiOffset ], &aucpCiphertext[ kuiOffset ] );
      kuiOffset    += NAES128::TcConfiguration::XuiSizeKey;
      kuiRemaining -= NAES128::TcConfiguration::XuiSizeKey;
   }

   if( kuiRemaining > 0 )
   {
      std::memset( reinterpret_cast< void* >( kucpBuffer ), 0, NAES128::TcConfiguration::XuiSizeKey );
      std::memcpy( reinterpret_cast< void* >( kucpBuffer ),
                   reinterpret_cast< const void* >( &aucpPlaintext[ kuiOffset ] ),
                   kuiRemaining );
      this->voEncryptor.MEncrypt( kucpBuffer, &aucpCiphertext[ kuiOffset ] );
   }
}

void TcSession::MDecrypt( const Tu8* aucpCiphertext, Tu8* aucpPlaintext, const Tu32 auiBytes )
{
   Tu32 kuiRemaining = auiBytes;
   Tu32 kuiOffset = 0;

   while( kuiRemaining >= NAES128::TcConfiguration::XuiSizeKey )
   {
      this->voDecryptor.MDecrypt( &aucpCiphertext[ kuiOffset ], &aucpPlaintext[ kuiOffset ] );
      kuiOffset    += NAES128::TcConfiguration::XuiSizeKey;
      kuiRemaining -= NAES128::TcConfiguration::XuiSizeKey;
   }
}

