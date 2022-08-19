// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Encryptor.h>
#include <Crypto/AES/Decryptor.h>
#include <Crypto/KeyExchange/DiffieHellman.h>
#include <Crypto/Communication/Messages/EstablishSession.h>
#include <Crypto/Communication/Session.h>

using namespace Crypto;
using namespace Crypto::NKeyExchange;
using namespace Crypto::NCommunication;

TcSession::TcSession( const uint64_t aulpPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ] )
   : voEncryptor( voConfig ), voDecryptor( voConfig )
{
   std::memcpy( reinterpret_cast< void* >( this->vulpPrivateKey ),
                reinterpret_cast< const void* >( aulpPrivateKey ),
                NMessages::TcEstablishSession::XuiCountKeys * sizeof( uint64_t ) );

   std::memset( reinterpret_cast< void* >( this->vulpSharedSecret ), 0, 
                NMessages::TcEstablishSession::XuiCountKeys * sizeof( uint64_t ) );

   std::memset( reinterpret_cast< void* >( this->vucpHash ), 0,
                NMessages::TcEstablishSession::XuiCountKeys * NHash::TcSHA512::XuiLength );
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
      std::memcpy( reinterpret_cast< void* >( this->vulpPrivateKey ),
                   reinterpret_cast< const void* >( aorSession.vulpPrivateKey ),
                   NMessages::TcEstablishSession::XuiCountKeys * sizeof( uint64_t ) );

      std::memcpy( reinterpret_cast< void* >( this->vulpSharedSecret ),
                   reinterpret_cast< const void* >( aorSession.vulpSharedSecret ),
                   NMessages::TcEstablishSession::XuiCountKeys * sizeof( uint64_t ) );

      std::memcpy( reinterpret_cast< void* >( this->vucpHash ),
                   reinterpret_cast< const void* >( aorSession.vucpHash ),
                   NMessages::TcEstablishSession::XuiCountKeys * NHash::TcSHA512::XuiLength );

      this->voConfig    = aorSession.voConfig;
      this->voEncryptor = aorSession.voEncryptor;
      this->voDecryptor = aorSession.voDecryptor;
   }

   return( *this );
}

NMessages::TcEstablishSession TcSession::MRequest( void )
{
   NMessages::TcEstablishSession koMsg;
   uint32_t                          kuiIdx;

   for( kuiIdx = 0; kuiIdx < NMessages::TcEstablishSession::XuiCountKeys; kuiIdx++ )
   {
      koMsg.MSharedKey( kuiIdx ).MUpdate( 97, 92, this->vulpPrivateKey[ kuiIdx ] );
   }

   return( koMsg );
}

NMessages::TcEstablishSession TcSession::MEstablish( const NMessages::TcEstablishSession& aorRequest, bool abDynamicSBox )
{
   NMessages::TcEstablishSession koMsg;
   NHash::TcSHA512               koSHA;
   uint32_t                          kuiIdx;

   for( kuiIdx = 0; kuiIdx < NMessages::TcEstablishSession::XuiCountKeys; kuiIdx++ )
   {
      /// -# Obtain the Public Key
      const TcPublicKey& korPub = aorRequest.MSharedKey( kuiIdx );

      /// -# Calculate Shared Key
      koMsg.MSharedKey( kuiIdx ).MUpdate( korPub.MP( ), korPub.MG( ), this->vulpPrivateKey[ kuiIdx ] );

      /// -# Calculate Shared Secret
      this->vulpSharedSecret[ kuiIdx ] = NDiffieHellman::MCalculate( korPub.MSharedKey( ), 
                                                                     this->vulpPrivateKey[ kuiIdx ], 
                                                                     korPub.MP( ) );

      /// -# Calculate SHA-512 of Shared Secret
      koSHA.MInitialize( );
      koSHA.MProcess( reinterpret_cast< const uint8_t* >( &this->vulpSharedSecret[ kuiIdx ] ), sizeof( uint64_t ) );
      koSHA.MFinalize( );
      std::memcpy( reinterpret_cast< void* >( this->vucpHash[ kuiIdx ] ), 
                   reinterpret_cast< const void* >( koSHA.MDigest( ) ), 
                   NHash::TcSHA512::XuiLength );
   }

   /// -# Configure AES Algorithm using the first 128-bits of SharedSecret[ 0 ]'s Digest as the key
   this->voConfig.MExpandKey( reinterpret_cast< const uint8_t* >( this->vucpHash[ 0 ] ) );

   /// -# Generation S-Box and Inverse S-Box using SharedSecret[ 1 - 4 ]'s Digest
   if( abDynamicSBox )
   {
      this->voConfig.MGenerateSBox( reinterpret_cast< const uint8_t* >( &this->vucpHash[ 1 ] ) );
   }

   return( koMsg );
}

NAES128::TcConfiguration& TcSession::SConfiguration( void )
{
   return( this->voConfig );
}

void TcSession::MEncrypt( const uint8_t* aucpPlaintext, uint8_t* aucpCiphertext, const size_t auiBytes )
{
   uint8_t  kucpBuffer[ NAES128::TcConfiguration::XuiSizeKey ];
   size_t kuiRemaining = auiBytes;
   size_t kuiOffset    = 0;

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

void TcSession::MDecrypt( const uint8_t* aucpCiphertext, uint8_t* aucpPlaintext, const size_t auiBytes )
{
   size_t kuiRemaining = auiBytes;
   size_t kuiOffset = 0;

   while( kuiRemaining >= NAES128::TcConfiguration::XuiSizeKey )
   {
      this->voDecryptor.MDecrypt( &aucpCiphertext[ kuiOffset ], &aucpPlaintext[ kuiOffset ] );
      kuiOffset    += NAES128::TcConfiguration::XuiSizeKey;
      kuiRemaining -= NAES128::TcConfiguration::XuiSizeKey;
   }
}

