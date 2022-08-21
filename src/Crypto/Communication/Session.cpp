// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Encryptor.h>
#include <Crypto/AES/Decryptor.h>
#include <Crypto/KeyExchange/DiffieHellman.h>
#include <Crypto/Communication/Messages/EstablishSession.h>
#include <Crypto/Communication/Session.h>

using namespace Crypto;
using namespace Crypto::KeyExchange;
using namespace Crypto::Communication;

Session::Session( const uint64_t aulpPrivateKey[ Messages::EstablishSession::XuiCountKeys ] )
   : encryptor( config ), decryptor( config )
{
   std::memcpy( reinterpret_cast< void* >( this->privateKey ),
                reinterpret_cast< const void* >( aulpPrivateKey ),
                Messages::EstablishSession::XuiCountKeys * sizeof( uint64_t ) );

   std::memset( reinterpret_cast< void* >( this->sharedSecret ), 0, 
                Messages::EstablishSession::XuiCountKeys * sizeof( uint64_t ) );

   std::memset( reinterpret_cast< void* >( this->hash ), 0,
                Messages::EstablishSession::XuiCountKeys * Hash::SHA512::Length );
}

Session::Session( const Session& aorSession )
   : encryptor( config ), decryptor( config )
{
   *this = aorSession;
}

Session::~Session( void )
{
   // Nothing to destruct
}

Session& Session::operator=( const Session& aorSession )
{
   if( this != &aorSession )
   {
      std::memcpy( reinterpret_cast< void* >( this->privateKey ),
                   reinterpret_cast< const void* >( aorSession.privateKey ),
                   Messages::EstablishSession::XuiCountKeys * sizeof( uint64_t ) );

      std::memcpy( reinterpret_cast< void* >( this->sharedSecret ),
                   reinterpret_cast< const void* >( aorSession.sharedSecret ),
                   Messages::EstablishSession::XuiCountKeys * sizeof( uint64_t ) );

      std::memcpy( reinterpret_cast< void* >( this->hash ),
                   reinterpret_cast< const void* >( aorSession.hash ),
                   Messages::EstablishSession::XuiCountKeys * Hash::SHA512::Length );

      this->config    = aorSession.config;
      this->encryptor = aorSession.encryptor;
      this->decryptor = aorSession.decryptor;
   }

   return( *this );
}

Messages::EstablishSession Session::Request( void )
{
   Messages::EstablishSession koMsg;
   uint32_t                          kuiIdx;

   for( kuiIdx = 0; kuiIdx < Messages::EstablishSession::XuiCountKeys; kuiIdx++ )
   {
      koMsg.SharedKey( kuiIdx ).Update( 97, 92, this->privateKey[ kuiIdx ] );
   }

   return( koMsg );
}

Messages::EstablishSession Session::Establish( const Messages::EstablishSession& aorRequest, bool abDynamicSBox )
{
   Messages::EstablishSession koMsg;
   Hash::SHA512               koSHA;
   uint32_t                          kuiIdx;

   for( kuiIdx = 0; kuiIdx < Messages::EstablishSession::XuiCountKeys; kuiIdx++ )
   {
      /// -# Obtain the Public Key
      const PublicKey& korPub = aorRequest.SharedKey( kuiIdx );

      /// -# Calculate Shared Key
      koMsg.SharedKey( kuiIdx ).Update( korPub.P( ), korPub.G( ), this->privateKey[ kuiIdx ] );

      /// -# Calculate Shared Secret
      this->sharedSecret[ kuiIdx ] = DiffieHellman::MCalculate( korPub.SharedKey( ), 
                                                                     this->privateKey[ kuiIdx ], 
                                                                     korPub.P( ) );

      /// -# Calculate SHA-512 of Shared Secret
      koSHA.Initialize( );
      koSHA.Process( reinterpret_cast< const uint8_t* >( &this->sharedSecret[ kuiIdx ] ), sizeof( uint64_t ) );
      koSHA.Finalize( );
      std::memcpy( reinterpret_cast< void* >( this->hash[ kuiIdx ] ), 
                   reinterpret_cast< const void* >( koSHA.Digest( ) ), 
                   Hash::SHA512::Length );
   }

   /// -# Configure AES Algorithm using the first 128-bits of SharedSecret[ 0 ]'s Digest as the key
   this->config.ExpandKey( reinterpret_cast< const uint8_t* >( this->hash[ 0 ] ) );

   /// -# Generation S-Box and Inverse S-Box using SharedSecret[ 1 - 4 ]'s Digest
   if( abDynamicSBox )
   {
      this->config.GenerateSBox( reinterpret_cast< const uint8_t* >( &this->hash[ 1 ] ) );
   }

   return( koMsg );
}

AES128::Configuration& Session::Configuration( void )
{
   return( this->config );
}

void Session::Encrypt( const uint8_t* aucpPlaintext, uint8_t* aucpCiphertext, const size_t auiBytes )
{
   uint8_t  kucpBuffer[ AES128::Configuration::KeySize ];
   size_t kuiRemaining = auiBytes;
   size_t kuiOffset    = 0;

   while( kuiRemaining >= AES128::Configuration::KeySize )
   {
      this->encryptor.Encrypt( &aucpPlaintext[ kuiOffset ], &aucpCiphertext[ kuiOffset ] );
      kuiOffset    += AES128::Configuration::KeySize;
      kuiRemaining -= AES128::Configuration::KeySize;
   }

   if( kuiRemaining > 0 )
   {
      std::memset( reinterpret_cast< void* >( kucpBuffer ), 0, AES128::Configuration::KeySize );
      std::memcpy( reinterpret_cast< void* >( kucpBuffer ),
                   reinterpret_cast< const void* >( &aucpPlaintext[ kuiOffset ] ),
                   kuiRemaining );
      this->encryptor.Encrypt( kucpBuffer, &aucpCiphertext[ kuiOffset ] );
   }
}

void Session::Decrypt( const uint8_t* aucpCiphertext, uint8_t* aucpPlaintext, const size_t auiBytes )
{
   size_t kuiRemaining = auiBytes;
   size_t kuiOffset = 0;

   while( kuiRemaining >= AES128::Configuration::KeySize )
   {
      this->decryptor.Decrypt( &aucpCiphertext[ kuiOffset ], &aucpPlaintext[ kuiOffset ] );
      kuiOffset    += AES128::Configuration::KeySize;
      kuiRemaining -= AES128::Configuration::KeySize;
   }
}

