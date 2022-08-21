/**
 * @file
 * @brief
 * Encrypted Communication Session Package
 *
 * @details
 * @par
 * This package contains the Encrypted Communication Session class.
 */
#ifndef Crypto_Communication_Session_h
#define Crypto_Communication_Session_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Encryptor.h>
#include <Crypto/AES/Decryptor.h>
#include <Crypto/Communication/Messages/EstablishSession.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
{
   /// Namespace containing encrypted communication functionality
   namespace Communication
   {
      /**
       * 
       *
       */
      class Session
      {
      private:    // Private Attributes
         uint64_t privateKey[ Messages::EstablishSession::XuiCountKeys ];
         uint64_t sharedSecret[ Messages::EstablishSession::XuiCountKeys ];
         uint8_t hash[ Messages::EstablishSession::XuiCountKeys ][ Hash::SHA512::Length ];
         AES128::Configuration config;
         AES128::Encryptor encryptor;
         AES128::Decryptor decryptor;

      public:     // Public Methods
         Session( const uint64_t aulpPrivateKey[ Messages::EstablishSession::XuiCountKeys ] );
         Session( const Session& aorSession );
         ~Session( void );
         Session& operator=( const Session& aorSession );

         Messages::EstablishSession Request( void );
         Messages::EstablishSession Establish( const Messages::EstablishSession& aorRequest, bool abDynamicSBox );

         AES128::Configuration& Configuration( void );

         void Encrypt( const uint8_t* aucpPlaintext,  uint8_t* aucpCiphertext, const size_t auiBytes );
         void Decrypt( const uint8_t* aucpCiphertext, uint8_t* aucpPlaintext,  const size_t auiBytes );
      };
   }
}

#endif
