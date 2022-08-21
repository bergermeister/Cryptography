/**
 * @file
 * This package contains the AES Algorithm Encryptor class.
 */
#ifndef Crypto_AES_Encryptor_h
#define Crypto_AES_Encryptor_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
{
   /// Namespace containing the 128-Bit AES Algorithm
   namespace AES128
   {
      /**
       *
       */
      class Encryptor
      {
      private:       // Private Attriutes
         const Configuration& config;   ///< Algorithm Configuration (S-Box, I-Box, Key Schedule)
         uint8_t state[ Configuration::KeySize ];

      public:        // Public Methods
         Encryptor( const Configuration& aorConfiguration );
         Encryptor( const Encryptor& aorEncryptor );
         ~Encryptor( void );
         Encryptor& operator=( const Encryptor& aorEncryptor );

         void Encrypt( const uint8_t aucpPlaintext[ Configuration::KeySize ], 
                       uint8_t aucpCiphertext[ Configuration::KeySize ] );

      private:       // Private Methods
         void addRoundKey( const uint8_t* aucpRoundKey );
         void substitute( void );
         void shiftRows( void );
         void mixColumns( void );
      };
   }
}

#endif

