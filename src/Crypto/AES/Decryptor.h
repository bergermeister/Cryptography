/**
 * @file
 * This package contains the AES Algorithm Decryptor class.
 */
#ifndef Crypto_AES_Decryptor_h
#define Crypto_AES_Decryptor_h

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
      class Decryptor
      {
      private:    // Private Attributes
         const Configuration& config;   ///< Algorithm Configuration (S-Box, I-Box, Key Schedule)
         uint8_t state[ Configuration::KeySize ];

      public:     // Public Methods
         Decryptor( const Configuration& aorConfiguration );
         Decryptor( const Decryptor& aorDecryptor );
         ~Decryptor( void );
         Decryptor& operator=( const Decryptor& aorDecryptor );

         void Decrypt( const uint8_t aucpCiphertext[ Configuration::KeySize ],
                       uint8_t aucpPlaintext[ Configuration::KeySize ] );

      private:    // Private Methods
         void addRoundKey( const uint8_t* aucpRoundKey );
         void substitute( void );
         void shiftRows( void );
         void mixColumns( void );
      };
   }
}

#endif

