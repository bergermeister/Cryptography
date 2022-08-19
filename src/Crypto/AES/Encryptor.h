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
   namespace NAES128
   {
      /**
       * @brief
       *
       *
       * @details
       * @par
       *
       */
      class TcEncryptor
      {
      private:       // Private Attriutes
         const TcConfiguration& vorCfg;   ///< Algorithm Configuration (S-Box, I-Box, Key Schedule)
         uint8_t vucpState[ TcConfiguration::XuiSizeKey ];

      public:        // Public Methods
         TcEncryptor( const TcConfiguration& aorConfiguration );
         TcEncryptor( const TcEncryptor& aorEncryptor );
         ~TcEncryptor( void );
         TcEncryptor& operator=( const TcEncryptor& aorEncryptor );

         void MEncrypt( const uint8_t aucpPlaintext[ TcConfiguration::XuiSizeKey ], 
                        uint8_t aucpCiphertext[ TcConfiguration::XuiSizeKey ] );

      private:       // Private Methods
         void mAddRoundKey( const uint8_t* aucpRoundKey );
         void mSubstitute( void );
         void mShiftRows( void );
         void mMixColumns( void );
      };
   }
}

#endif

