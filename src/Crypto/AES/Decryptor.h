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
      class TcDecryptor
      {
      private:    // Private Attributes
         const TcConfiguration& vorCfg;   ///< Algorithm Configuration (S-Box, I-Box, Key Schedule)
         Tu8 vucpState[ TcConfiguration::XuiSizeKey ];

      public:     // Public Methods
         TcDecryptor( const TcConfiguration& aorConfiguration );
         TcDecryptor( const TcDecryptor& aorDecryptor );
         ~TcDecryptor( void );
         TcDecryptor& operator=( const TcDecryptor& aorDecryptor );

         void MDecrypt( const Tu8 aucpCiphertext[ TcConfiguration::XuiSizeKey ],
                        Tu8 aucpPlaintext[ TcConfiguration::XuiSizeKey ] );

      private:    // Private Methods
         void mAddRoundKey( const Tu8* aucpRoundKey );
         void mSubstitute( void );
         void mShiftRows( void );
         void mMixColumns( void );
      };
   }
}

#endif

