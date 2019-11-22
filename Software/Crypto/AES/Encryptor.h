/**
 * @file
 * @brief
 * AES Algorithm Encryptor Package
 *
 * @details
 * @par
 * This package contains the AES Algorithm Encryptor class.
 */
#ifndef Crypto_AES_Encryptor_h
#define Crypto_AES_Encryptor_h

#include <Types.h>
#include <AES/Configuration.h>

/// Namespace containing Cryptograpic functionality
namespace GNCrypto
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
         Tu8 vucpState[ TcConfiguration::XuiSizeKey ];

      public:        // Public Methods
         TcEncryptor( const TcConfiguration& aorConfiguration );
         TcEncryptor( const TcEncryptor& aorEncryptor );
         ~TcEncryptor( void );
         TcEncryptor& operator=( const TcEncryptor& aorEncryptor );

         void MEncrypt( const Tu8 aucpPlaintext[ TcConfiguration::XuiSizeKey ], 
                        Tu8 aucpCiphertext[ TcConfiguration::XuiSizeKey ] );

      private:       // Private Methods
         void mAddRoundKey( const Tu8* aucpRoundKey );
         void mSubstitute( void );
         void mShiftRows( void );
         void mMixColumns( void );
      };
   }
}

#endif

