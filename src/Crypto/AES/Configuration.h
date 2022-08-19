/**
 * @file
 * This package contains the AES Algorithm Configuration class.
 */
#ifndef Crypto_AES_Configuration_h
#define Crypto_AES_Configuration_h

// Crypto Includes
#include <Crypto/Types.h>

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
      class TcConfiguration
      {
      public:        // Public Attributes
         static const uint32_t XuiRounds  = 10;                                      ///< Number of rounds
         static const uint32_t XuiSizeKey = 16;                                      ///< Number of bytes in Key
         static const uint32_t XuiSizeExpandedKey = XuiSizeKey * ( XuiRounds + 1 );  ///< Number of bytes in Expanded Key set
         static const uint32_t XuiSizeBox = 256;                                     ///< Number of bytes in S-Box and Galois Look-up Tables
         static const uint8_t  XucpRijndaelSBox[ XuiSizeBox ];                       ///< Rijndael S-Box
         static const uint8_t  XucpRijndaelIBox[ XuiSizeBox ];                       ///< Rijndael Inverse S-Box
         static const uint8_t  XucpRCon[ XuiSizeBox ];                                ///< Round Constants
         static const uint8_t  XucpMul2[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const uint8_t  XucpMul3[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const uint8_t  XucpMul9[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const uint8_t  XucpMul11[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table
         static const uint8_t  XucpMul13[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table
         static const uint8_t  XucpMul14[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table

      private:       // Private attributes
         uint8_t vucpSBox[ XuiSizeBox ];             ///< Substitution Box
         uint8_t vucpIBox[ XuiSizeBox ];             ///< Inverse Substitution Box
         uint8_t vucpEKey[ XuiSizeExpandedKey ];     ///< Expanded Key

      public:        // Public Methods
         TcConfiguration( void );
         TcConfiguration( const TcConfiguration& aorConfig );
         ~TcConfiguration( void );
         TcConfiguration& operator=( const TcConfiguration& aorConfig );

         void MExpandKey( const uint8_t aucpInputKey[ XuiSizeKey ] );
         void MGenerateSBox( const uint8_t aucpInputKey[ XuiSizeBox ] );

         const uint8_t* MExpandedKey( void ) const;
         const uint8_t* MSBox( void ) const;
         const uint8_t* MIBox( void ) const;
      };
   }
}

#endif

