/**
 * @file
 * @brief
 * AES Algorithm Configuration Package
 *
 * @details
 * @par
 * This package contains the AES Algorithm Configuration class.
 */
#ifndef Crypto_AES_Configuration_h
#define Crypto_AES_Configuration_h

#include <Types.h>

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
      class TcConfiguration
      {
      public:        // Public Attributes
         static const Tu32 XuiRounds  = 10;                                      ///< Number of rounds
         static const Tu32 XuiSizeKey = 16;                                      ///< Number of bytes in Key
         static const Tu32 XuiSizeExpandedKey = XuiSizeKey * ( XuiRounds + 1 );  ///< Number of bytes in Expanded Key set
         static const Tu32 XuiSizeBox = 256;                                     ///< Number of bytes in S-Box and Galois Look-up Tables
         static const Tu8  XucpRijndaelSBox[ XuiSizeBox ];                       ///< Rijndael S-Box
         static const Tu8  XucpRijndaelIBox[ XuiSizeBox ];                       ///< Rijndael Inverse S-Box
         static const Tu8  XucRCon[ XuiSizeBox ];                                ///< Round Constants
         static const Tu8  XucMul2[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const Tu8  XucMul3[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const Tu8  XucMul9[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const Tu8  XucMul11[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table
         static const Tu8  XucMul13[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table
         static const Tu8  XucMul14[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table

      private:       // Private attributes
         Tu8 vucSBox[ XuiSizeBox ];
         Tu8 vucIBox[ XuiSizeBox ];

      public:        // Public Methods
         TcConfiguration( void );
         TcConfiguration( const TcConfiguration& aorConfig );
         ~TcConfiguration( void );
         TcConfiguration& operator=( const TcConfiguration& aorConfig );

         void MExpandKey( const Tu8 aucpInputKey[ XuiSizeKey ], Tu8 aucpExpandedKeys[ XuiSizeExpandedKey ] );
      };
   }
}

#endif

