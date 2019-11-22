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
         static const Tu8  XucpRCon[ XuiSizeBox ];                                ///< Round Constants
         static const Tu8  XucpMul2[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const Tu8  XucpMul3[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const Tu8  XucpMul9[ XuiSizeBox ];                                ///< Galois Multiplication Look-up Table
         static const Tu8  XucpMul11[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table
         static const Tu8  XucpMul13[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table
         static const Tu8  XucpMul14[ XuiSizeBox ];                               ///< Galois Multiplication Look-up Table

      private:       // Private attributes
         Tu8 vucpSBox[ XuiSizeBox ];             ///< Substitution Box
         Tu8 vucpIBox[ XuiSizeBox ];             ///< Inverse Substitution Box
         Tu8 vucpEKey[ XuiSizeExpandedKey ];     ///< Expanded Key

      public:        // Public Methods
         TcConfiguration( void );
         TcConfiguration( const TcConfiguration& aorConfig );
         ~TcConfiguration( void );
         TcConfiguration& operator=( const TcConfiguration& aorConfig );

         void MExpandKey( const Tu8 aucpInputKey[ XuiSizeKey ] );
         const Tu8* MExpandedKey( void ) const;
         const Tu8* MSBox( void ) const;
         const Tu8* MIBox( void ) const;
      };
   }
}

#endif

