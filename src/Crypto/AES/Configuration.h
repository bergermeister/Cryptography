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
   namespace AES128
   {
      /**
       *
       */
      class Configuration
      {
      public:        // Public Attributes
         static const uint32_t Rounds  = 10;                               ///< Number of rounds
         static const uint32_t KeySize = 16;                               ///< Number of bytes in Key
         static const uint32_t ExpandedKeySize = KeySize * ( Rounds + 1 ); ///< Number of bytes in Expanded Key set
         static const uint32_t BoxSize = 256;                              ///< Number of bytes in S-Box and Galois Look-up Tables
         static const uint8_t  RijndaelSBox[ BoxSize ];                    ///< Rijndael S-Box
         static const uint8_t  RijndaelIBox[ BoxSize ];                    ///< Rijndael Inverse S-Box
         static const uint8_t  RoundConstant[ BoxSize ];                   ///< Round Constants
         static const uint8_t  Mul2[ BoxSize ];                            ///< Galois Multiplication Look-up Table
         static const uint8_t  Mul3[ BoxSize ];                            ///< Galois Multiplication Look-up Table
         static const uint8_t  Mul9[ BoxSize ];                            ///< Galois Multiplication Look-up Table
         static const uint8_t  Mul11[ BoxSize ];                           ///< Galois Multiplication Look-up Table
         static const uint8_t  Mul13[ BoxSize ];                           ///< Galois Multiplication Look-up Table
         static const uint8_t  Mul14[ BoxSize ];                           ///< Galois Multiplication Look-up Table

      private:       // Private attributes
         uint8_t sBox[ BoxSize ];             ///< Substitution Box
         uint8_t iBox[ BoxSize ];             ///< Inverse Substitution Box
         uint8_t eKey[ ExpandedKeySize ];     ///< Expanded Key

      public:        // Public Methods
         Configuration( void );
         Configuration( const Configuration& aorConfig );
         ~Configuration( void );
         Configuration& operator=( const Configuration& aorConfig );

         void ExpandKey( const uint8_t aucpInputKey[ KeySize ] );
         void GenerateSBox( const uint8_t aucpInputKey[ BoxSize ] );

         const uint8_t* ExpandedKey( void ) const;
         const uint8_t* SBox( void ) const;
         const uint8_t* IBox( void ) const;
      };
   }
}

#endif

