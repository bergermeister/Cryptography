/**
 * @file
 * @brief 
 * Generic Hash Algorithm Package
 *
 * @details
 * @par
 * This package contains the Generic Hash Algorithm class.
 */
#ifndef Crypto_Hash_Algorithm_h
#define Crypto_Hash_Algorithm_h

#include <Types.h>

/// Namespace containing Cryptographic functionality
namespace GNCrypto
{
   /// Namespace containing Hashing algorithms
   namespace NHash
   {
      /**
       * @brief
       *
       *
       * @details
       * @par
       *
       */
      class TcAlgorithm
      {
      private:       // Private Attributes
         const Tu8* vucpDigest;  ///< Hash Digest

      protected:     // Protected Attributes
         Tu32 vuiDigested; ///< Number of bytes digested

      public:        // Public Methods
         TcAlgorithm( const Tu8* aucpDigest );
         TcAlgorithm( const TcAlgorithm& aorHash );
         virtual ~TcAlgorithm( void );

         TcAlgorithm& operator=( const TcAlgorithm& aorHash );
         
         virtual void MInitialize( void ) = 0;
         virtual void MProcess( const Tu8* aucpData, const Tu32 auiBytes ) = 0;
         virtual void MFinalize( void ) = 0;

         const Tu8* MDigest( void ) const;
         const Tu32 MDigested( void ) const;

         inline Tu64 MSwap( const Tu64 aulVal )
         {
            return( ( ( aulVal & 0x00000000000000FF ) << 56 ) |
                    ( ( aulVal & 0x000000000000FF00 ) << 40 ) |
                    ( ( aulVal & 0x0000000000FF0000 ) << 24 ) |
                    ( ( aulVal & 0x00000000FF000000 ) <<  8 ) |
                    ( ( aulVal & 0x000000FF00000000 ) >>  8 ) |
                    ( ( aulVal & 0x0000FF0000000000 ) >> 24 ) |
                    ( ( aulVal & 0x00FF000000000000 ) >> 40 ) |
                    ( ( aulVal & 0xFF00000000000000 ) >> 56 ) );
         }
      };
   }
}

#endif

