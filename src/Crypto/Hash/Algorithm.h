/**
 * @file
 * This package contains the Generic Hash Algorithm class.
 */
#ifndef Crypto_Hash_Algorithm_h
#define Crypto_Hash_Algorithm_h

// Crypto Includes
#include <Crypto/Types.h>

/// Namespace containing Cryptographic functionality
namespace Crypto
{
   /// Namespace containing Hashing algorithms
   namespace NHash
   {
      /**
       *
       */
      class TcAlgorithm
      {
      private:       // Private Attributes
         const uint8_t* vucpDigest;  ///< Hash Digest

      protected:     // Protected Attributes
         uint32_t vuiDigested; ///< Number of bytes digested

      public:        // Public Methods
         TcAlgorithm( const uint8_t* aucpDigest );
         TcAlgorithm( const TcAlgorithm& aorHash );
         virtual ~TcAlgorithm( void );

         TcAlgorithm& operator=( const TcAlgorithm& aorHash );
         
         virtual void MInitialize( void ) = 0;
         virtual void MProcess( const uint8_t* aucpData, const size_t auiBytes ) = 0;
         virtual void MFinalize( void ) = 0;

         const uint8_t* MDigest( void ) const;
         const uint32_t MDigested( void ) const;

         inline uint64_t MSwap( const uint64_t aulVal )
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

