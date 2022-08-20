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
   namespace Hash
   {
      /**
       *
       */
      class Algorithm
      {
      private:       // Private Attributes
         const uint8_t* digest;  ///< Hash Digest

      protected:     // Protected Attributes
         size_t bytesDigested; ///< Number of bytes digested

      public:        // Public Methods
         Algorithm( const uint8_t* aucpDigest );
         Algorithm( const Algorithm& aorHash );
         virtual ~Algorithm( void );

         Algorithm& operator=( const Algorithm& aorHash );
         
         virtual void Initialize( void ) = 0;
         virtual void Process( const uint8_t* aucpData, const size_t auiBytes ) = 0;
         virtual void Finalize( void ) = 0;

         const uint8_t* Digest( void ) const;
         const size_t BytesDigested( void ) const;

         inline uint64_t Swap( const uint64_t aulVal )
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

