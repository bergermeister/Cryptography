/**
 * @file
 * This package provides the Secure Hash Algorithm base class.
 */
#ifndef Crypto_Hash_SHA_h
#define Crypto_Hash_SHA_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>

 /// Namespace containing Cryptographic functionality
namespace Crypto
{
   /// Namespace containing Hashing algorithms
   namespace Hash
   {
      /** 
       * Secure Hash Algorithm (SHA) Base Class
       */
      class SHA : public Algorithm
      {
      private:       // Private Attributes
         static const uint32_t xuiBPB = 8; ///< Bits Per Byte

      public:        // Public Methods
         SHA( const uint8_t* aucpDigest );
         SHA( const SHA& aorSHA );
         virtual ~SHA( void );
         SHA& operator=( const SHA& aorSHA );

         virtual void Initialize( void ) = 0;
         virtual void Process( const uint8_t* aucpData, const size_t auiBytes ) = 0;
         virtual void Finalize( void ) = 0;

         using Algorithm::Digest;
         using Algorithm::BytesDigested;
      };
   }
}

#endif

