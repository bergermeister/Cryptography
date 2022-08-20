// Crypto Includes
#include <Crypto/Hash/Algorithm.h>

namespace Crypto
{
   namespace Hash
   {
      Algorithm::Algorithm( const uint8_t* kucpDigest )
      {
         this->digest = kucpDigest;
         this->bytesDigested = 0;
      }

      Algorithm::Algorithm( const Algorithm& aorHash )
      {
         // Call assignment operator
         *this = aorHash;
      }

      Algorithm::~Algorithm( void )
      {
         // Nothing to destruct
      }

      Algorithm& Algorithm::operator=( const Algorithm& aorHash )
      {
         // Prevent self-assignment
         if( this != &aorHash )
         {
            this->bytesDigested = aorHash.bytesDigested;
         }

         return( *this );
      }

      const uint8_t* Algorithm::Digest( void ) const
      {
         return( this->digest );
      }

      const size_t Algorithm::BytesDigested( void ) const
      {
         return( this->bytesDigested );
      }
   }
}
