// Crypto Includes
#include <Crypto/Hash/Algorithm.h>

namespace Crypto
{
   namespace NHash
   {
      TcAlgorithm::TcAlgorithm( const uint8_t* kucpDigest )
      {
         this->vucpDigest = kucpDigest;
         this->vuiDigested = 0;
      }

      TcAlgorithm::TcAlgorithm( const TcAlgorithm& aorHash )
      {
         // Call assignment operator
         *this = aorHash;
      }

      TcAlgorithm::~TcAlgorithm( void )
      {
         // Nothing to destruct
      }

      TcAlgorithm& TcAlgorithm::operator=( const TcAlgorithm& aorHash )
      {
         // Prevent self-assignment
         if( this != &aorHash )
         {
            this->vuiDigested = aorHash.vuiDigested;
         }

         return( *this );
      }

      const uint8_t* TcAlgorithm::MDigest( void ) const
      {
         return( this->vucpDigest );
      }

      const uint32_t TcAlgorithm::MDigested( void ) const
      {
         return( this->vuiDigested );
      }
   }
}
