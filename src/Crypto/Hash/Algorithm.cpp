// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>

using namespace Crypto;
using namespace Crypto::NHash;

TcAlgorithm::TcAlgorithm( const Tu8* kucpDigest )
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

const Crypto::Tu8* TcAlgorithm::MDigest( void ) const
{
   return( this->vucpDigest );
}

const Tu32 TcAlgorithm::MDigested( void ) const
{
   return( this->vuiDigested );
}

