// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>
#include <Crypto/Hash/SHA.h>

using namespace Crypto;
using namespace Crypto::NHash;

TcSHA::TcSHA( const Tu8* aucpDigest ) : TcAlgorithm( aucpDigest )
{
   // Nothing to construct
}

TcSHA::TcSHA( const TcSHA& aorSHA ) : TcAlgorithm( aorSHA )
{
   // Call assignment operator
   *this = aorSHA;
}

TcSHA::~TcSHA( void )
{
   // Nothing to destruct
}

TcSHA& TcSHA::operator=( const TcSHA& aorSHA )
{
   // Prevent self-assignment
   if( this != &aorSHA )
   {

   }

   return( *this );
}

