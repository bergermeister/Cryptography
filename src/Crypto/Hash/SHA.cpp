// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>
#include <Crypto/Hash/SHA.h>

using namespace Crypto;
using namespace Crypto::Hash;

SHA::SHA( const uint8_t* aucpDigest ) : Algorithm( aucpDigest )
{
   // Nothing to construct
}

SHA::SHA( const SHA& aorSHA ) : Algorithm( aorSHA )
{
   // Call assignment operator
   *this = aorSHA;
}

SHA::~SHA( void )
{
   // Nothing to destruct
}

SHA& SHA::operator=( const SHA& aorSHA )
{
   // Prevent self-assignment
   if( this != &aorSHA )
   {

   }

   return( *this );
}

