#ifndef Crypto_Math_Prime_h
#define Crypto_Math_Prime_h

// Crypto Includes
#include <Crypto/Types.h>

namespace Crypto
{
   namespace NMath
   {
      bool MIsPrime( int64_t alN );
      bool MGenerateMersennePrime( int64_t alP );
   }
}

#endif
