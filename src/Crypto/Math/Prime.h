#ifndef Crypto_Math_Prime_h
#define Crypto_Math_Prime_h

// Crypto Includes
#include <Crypto/Types.h>

namespace Crypto
{
   namespace NMath
   {
      Tb8 MIsPrime( Ti64 alN );
      Tb8 MGenerateMersennePrime( Ti64 alP );
   }
}

#endif
