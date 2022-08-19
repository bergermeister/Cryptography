#ifndef Crypto_Math_GCD_h
#define Crypto_Math_GCD_h

// Crypto Includes
#include <Crypto/Types.h>

// StdLib Includes
#include <vector>

namespace Crypto
{
   namespace NMath
   {
      Ti64 MGCD( Ti64 alA, Ti64 alB, Ti64& airInverse );
      Ti64 MLCM( Ti64 alA, Ti64 alB );
      std::vector< std::pair< Ti64, Ti64 > > MMultiplicativeInverses( Ti64 alN );
      Ti64 MMultiplicativeInverse( Ti64 alA, Ti64 alN );
   }
}

#endif

