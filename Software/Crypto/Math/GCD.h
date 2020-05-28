#ifndef Crypto_Math_GCD_h
#define Crypto_Math_GCD_h

#include <Types.h>
#include <vector>

namespace GNCrypto
{
   namespace NMath
   {
      static Ti64 MGCD( Ti64 alA, Ti64 alB, Ti64& airInverse );
      static std::vector< std::pair< Ti64, Ti64 > > MMultiplicativeInverses( Ti64 alN );
      static Ti64 MMultiplicativeInverse( Ti64 alA, Ti64 alN );
   }
}

#endif

