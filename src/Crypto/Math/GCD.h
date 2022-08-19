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
      int64_t MGCD( int64_t alA, int64_t alB, int64_t& airInverse );
      int64_t MLCM( int64_t alA, int64_t alB );
      std::vector< std::pair< int64_t, int64_t > > MMultiplicativeInverses( int64_t alN );
      int64_t MMultiplicativeInverse( int64_t alA, int64_t alN );
   }
}

#endif

