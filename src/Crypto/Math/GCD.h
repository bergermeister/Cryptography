/**
 * @file 
 */
#ifndef Crypto_Math_GCD_h
#define Crypto_Math_GCD_h

// Crypto Includes
#include <Crypto/Types.h>

// StdLib Includes
#include <vector>

namespace Crypto
{
   namespace Math
   {
      int64_t GCD( int64_t alA, int64_t alB, int64_t& airInverse );
      int64_t LCM( int64_t alA, int64_t alB );
      std::vector< std::pair< int64_t, int64_t > > MultiplicativeInverses( int64_t alN );
      int64_t MultiplicativeInverse( int64_t alA, int64_t alN );
   }
}

#endif

