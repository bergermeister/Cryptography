// UnitTest Framework Includes
#include <Crypto/pch.h>
#include <CppUnitTest.h>

// StdLib Includes
#include <stdint.h>
#include <vector>
#include <Crypto/Math/galois.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

namespace CryptoTest
{
	TEST_CLASS( CryptoTest )
	{
	public:
		
		TEST_METHOD( TestMethod1 )
		{
         uint8_t p = 1;
         uint8_t q = 1;
         uint8_t s;

         uint8_t inv = galois_inverse( 2, 8 );

         std::vector< uint8_t > v( 256, 0 );

         v[ 0 ] = 0;
         v[ 1 ] = 1;

         for( auto i = 2; i < 256; i++ )
         {
            v[ i ] = ( -( 256 / i ) * v[ 256 % i ] ) % 256 + 256;
         }

         do
         {
            p = p ^ ( p << 1 ) ^ ( p & 0x80 ? 0x1B : 0 );
            inv = galois_inverse( p, 8 );

            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            q ^= ( q & 0x80 ) ? 0x09 : 0;

            s = q ^ ROTL8( q, 1 ) ^ ROTL8( q, 2 ) ^ ROTL8( q, 3 ) ^ ROTL8( q, 4 ) ^ 0x63;

         } while( p != 1 );
		}
	};
}
