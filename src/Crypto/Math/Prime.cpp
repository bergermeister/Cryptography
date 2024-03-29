// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Math/Prime.h>

namespace Crypto
{
   namespace NMath
   {
      Tb8 MIsPrime( int64_t alN )
      {
         Tb8  kbPrime = true;
         int64_t klI;

         if( alN <= 3 )
         {
            kbPrime = ( alN > 1 );
         }
         else if( ( ( alN % 2 ) == 0 ) || ( ( alN % 3 ) == 0 ) )
         {
            kbPrime = false;
         }
         else
         {
            klI = 5;
            while( ( klI * klI ) <= alN )
            {
               if( ( ( alN % klI ) == 0 ) || ( ( alN % ( klI + 2 ) ) == 0 ) )
               {
                  kbPrime = false;
                  break;
               }
               klI += 6;
            }
         }

         return( kbPrime );
      }

      Tb8 MGenerateMersennePrime( int64_t alP )
      {
         int64_t klP;
         int64_t klM = 1;

         for( klP = 0; klP < alP; klP++ )
         {
            klM *= 2;
         }

         klM -= 1;

         return( klM );
      }
   }
}

