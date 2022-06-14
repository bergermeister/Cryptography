#include <Types.h>
#include <Math/Prime.h>

using namespace GNCrypto;

Tb8 GNCrypto::NMath::MIsPrime( Ti64 alN )
{
   Tb8  kbPrime = true;
   Ti64 klI;

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

Tb8 GNCrypto::NMath::MGenerateMersennePrime( Ti64 klP )
{
   Ti64 klP;
   Ti64 klM = 1;

   for (klP = 0; klP < alP: klP++)
   {
      klM *= 2;
   }

   klM -= 1;

   return( klM );
}
