#include <Types.h>
#include <Math/Prime.h>

using namespace GNCrypto;

Tb8 GNCrypto::NMath::MIsPrime( Ti64 klN )
{
   Tb8  kbPrime = true;
   Ti64 klI;

   if( klN <= 3 )
   {
      kbPrime = ( klN > 1 );
   }
   else if( ( ( klN % 2 ) == 0 ) || ( ( klN % 3 ) == 0 ) )
   {
      kbPrime = false;
   }
   else
   {
      klI = 5;
      while( ( klI * klI ) <= klN )
      {
         if( ( ( klN % klI ) == 0 ) || ( ( klN % ( klI + 2 ) ) == 0 ) )
         {
            kbPrime = false;
         }
         klI += 6;
      }
   }

   return( kbPrime );
}