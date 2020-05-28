#include <Types.h>
#include <Math/GCD.h>
#include <vector>

using namespace GNCrypto;

Ti64 GNCrypto::NMath::MGCD( Ti64 alA, Ti64 alB, Ti64& airInverse )
{
   Ti64 klQ;
   Ti64 klR;
   Ti64 klR1 = alA;
   Ti64 klR2 = alB;
   Ti64 klS;
   Ti64 klS1 = 1;
   Ti64 klS2 = 0;
   Ti64 klT;
   Ti64 klT1 = 0;
   Ti64 klT2 = 1;
   
   while( klR2 > 0 )
   {
      klQ = klR1 / klR2;
      klR = klR1 - ( klQ * klR2 );
      klS = klS1 - ( klQ * klS2 );
      klT = klT1 - ( klQ * klT2 );

      klR1 = klR2;
      klR2 = klR;
      klS1 = klS2;
      klS2 = klS;
      klT1 = klT2;
      klT2 = klT;
   }

   airInverse = klT1;

   return( klR1 );
}

Ti64 GNCrypto::NMath::MLCM( Ti64 alA, Ti64 alB )
{
   Ti64 klT;
   Ti64 klD = MGCD( alA, alB, klT );
   return( ( alA * alB ) / klD );
}

std::vector< std::pair< Ti64, Ti64 > > GNCrypto::NMath::MMultiplicativeInverses( Ti64 alN )
{
   std::vector< std::pair< Ti64, Ti64 > > koInverses;
   std::pair< Ti64, Ti64 > koInverse;
   Ti64 klA;
   Ti64 klR;
   Ti64 klT;

   for( klA = 1; klA < alN; klA++ )
   {
      klR = MGCD( alN, klA, klT );

      // If gcd is 1, then a has a multiplicative inverse
      if( klR == 1 )
      {
         koInverse.first = klR;
         koInverse.second = klT % alN;
         koInverses.push_back( koInverse );
      }
   }

   return( koInverses );
}

Ti64 GNCrypto::NMath::MMultiplicativeInverse( Ti64 alA, Ti64 alN )
{
   std::vector< std::pair< Ti64, Ti64 > > koInverses = MMultiplicativeInverses( alN );
   std::pair< Ti64, Ti64 >* kopPair;
   Ti32 kiIndex;
   Ti64 kiInv = 0;

   for( kiIndex = 0; kiIndex < koInverses.size( ); kiIndex++ )
   {
      kopPair = &koInverses[ kiIndex ];
      if( alA == kopPair->first )
      {
         kiInv = kopPair->second;
         break;
      }
      else if( alA == kopPair->second )
      {
         kiInv = kopPair->first;
         break;
      }
   }

   return( kiInv );
}
