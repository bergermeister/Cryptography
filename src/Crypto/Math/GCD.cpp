// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Math/GCD.h>
#include <Crypto/Math/Prime.h>

using namespace Crypto;

/**
 * This method calculates the greatest common divisor between A and B.
 *
 * @return
 * This method returns the greatest common divisor between A and B.
 *
 * @FormalParam{
 * @PRM{  in, alA        } Input A
 * @PRM{  in, alB        } Input B
 * @PRM{ out, airInverse } Inverse of greatest common divisor
 * }
 * 
 * @UserDefined{
 * @UDT{ None }
 * }
 * 
 * @LocalSymbol{
 * @LOC{ klQ  } Local Variable Q
 * @LOC{ klR  } Local Variable R
 * @LOC{ klR1 } Local Variable R1
 * @LOC{ klR2 } Local Variable R2
 * @LOC{ klS  } Local Variable S
 * @LOC{ klS1 } Local Variable S1
 * @LOC{ klS2 } Local Variable S2
 * @LOC{ klT  } Local Variable T
 * @LOC{ klT1 } Local Variable T1
 * @LOC{ klT2 } Local Variable T2
 * }
 */
int64_t Crypto::NMath::MGCD( int64_t alA, int64_t alB, int64_t& airInverse )
{
   int64_t klQ;
   int64_t klR;
   int64_t klR1;
   int64_t klR2;
   int64_t klS;
   int64_t klS1;
   int64_t klS2;
   int64_t klT;
   int64_t klT1;
   int64_t klT2;
   
   /// @par Process Design Language
   klR1 = alA;    /// -# R1 = Input A
   klR2 = alB;    /// -# R2 = Input B
   klS1 = 1;      /// -# S1 = 1
   klS2 = 0;      /// -# S2 = 0
   klT1 = 0;      /// -# T1 = 0
   klT2 = 1;      /// -# T2 = 1

   /// -# BEGIN: While R2 > 0
   while( klR2 > 0 )
   {
      klQ = klR1 / klR2;            /// -# Q = R1 / R2
      klR = klR1 - ( klQ * klR2 );  /// -# R = R1 - ( Q * R2 )
      klS = klS1 - ( klQ * klS2 );  /// -# S = S1 - ( Q * S2 )
      klT = klT1 - ( klQ * klT2 );  /// -# T = T1 - ( Q * T2 )

      klR1 = klR2;                  /// -# R1 = R2
      klR2 = klR;                   /// -# R2 = R
      klS1 = klS2;                  /// -# S1 = S2
      klS2 = klS;                   /// -# S2 = S
      klT1 = klT2;                  /// -# T1 = T2
      klT2 = klT;                   /// -# T2 = T
   }
   /// -# END: While R2 > 0

   /// -# Record T1 as Inverse
   airInverse = klT1;

   /// -# Return R1 as GCD
   return( klR1 );
}

int64_t Crypto::NMath::MLCM( int64_t alA, int64_t alB )
{
   int64_t klT;
   int64_t klD = MGCD( alA, alB, klT );
   return( ( alA * alB ) / klD );
}

std::vector< std::pair< int64_t, int64_t > > Crypto::NMath::MMultiplicativeInverses( int64_t alN )
{
   std::vector< std::pair< int64_t, int64_t > > koInverses;
   std::pair< int64_t, int64_t > koInverse;
   int64_t klA;
   int64_t klR;
   int64_t klT;

   for( klA = 1; klA < alN; klA++ )
   {
      klR = MGCD( alN, klA, klT );

      // If gcd is 1, then a has a multiplicative inverse
      if( klR == 1 )
      {
         koInverse.first = klA;
         koInverse.second = klT % alN;
         while( koInverse.second < 0 )
         {
            koInverse.second += alN;
         }
         koInverses.push_back( koInverse );
      }
   }

   return( koInverses );
}

int64_t Crypto::NMath::MMultiplicativeInverse( int64_t alA, int64_t alN )
{
   std::vector< std::pair< int64_t, int64_t > > koInverses;
   std::pair< int64_t, int64_t >* kopPair;
   int32_t kiIndex;
   int64_t klInv = 0;

   if( NMath::MIsPrime( alN ) )
   {
      // Fermat's Theorem
      // If alN is a prime and alA is an integer such that alN does not divide alA, 
      // then alA^-1 mod alN = alA^(alN-2) mod alN
      klInv = 1;
      for( kiIndex = 0; kiIndex < ( alN - 2 ); kiIndex++ )
      {
         klInv *= alA;
         klInv %= alN;
      }
   }
   else
   {
      koInverses = MMultiplicativeInverses( alN );

      for( kiIndex = 0; kiIndex < koInverses.size( ); kiIndex++ )
      {
         kopPair = &koInverses[ kiIndex ];
         if( alA == kopPair->first )
         {
            klInv = kopPair->second;
            break;
         }
         else if( alA == kopPair->second )
         {
            klInv = kopPair->first;
            break;
         }
      }
   }

   return( klInv );
}
