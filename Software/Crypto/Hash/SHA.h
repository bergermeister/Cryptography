/**
 * @file
 * @brief
 * Generic Secure Hash Algorithm Package
 *
 * @details
 * @par
 * This package provides the Secure Hash Algorithm base class.
 */
#ifndef Crypto_Hash_SHA_h
#define Crypto_Hash_SHA_h

#include <Types.h>
#include <Hash/Algorithm.h>

 /// Namespace containing Cryptographic functionality
namespace GNCrypto
{
   /// Namespace containing Hashing algorithms
   namespace NHash
   {
      /** 
       * @brief 
       * Secure Hash Algorithm (SHA) Base Class
       *
       * @details
       * @par
       * 
       */

      class TcSHA : public TcAlgorithm
      {
      public:        // Public Methods
         TcSHA( const Tu8* aucpDigest );
         TcSHA( const TcSHA& aorSHA );
         virtual ~TcSHA( void );
         TcSHA& operator=( const TcSHA& aorSHA );

         virtual void MInitialize( void ) = 0;
         virtual void MProcess( const Tu8* aucpData, const Tu32 auiBytes ) = 0;
         virtual void MFinalize( void ) = 0;

         using TcAlgorithm::MDigest;

      protected:     // Protected Methods
         /**
          * @brief 
          * Rotate Left Operation
          *
          * @details
          * @par
          * This method performs the Rotate left (circular left shift) operation, where x is a w-bit word and n is an integer 
          * with 0 <= n < w, is defined by ROTL( x, n, w )=( x << n ) | ( x >> ( w - n ) ).
          *
          * @return 
          * This method returns the 64-bit word rotated left.
          *
          * @param aulrX   [in] W-bit word to be operated on
          * @param aulrN   [in] Integer with 0 <= N <= W 
          * @param aulrW   [in] Size of a word in bits 
          */
         inline Tu64 mROTL( const Tu64& aulrX, const Tu64& aulrN, const Tu64& aulrW )
         {
            return( ( aulrX << aulrN ) | ( aulrX >> ( aulrW - aulrN ) ) );
         }

         /**
          * @brief 
          * Rotate Right Operation
          *
          * @details
          * @par
          * This method performs the Rotate right (circular right shift) operation, where x is a w-bit word and n is an integer
          * with 0 <= n < w, is defined by ROTR( x, n, w )=( x >> n ) | ( x << ( w - n ) ).
          *
          * @return  
          * This method returns the 64-bit word rotated right.
          *
          * @param aulrX   [in] W-bit word to be operated on
          * @param aulrN   [in] Integer with 0 <= N <= W
          * @param aulrW   [in] Size of a word in bits
          */
         inline Tu64 mROTR( const Tu64 aulX, const Tu64 aulN, const Tu64 aulW )
         {
            return( ( aulX >> aulN ) | ( aulX << ( aulW - aulN ) ) );
         }

         /**
          * @brief 
          * Right Shift Operation
          *
          * @details
          * @par
          * This method performs the Rotate shift operation, where x is a w-bit word and n is an integer with 0 <= n < w, is
          * defined by ( x, n )=( x >> n ).
          *
          * @return  
          * This method returns the 64-bit word rotated left.
          *
          * @param aulrX   [in] W-bit word to be operated on 
          * @param aulrN   [in] Integer with 0 <= N <= W 
          */
         inline Tu64 mSHR( const Tu64& aulrX, const Tu64& aulrN )
         {
            return( aulrX >> aulrN );
         }

         /**
          * @brief
          * Choose Operation
          */
         inline Tu64 mCh( const Tu64& aulrX, const Tu64& aulrY, const Tu64& aulrZ )
         {
            return( ( aulrX & aulrY ) ^ ( ~aulrX & aulrZ ) );
         }

         /**
          * @brief
          * Majority Operation
          */
         inline Tu64 mMaj( const Tu64& aulrX, const Tu64& aulrY, const Tu64& aulrZ )
         {
            return( ( aulrX & aulrY ) ^ ( aulrX & aulrZ ) ^ ( aulrY & aulrZ ) );
         }
      };
   }
}

#endif

