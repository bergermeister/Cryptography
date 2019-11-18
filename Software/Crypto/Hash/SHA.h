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
      private:       // Private Attributes
         static const Tu32 xuiBPB = 8; ///< Bits Per Byte

      public:        // Public Methods
         TcSHA( const Tu8* aucpDigest );
         TcSHA( const TcSHA& aorSHA );
         virtual ~TcSHA( void );
         TcSHA& operator=( const TcSHA& aorSHA );

         virtual void MInitialize( void ) = 0;
         virtual void MProcess( const Tu8* aucpData, const Tu32 auiBytes ) = 0;
         virtual void MFinalize( void ) = 0;

         using TcAlgorithm::MDigest;
         using TcAlgorithm::MDigested;

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
          */
         template< class GTcType >
         inline GTcType mROTL( const GTcType aoX, const GTcType aoN )
         {
            return( ( aoX << aoN ) | ( aoX >> ( ( sizeof( GTcType ) * xuiBPB ) - aoN ) ) );
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
          */
         template< class GTcType >
         inline GTcType mROTR( const GTcType aoX, const GTcType aoN )
         {
            return( ( aoX >> aoN ) | ( aoX << ( ( sizeof( GTcType ) * xuiBPB ) - aoN ) ) );
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
         template< class GTcType >
         inline GTcType mSHR( const GTcType aoX, const GTcType aoN )
         {
            return( aoX >> aoN );
         }

         /**
          * @brief
          * Choose Operation
          */
         template< class GTcType >
         inline GTcType mCh( const GTcType aoX, const GTcType aoY, const GTcType aoZ )
         {
            return( ( aoX & aoY ) ^ ( ~aoX & aoZ ) );
         }

         /**
          * @brief
          * Majority Operation
          */
         template< class GTcType >
         inline GTcType mMaj( const GTcType aoX, const GTcType aoY, const GTcType aoZ )
         {
            return( ( aoX & aoY ) ^ ( aoX & aoZ ) ^ ( aoY & aoZ ) );
         }
      };
   }
}

#endif

