/**
 * @file
 * @brief 
 * 512-Bit Secure Hash Algorithm (SHA-512) Package
 *
 * @details
 * @par
 * This package provides the 512-Bit Secure Hash Algorithm (SHA-512) class.
 */
#ifndef Crypto_Hash_SHA512_h
#define Crypto_Hash_SHA512_h

#include <Types.h>
#include <Hash/Algorithm.h>
#include <Hash/SHA.h>

 /// Namespace containing Cryptographic functionality
namespace GNCrypto
{
   /// Namespace containing Hashing algorithms
   namespace NHash
   {
      /** 
       * @brief 
       * 512-bit Secure Hashing Algorithm (SHA-512)
       *
       * @details
       * @par
       *
       */
      class TcSHA512 : public TcSHA
      {
      public:        // Public Attributes
         static const Tu32 XuiLength = 64;   ///< Length of Hash in bytes

      private:       // Private Attributes
         static const Tu32 xuiConstCnt    = 80;                            ///< 
         static const Tu32 xuiLengthBlock = 128;                           ///< Block size in bytes 
         static const Tu32 xuiLengthWords = XuiLength / sizeof( Tu64 );    ///< Length of digest in 64-bit words
         static const Tu32 xuiPadMax      = 112;
         static const Tu32 xuiPadEnd      = 123;
         static const Tu64 xulConstant[ xuiConstCnt ];                     ///< 
         static const Tu64 xulDefaultHash[ xuiLengthWords ];               ///< 

         Tu64 vulHash[ xuiLengthWords ];                                   ///< Calculated Hash 

      public:        // Public Methods
         TcSHA512( void );
         TcSHA512( const TcSHA512& aorSHA );
         ~TcSHA512( void );
         TcSHA512& operator=( const TcSHA512& aorSHA );

         void MInitialize( void );
         void MProcess( const Tu8* aucpData, const Tu32 auiLength );
         void MFinalize( void );

         using TcAlgorithm::MDigest;
         using TcAlgorithm::MDigested;

      private:       // Private Methods
         void mProcessBlock( const Tu8* aucpBlock );

         inline Tu64 mSig1( const Tu64 aulX )
         {
            return( mROTR< Tu64 >( aulX, 28 ) ^ mROTR< Tu64 >( aulX, 34 ) ^ mROTR< Tu64 >( aulX, 39 ) );
         }

         inline Tu64 mSig2( const Tu64 aulX )
         {
            return( mROTR< Tu64 >( aulX, 14 ) ^ mROTR< Tu64 >( aulX, 18 ) ^ mROTR< Tu64 >( aulX, 41 ) );
         }

         inline Tu64 mSig3( const Tu64 aulX )
         {
            return( mROTR< Tu64 >( aulX, 1 ) ^ mROTR< Tu64 >( aulX, 8 ) ^ mSHR< Tu64 >( aulX, 7 ) );
         }

         inline Tu64 mSig4( const Tu64 aulX )
         {
            return( mROTR< Tu64 >( aulX, 19 ) ^ mROTR< Tu64 >( aulX, 61 ) ^ mSHR< Tu64 >( aulX, 6 ) );
         }
      };
   }
}

#endif

