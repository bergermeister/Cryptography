/**
 * @file
 * This package provides the 512-Bit Secure Hash Algorithm (SHA-512) class.
 */
#ifndef Crypto_Hash_SHA512_h
#define Crypto_Hash_SHA512_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>
#include <Crypto/Hash/SHA.h>

 /// Namespace containing Cryptographic functionality
namespace Crypto
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
         static const size_t XuiLength = 64;   ///< Length of Hash in bytes

      private:       // Private Attributes
         static const uint32_t xuiConstCnt    = 80;                            ///< 
         static const uint32_t xuiLengthBlock = 128;                           ///< Block size in bytes 
         static const uint32_t xuiLengthWords = XuiLength / sizeof( uint64_t );    ///< Length of digest in 64-bit words
         static const uint32_t xuiPadMax      = 112;
         static const uint32_t xuiPadEnd      = 123;
         static const uint64_t xulConstant[ xuiConstCnt ];                     ///< 
         static const uint64_t xulDefaultHash[ xuiLengthWords ];               ///< 

         uint64_t vulHash[ xuiLengthWords ];                                   ///< Calculated Hash 

      public:        // Public Methods
         TcSHA512( void );
         TcSHA512( const TcSHA512& aorSHA );
         ~TcSHA512( void );
         TcSHA512& operator=( const TcSHA512& aorSHA );

         void MInitialize( void );
         void MProcess( const uint8_t* aucpData, const size_t auiLength );
         void MFinalize( void );

         using TcAlgorithm::MDigest;
         using TcAlgorithm::MDigested;

      private:       // Private Methods
         void mProcessBlock( const uint8_t* aucpBlock );

         inline uint64_t mSig1( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 28 ) ^ ROTR< uint64_t >( aulX, 34 ) ^ ROTR< uint64_t >( aulX, 39 ) );
         }

         inline uint64_t mSig2( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 14 ) ^ ROTR< uint64_t >( aulX, 18 ) ^ ROTR< uint64_t >( aulX, 41 ) );
         }

         inline uint64_t mSig3( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 1 ) ^ ROTR< uint64_t >( aulX, 8 ) ^ SHR< uint64_t >( aulX, 7 ) );
         }

         inline uint64_t mSig4( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 19 ) ^ ROTR< uint64_t >( aulX, 61 ) ^ SHR< uint64_t >( aulX, 6 ) );
         }
      };
   }
}

#endif

