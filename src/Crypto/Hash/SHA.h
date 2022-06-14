/**
 * @file
 * This package provides the Secure Hash Algorithm base class.
 */
#ifndef Crypto_Hash_SHA_h
#define Crypto_Hash_SHA_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>

 /// Namespace containing Cryptographic functionality
namespace Crypto
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
      };
   }
}

#endif

