#include <pch.h>


namespace CryptoTest
{
   namespace NCommunication
   {
      using namespace Microsoft::VisualStudio::CppUnitTestFramework;
      using namespace GNCrypto;

      TEST_CLASS( TuRSA )
      {
      public:
         TEST_METHOD( MVector )
         {
            const Ti64 xlPlaintext[ 7 ] = { 65, 3232, 1, 2314, 7919, 6691, 7919 * 6691 };
            Ti64       klCiphertext[ 7 ];
            Ti64       klPlaintext[ 7 ];

            GNCrypto::NCipher::TcCipher* kopCipher = new GNCrypto::NCipher::TcRSA( );
            GNCrypto::NCipher::TcRSA*    kopRSA = static_cast< GNCrypto::NCipher::TcRSA* >( kopCipher );           

            /// -# Choose two distinct prime numbers
            //kopRSA->MInitialize( 7919, 6691, 15 );
            kopRSA->MInitialize( 61, 53, 3 );

            /// -# Encryption funcition c(m)=m^e mod n
            kopCipher->MEncrypt( ( const Tu8* )&xlPlaintext, ( Tu8* )&klCiphertext, 8 * 7 );

            /// -# Deryption function m(c)=c^kiD mod n
            kopCipher->MDecrypt( ( const Tu8* )&klCiphertext, ( Tu8* )&klPlaintext, 8 * 7 );

            delete kopCipher;
         }
      };
   }
}