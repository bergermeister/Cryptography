#include <pch.h>
#include <CppUnitTest.h>
#include <Types.h>
#include <Hash/SHA512.h>
#include <AES/Configuration.h>
#include <AES/Decryptor.h>
#include <AES/Encryptor.h>

namespace CryptoTest
{
   namespace NAES128
   {
      using namespace Microsoft::VisualStudio::CppUnitTestFramework;
      using namespace GNCrypto;
      using namespace GNCrypto::NAES128;

      TEST_CLASS( TuEncryption )
      {
      public:
         TEST_METHOD( MRijndael )
         {
            const Tu8 kucpKey[ ] =
            {
               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            };
            const Tu8 kucpPlaintext[ ] =
            {
               0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
            };            
            const Tu8 kucpCiphertext[ ] =
            {
               0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
               0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
            };
            Tu8 kucpResult[ TcConfiguration::XuiSizeKey ];

            TcConfiguration* kopCfg = new TcConfiguration( );
            TcEncryptor*     kopEnc = new TcEncryptor( *kopCfg );
            TcDecryptor*     kopDec = new TcDecryptor( *kopCfg );

            /// -# Initialize AES-128 Configuration for Rijndael
            kopCfg->MExpandKey( kucpKey );

            /// -# Perform Encryption
            kopEnc->MEncrypt( kucpPlaintext, kucpResult );

            /// -# Verify Ciphertext
            for( auto kuiIter = 0; kuiIter < TcConfiguration::XuiSizeKey; kuiIter++ )
            {
               Assert::AreEqual( kucpCiphertext[ kuiIter ], kucpResult[ kuiIter ], L"ERROR: Ciphertext Mismatch" );
            }

            /// -# Perform Decryption
            kopDec->MDecrypt( kucpCiphertext, kucpResult );
            for( auto kuiIter = 0; kuiIter < TcConfiguration::XuiSizeKey; kuiIter++ )
            {
               Assert::AreEqual( kucpPlaintext[ kuiIter ], kucpResult[ kuiIter ], L"ERROR: Plaintext Mismatch" );
            }

            /// -# Free allocated memory
            delete kopDec;
            delete kopEnc;
            delete kopCfg;
         }
      };
   }
}
