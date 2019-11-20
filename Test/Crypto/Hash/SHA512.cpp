#include <pch.h>
#include <CppUnitTest.h>
#include <Types.h>
#include <Hash/SHA512.h>

namespace CryptoTest
{
   using namespace Microsoft::VisualStudio::CppUnitTestFramework;
   using namespace GNCrypto;
   using namespace GNCrypto::NHash;
   namespace NHash
   {
      TEST_CLASS( TuSHA512 )
      {
      public:
         TEST_METHOD( MVector1 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0xddaf35a193617aba, 0xcc417349ae204131, 0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
               0x2192992a274fc1a8, 0x36ba3c23a3feebbd, 0x454d4423643ce80e, 0x2a9ac94fa54ca49f
            };
            const Tu8  xucpMsg[ ] = "abc";
            const Tu32 xuiBytes = 3;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            koSHA.MProcess( xucpMsg, xuiBytes );
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }

         TEST_METHOD( MVector2 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0xcf83e1357eefb8bd, 0xf1542850d66d8007, 0xd620e4050b5715dc, 0x83f4a921d36ce9ce,
               0x47d0d13c5d85f2b0, 0xff8318d2877eec2f, 0x63b931bd47417a81, 0xa538327af927da3e
            };

            const Tu8  xucpMsg[ ] = "";
            const Tu32 xuiBytes = 0;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            koSHA.MProcess( xucpMsg, xuiBytes );
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }

         TEST_METHOD( MVector3 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0x204a8fc6dda82f0a, 0x0ced7beb8e08a416, 0x57c16ef468b228a8, 0x279be331a703c335,
               0x96fd15c13b1b07f9, 0xaa1d3bea57789ca0, 0x31ad85c7a71dd703, 0x54ec631238ca3445
            };

            const Tu8  xucpMsg[ ] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            const Tu32 xuiBytes = 56;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            koSHA.MProcess( xucpMsg, xuiBytes );
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }

         TEST_METHOD( MVector4 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0x8e959b75dae313da, 0x8cf4f72814fc143f, 0x8f7779c6eb9f7fa1, 0x7299aeadb6889018, 
               0x501d289e4900f7e4, 0x331b99dec4b5433a, 0xc7d329eeb6dd2654, 0x5e96e55b874be909
            };

            const Tu8  xucpMsg[ ] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
            const Tu32 xuiBytes = 112;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            koSHA.MProcess( xucpMsg, xuiBytes );
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }

         TEST_METHOD( MVector5 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0xe718483d0ce76964, 0x4e2e42c7bc15b463, 0x8e1f98b13b204428, 0x5632a803afa973eb, 
               0xde0ff244877ea60a, 0x4cb0432ce577c31b, 0xeb009c5c2c49aa2e, 0x4eadb217ad8cc09b
            };

            const Tu8  xucpMsg[ ] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            const Tu32 xuiLen   = 128;
            const Tu32 xuiBytes = 1000000;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            Tu32        kuiRem;
            Tu32        kuiProc = 0;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            while( kuiProc < xuiBytes )
            {
               kuiRem = xuiBytes - kuiProc;
               if( kuiRem > xuiLen )
               {
                  kuiRem = xuiLen;
               }
               koSHA.MProcess( xucpMsg, kuiRem );
               kuiProc += kuiRem;
            }
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }

         TEST_METHOD( MVector6 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0xe718483d0ce76964, 0x4e2e42c7bc15b463, 0x8e1f98b13b204428, 0x5632a803afa973eb,
               0xde0ff244877ea60a, 0x4cb0432ce577c31b, 0xeb009c5c2c49aa2e, 0x4eadb217ad8cc09b
            };

            const Tu8  xucpMsg[ ] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
            const Tu32 xuiLen   = 128;
            const Tu32 xuiCount = 16777216 / 2;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            Tu32        kuiProc = 0;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            for( kuiIdx = 0; kuiIdx < xuiCount; kuiIdx++ )
            {
               koSHA.MProcess( xucpMsg, xuiLen );
            }
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }
      };
   }
}

