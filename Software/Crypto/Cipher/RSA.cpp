#include <Types.h>
#include <Cipher/Cipher.h>
#include <Cipher/RSA.h>
#include <Math/GCD.h>
#include <vector>
#include <string>

using namespace GNCrypto;
using namespace GNCrypto::NCipher;

TcRSA::TcRSA( void ) 
{

}

TcRSA::TcRSA( const TcRSA& aorCipher )
{
   *this = aorCipher;
}

TcRSA::~TcRSA( void )
{

}

TcRSA& TcRSA::operator=( const TcRSA& aorCipher )
{
   if( this != &aorCipher )
   {

   }

   return( *this );
}

void TcRSA::MInitialize( Ti64 alP, Ti64 alQ, Ti64 alI )
{
   Ti64 klY;
   std::vector< std::pair< Ti64, Ti64 > > koInverses;
   
   /// @par Process Design Language
   /// -# Compute n = pq
   this->vlN = alP * alQ;

   /// -# Compute the Carmichael's totient function of the product as Y(N)=lcm(p - 1, q - 1)
   klY = GNCrypto::NMath::MLCM( alP - 1, alQ - 1 );

   /// -# Choose any number 1 < e < klY that is coprime to 780
   koInverses = GNCrypto::NMath::MMultiplicativeInverses( klY );
   if( alI >= koInverses.size( ) )
   {
      alI = koInverses.size( ) / 2;
   }
   this->vlE = koInverses[ alI ].first;

   /// -# Compute d, the modular multiplicative inverse of e mod Y 
   this->vlD = koInverses[ 3 ].second;
}

void TcRSA::MEncrypt( const Tu8* aucpPlaintext, Tu8* aucpCiphertext, const Tu64 aulBytes )
{
   Tu64 kulRemaining = aulBytes;
   Tu64 kulBytes;
   Ti64 klWord;
   Ti64 klValue;
   Ti64 klIndex;
   const Ti64* klPlaintext  = reinterpret_cast< const Ti64* >( aucpPlaintext );
   Ti64*       klCiphertext = reinterpret_cast< Ti64* >( aucpCiphertext );

   while( kulRemaining > 0 )
   {
      kulBytes = kulRemaining;
      if( kulRemaining > sizeof( Ti64 ) )
      {
         kulBytes = sizeof( Ti64 );
      }

      klValue = 0;
      std::memcpy( reinterpret_cast< void* >( &klValue ), reinterpret_cast< const void* >( klPlaintext ), kulBytes );
      klWord = 1;
      for( klIndex = 0; klIndex < this->vlE; klIndex++ )
      {
         klWord *= klValue;
         klWord %= this->vlN;
      }
      while( klWord < 0 )
      {
         klWord += this->vlN;
      }
      std::memcpy( reinterpret_cast< void* >( klCiphertext ), reinterpret_cast< const void* >( &klWord ), kulBytes );

      kulRemaining -= sizeof( Tu64 );
      klPlaintext++;
      klCiphertext++;
   }
}

void TcRSA::MDecrypt( const Tu8* aucpCiphertext, Tu8* aucpPlaintext, const Tu64 aulBytes )
{
   Tu64 kulRemaining = aulBytes;
   Tu64 kulBytes;
   Ti64 klWord;
   Ti64 klValue;
   Ti64 klIndex;
   Ti64*       klPlaintext  = reinterpret_cast< Ti64* >( aucpPlaintext );
   const Ti64* klCiphertext = reinterpret_cast< const Ti64* >( aucpCiphertext );

   while( kulRemaining > 0 )
   {
      kulBytes = kulRemaining;
      if( kulRemaining > sizeof( Ti64 ) )
      {
         kulBytes = sizeof( Ti64 );
      }

      klValue = 0;
      std::memcpy( reinterpret_cast< void* >( &klValue ), reinterpret_cast< const void* >( klCiphertext ), kulBytes );
      klWord = 1;
      for( klIndex = 0; klIndex < this->vlD; klIndex++ )
      {
         klWord *= klValue;
         klWord %= this->vlN;
      }
      while( klWord < 0 )
      {
         klWord += this->vlN;
      }
      std::memcpy( reinterpret_cast< void* >( klPlaintext ), reinterpret_cast< const void* >( &klWord ), kulBytes );

      kulRemaining -= kulBytes;
      klPlaintext++;
      klCiphertext++;
   }
}
