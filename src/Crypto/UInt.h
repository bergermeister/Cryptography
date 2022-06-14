#ifndef Crypto_Math_Numebr_h
#define Crypto_Math_Number_h

// Crypto Includes
#include <Crypto/Types.h>

namespace Crypto
{
   template< size_t Bits > class UInt
   {
   public:     // Public Attributes
      static constexpr size_t ByteCount = ( Bits + BitsPerByte - 1 ) / BitsPerByte;
         
   private:    // Private Attributes
      uint8_t data[ ByteCount ];

   public:     // Public Methods
      Number( void ) = default;

      const uint8_t* const Bytes( void ) const
      {
         return( this->data );
      }

      Number operator+( const Number& B )
      {
         size_t byte;
         int16_t result = 0;
         Number C;

         for( byte = 0; byte < ByteCount; byte++ )
         {
            result = this->data[ byte ] + B.data[ byte ] + static_cast< int8_t >( result );
            C.data[ byte ] = static_cast< int8_t >( result );
            result = ( result >> BitsPerByte ) & 0x00FF;
         }
      }

      Number operator-( const Number& B )
      {
         size_t byte;
         int16_t result = 0;
         for( byte = 0; byte < ByteCount; byte++ )
         {

         }
      }

      Number operator*( const Number& B )
      {

      }

      Number operator*( const Number& B )
      {

      }

      Number operator%( const Number& B )
      {

      }
   };
}

#endif

