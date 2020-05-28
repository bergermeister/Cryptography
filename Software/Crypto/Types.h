#ifndef Crypto_Types_h
#define Crypto_Types_h

namespace GNCrypto
{
   using  Tb8 =               bool; ///< Type definition for 8-bit boolean primitive 
   using  Tc8 =               char; ///< Type definition for 8-bit character primitive 
   using  Ti8 = signed        char; ///< Type definition for signed 8-bit integer primitive 
   using  Tu8 = unsigned      char; ///< Type definition for unsigned 8-bit integer primitive 
   using Ti16 = signed       short; ///< Type definition for signed 16-bit integer primitive 
   using Tu16 = unsigned     short; ///< Type definition for unsigned 16-bit integer primitive 
   using Ti32 = signed        long; ///< Type definition for signed 32-bit integer primitive 
   using Tu32 = unsigned      long; ///< Type definition for unsigned 32-bit primitive 
   using Ti64 = signed   long long; ///< Type definition for signed 64-bit integer primitive 
   using Tu64 = unsigned long long; ///< Type definition for unsigned 64-bit integer primitive 
   using Tf32 =              float; ///< Type definition for 32-bit single-precision floating point primitive 
   using Tf64 =             double; ///< Type definition for 64-bit double-precision floating point primitive 

   static const Tu32 XuiSizeOfTb8  = sizeof( Tb8 );  ///< Size of Tb8 
   static const Tu32 XuiSizeOfTi8  = sizeof( Ti8 );  ///< Size of Ti8 
   static const Tu32 XuiSizeOfTu8  = sizeof( Tu8 );  ///< Size of Tu8 
   static const Tu32 XuiSizeOfTi16 = sizeof( Ti16 ); ///< Size of Ti16
   static const Tu32 XuiSizeOfTu16 = sizeof( Tu16 ); ///< Size of Tu16
   static const Tu32 XuiSizeOfTi32 = sizeof( Ti32 ); ///< Size of Ti32
   static const Tu32 XuiSizeOfTu32 = sizeof( Tu32 ); ///< Size of Tu32
   static const Tu32 XuiSizeOfTi64 = sizeof( Ti64 ); ///< Size of Ti64
   static const Tu32 XuiSizeOfTu64 = sizeof( Tu64 ); ///< Size of Tu64
   static const Tu32 XuiSizeOfTf32 = sizeof( Tu64 ); ///< Size of Tf32
   static const Tu32 XuiSizeOfTf64 = sizeof( Tu64 ); ///< Size of Tf64

   static const Tu64 XulMask32 = 0x00000000FFFFFFFF;
   static const Tu64 XulMask16 = 0x000000000000FFFF;
   static const Tu64 XulShift32 = 32;
   static const Tu32 XuiBPB = 8; ///< Bits Per Byte

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
    * @param aoX     [in] W-bit word to be operated on
    * @param aoN     [in] Integer with 0 <= N <= W
    */
   template< class GTcType >inline GTcType MROTL( const GTcType aoX, const GTcType aoN )
   {
      return( ( aoX << aoN ) | ( aoX >> ( ( sizeof( GTcType ) * XuiBPB ) - aoN ) ) );
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
    * @param aoX     [in] W-bit word to be operated on
    * @param aoN     [in] Integer with 0 <= N <= W
    */
   template< class GTcType > inline GTcType MROTR( const GTcType aoX, const GTcType aoN )
   {
      return( ( aoX >> aoN ) | ( aoX << ( ( sizeof( GTcType ) * XuiBPB ) - aoN ) ) );
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
    * @param aoX     [in] W-bit word to be operated on
    * @param aoN     [in] Integer with 0 <= N <= W
    */
   template< class GTcType > inline GTcType MSHR( const GTcType aoX, const GTcType aoN )
   {
      return( aoX >> aoN );
   }

   /**
    * @brief
    * Choose Operation
    */
   template< class GTcType > inline GTcType MChoose( const GTcType aoX, const GTcType aoY, const GTcType aoZ )
   {
      return( ( aoX & aoY ) ^ ( ~aoX & aoZ ) );
   }

   /**
    * @brief
    * Majority Operation
    */
   template< class GTcType > inline GTcType MMajority( const GTcType aoX, const GTcType aoY, const GTcType aoZ )
   {
      return( ( aoX & aoY ) ^ ( aoX & aoZ ) ^ ( aoY & aoZ ) );
   }
}

#endif

