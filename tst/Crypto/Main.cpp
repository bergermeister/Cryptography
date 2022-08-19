// Googletest Include
#include <gtest/gtest.h>

int main( int argc, char** argv )
{
   int status = 0;

   testing::InitGoogleTest( &argc, argv );
   status = RUN_ALL_TESTS( );

   return( status );
}

