cmake_minimum_required( VERSION 3.10 )									# CMake Version
get_filename_component( DirSrc "../../../Software/Crypto/" ABSOLUTE )	# Source Directory: ABSOLUTE Path
project( Crypto VERSION 0.0.0.1 DESCRIPTION "Crypto Description" )		# Project Name and Version
set( Sources
	${DirSrc}/Hash/Algorithm.cpp
	${DirSrc}/Hash/SHA.cpp
	${DirSrc}/Hash/SHA512.cpp
	${DirSrc}/AES/Configuration.cpp
	${DirSrc}/AES/Decryptor.cpp
	${DirSrc}/AES/Encryptor.cpp
	${DirSrc}/Communication/Session.cpp
	${DirSrc}/Communication/Messages/EstablishSession.cpp
	${DirSrc}/Communication/Messages/Message.cpp
	${DirSrc}/KeyExchange/DiffieHellman.cpp
	${DirSrc}/KeyExchange/PublicKey.cpp )
set( Includes
	${DirSrc}/Hash/Algorithm.h
	${DirSrc}/Hash/SHA.h
	${DirSrc}/Hash/SHA512.h
	${DirSrc}/AES/Configuration.h
	${DirSrc}/AES/Decryptor.h
	${DirSrc}/AES/Encryptor.h
	${DirSrc}/Communication/Session.h
	${DirSrc}/Communication/Messages/EstablishSession.h
	${DirSrc}/Communication/Messages/Message.h
	${DirSrc}/KeyExchange/DiffieHellman.h
	${DirSrc}/KeyExchange/PublicKey.h
	${DirSrc}/Types.h )
add_library( Crypto STATIC ${Sources} ${Includes} )		# Create the Library
set_target_properties( Crypto PROPERTIES 
	VERSION ${PROJECT_VERSION} 
	SOVERSION 1
	PUBLIC_HEADER ${DirSrc}/Types.h ) 
configure_file( Crypto.pc.in Crypto.pc @ONLY )
target_include_directories( Crypto PRIVATE ${DirSrc} )
install( TARGETS Crypto
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} )
#install( FILES ${CMAKE_BINARY_DIR}/Crypto.pc
#	DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
