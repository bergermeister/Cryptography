# Dynamic AES S-Box Generation with Diffie-Hellman Exchange

## Tools
<table>
	<tr><th> Tool <th> Source
	<tr><td> MSYS2 <td>
	<tr><td> MinGW <td>
</table>

## Compilation Instructions:

### CMake
    cmake -G "Unix Makefiles" -Bbuild -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
    cmake --build build
    cd build/tst && ctest && cd ../..
    lcov --capture --directory build/src --output-file doc/coverage.info 
    genhtml doc/coverage.info --output-directory doc/coverage
    gprof build/tst/GTestCrypto.exe build/tst/gmon.out > doc/profiling.txt

### Visual Studio 
1. Open Workspace\VS2019\VS2019.sln with Visual Studio 2019 Community Edition or later
2. From the Menu bar, select Build > Rebuild Solution
3. Wait for the build to complete (2 successful builds)

## Execution Instructions:
1. From the Menu bar, select View > Test Explorer
2. In the Test Explorer window, expand:
	a. CryptoTest > CryptoTest::NCommunication > TuSession
3. Right click the desired Unit Test and select Run
	a. MVector simulates two endpoints, Alice and Bob:
		1. Establishing a secure Session
		2. Alice securely tranmits the AES-128 Plaintext test vector to Bob
		3. Bob securely receives the AES-128 Plaintext test vector
	b.	MDynamicSBox simulates two endpoints, Alice and Bob:
		1. Establishing a secure Session
		2. Alice securely tranmits a text message to Bob
		3. Bob securely receives the correct text message
	c. 	To view intermediate stages, such as the Ciphertext generated, place a breakpoint
		on the final Assert::AreEqual line of the desired Unit Test and select Debug instead
		of Run. Visual Studio will halt at the breakpoint and the watch window can be used
		to view the values of the Ciphertext, S-Box, I-Box, etc...
