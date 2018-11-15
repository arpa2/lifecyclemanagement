include_directories (.)

# Forward the CMake option to the compiler
if (DEBUG)
        add_definitions(-DDEBUG)
endif()

add_definitions(-Wall -Wextra -pedantic)
include_directories(${CMAKE_SOURCE_DIR}/src)

add_executable (grammar_lcs grammar_lcs.c)
add_executable (grammar_dn  grammar_dn.c )
add_executable (new_struct  new_struct.c )
add_executable (open_close  open_close.c )
add_executable (txn_collab  txn_collab.c )
target_link_libraries (grammar_lcs pulleyback_lifecycle)
target_link_libraries (grammar_dn  pulleyback_lifecycle)
target_link_libraries (new_struct  pulleyback_lifecycle)
target_link_libraries (open_close  pulleyback_lifecycle)
target_link_libraries (txn_collab  pulleyback_lifecycle)

add_test (NAME stx-lcs-pkix-done
	COMMAND grammar_lcs
		"1pkix ."
		"0pkix . "
		"0pkix . ."
		"0pkix done@ ."
		"1pkix done@123 ."
		"1pkix . done@"
		"1pkix . done@123"
		"0pkix . done@123 ."
		"0pkix . done@123 . "
	)

add_test (NAME stx-dn-bakker-orvelte-nep
	COMMAND grammar_dn
		"1uid=bakker,dc=orvelte,dc=nep"
		"1uid=,dc=orvelte,dc=nep"
		"1uid=,dc=,dc=nep"
		"1uid=bakker,dc=,dc=nep"
		"1uid=bakker%2bkoeken,dc=orvelte,dc=nep"
		"0uid=bakker+koeken,dc=orvelte,dc=nep"
		"0uid=bakker,koeken,dc=orvelte,dc=nep"
		#TODO# "1uid=bakker koeken,dc=orvelte,dc=nep"
		"1uid=\"bakker koeken\",dc=orvelte,dc=nep"
		#TODO# "0uid=\"bakker koeken,dc=orvelte,dc=nep"
	)

add_test (NAME new-struct-lcs-lco COMMAND new_struct)

add_test (NAME open-close-three-args
	 COMMAND open_close
		"x=tee /tmp/x.out"
		"y=tee /tmp/y.out"
		"z=tee /tmp/z.out"
	)

add_test (NAME txn-collaborate
	COMMAND txn_collab
		"x=tee /tmp/x.out"
		"y=tee /tmp/y.out"
		"z=tee /tmp/z.out"
	)
