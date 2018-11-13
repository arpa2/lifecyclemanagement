# Build the ARPA2 Service Libraries twice: once shared, once static.
include_directories (.)

# Forward the CMake option to the compiler
if (DEBUG)
        add_definitions(-DDEBUG)
endif()

add_definitions(-Wall -Wextra -pedantic)

set(lifecyclemgt_SRC
        lifecycle.c lifecycle.h
)

add_library (pullback_lcmgt SHARED ${lifecyclemgt_SRC})
set_target_properties (pullback_lcmgt
	PROPERTIES OUTPUT_NAME pulleyback_lifecyclemanagement)

install (TARGETS pullback_lcmgt
	LIBRARY DESTINATION /usr/share/steamworks/pulleyback)

