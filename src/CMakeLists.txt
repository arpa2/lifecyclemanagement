# Build the ARPA2 Service Libraries twice: once shared, once static.
include_directories (.)

# Forward the CMake option to the compiler
if (DEBUG)
        add_definitions(-DDEBUG)
endif()

add_definitions(-Wall -Wextra -pedantic)

#TODO# For now, including pulleyback.h locally (which is awful)
set(lifecycle_SRC
        lifecycle.c lifecycle.h pulleyback.h
)

add_library (pulleyback_lifecycle SHARED ${lifecycle_SRC})

install (TARGETS pulleyback_lifecycle
	LIBRARY DESTINATION /usr/share/steamworks/pulleyback)

