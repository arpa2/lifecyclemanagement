include_directories (.)

# Forward the CMake option to the compiler
if (DEBUG)
        add_definitions(-DDEBUG)
endif()

add_definitions(-Wall -Wextra -pedantic)

set(lifecycle_SRC
        lifecycle.c lifecycle.h uthash.h
)

add_library (pulleyback_lifecycle SHARED ${lifecycle_SRC})
target_link_libraries (pulleyback_lifecycle Threads::Threads)

install (TARGETS pulleyback_lifecycle
	LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/share/steamworks/pulleyback)

