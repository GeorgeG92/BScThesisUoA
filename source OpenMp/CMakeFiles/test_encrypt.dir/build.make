# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# The program to use to edit the cache.
CMAKE_EDIT_COMMAND = /usr/bin/ccmake

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/users/std10031/Desktop/pt

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/users/std10031/Desktop/pt

# Include any dependencies generated for this target.
include CMakeFiles/test_encrypt.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test_encrypt.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_encrypt.dir/flags.make

CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o: CMakeFiles/test_encrypt.dir/flags.make
CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o: test/test_encrypt.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/users/std10031/Desktop/pt/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o   -c /home/users/std10031/Desktop/pt/test/test_encrypt.c

CMakeFiles/test_encrypt.dir/test/test_encrypt.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_encrypt.dir/test/test_encrypt.c.i"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/users/std10031/Desktop/pt/test/test_encrypt.c > CMakeFiles/test_encrypt.dir/test/test_encrypt.c.i

CMakeFiles/test_encrypt.dir/test/test_encrypt.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_encrypt.dir/test/test_encrypt.c.s"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/users/std10031/Desktop/pt/test/test_encrypt.c -o CMakeFiles/test_encrypt.dir/test/test_encrypt.c.s

CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.requires:
.PHONY : CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.requires

CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.provides: CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.requires
	$(MAKE) -f CMakeFiles/test_encrypt.dir/build.make CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.provides.build
.PHONY : CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.provides

CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.provides.build: CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o

# Object files for target test_encrypt
test_encrypt_OBJECTS = \
"CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o"

# External object files for target test_encrypt
test_encrypt_EXTERNAL_OBJECTS =

test_encrypt: CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o
test_encrypt: liboaes_lib.a
test_encrypt: CMakeFiles/test_encrypt.dir/build.make
test_encrypt: CMakeFiles/test_encrypt.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable test_encrypt"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_encrypt.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_encrypt.dir/build: test_encrypt
.PHONY : CMakeFiles/test_encrypt.dir/build

CMakeFiles/test_encrypt.dir/requires: CMakeFiles/test_encrypt.dir/test/test_encrypt.c.o.requires
.PHONY : CMakeFiles/test_encrypt.dir/requires

CMakeFiles/test_encrypt.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_encrypt.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_encrypt.dir/clean

CMakeFiles/test_encrypt.dir/depend:
	cd /home/users/std10031/Desktop/pt && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt/CMakeFiles/test_encrypt.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_encrypt.dir/depend

