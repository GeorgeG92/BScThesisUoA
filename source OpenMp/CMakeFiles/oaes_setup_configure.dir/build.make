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

# Utility rule file for oaes_setup_configure.

# Include the progress variables for this target.
include CMakeFiles/oaes_setup_configure.dir/progress.make

CMakeFiles/oaes_setup_configure:
	/usr/bin/cmake -E copy_if_different /home/users/std10031/Desktop/pt/src/oaes_setup.vdproj /home/users/std10031/Desktop/pt & /usr/bin/cmake -E copy_if_different /home/users/std10031/Desktop/pt/CHANGELOG /home/users/std10031/Desktop/pt & /usr/bin/cmake -E copy_if_different /home/users/std10031/Desktop/pt/LICENSE /home/users/std10031/Desktop/pt & /usr/bin/cmake -E copy_if_different /home/users/std10031/Desktop/pt/README /home/users/std10031/Desktop/pt & /usr/bin/cmake -E copy_if_different /home/users/std10031/Desktop/pt/VERSION /home/users/std10031/Desktop/pt

oaes_setup_configure: CMakeFiles/oaes_setup_configure
oaes_setup_configure: CMakeFiles/oaes_setup_configure.dir/build.make
.PHONY : oaes_setup_configure

# Rule to build all files generated by this target.
CMakeFiles/oaes_setup_configure.dir/build: oaes_setup_configure
.PHONY : CMakeFiles/oaes_setup_configure.dir/build

CMakeFiles/oaes_setup_configure.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/oaes_setup_configure.dir/cmake_clean.cmake
.PHONY : CMakeFiles/oaes_setup_configure.dir/clean

CMakeFiles/oaes_setup_configure.dir/depend:
	cd /home/users/std10031/Desktop/pt && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt /home/users/std10031/Desktop/pt/CMakeFiles/oaes_setup_configure.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/oaes_setup_configure.dir/depend

