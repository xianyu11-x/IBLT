# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


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

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/monitor/p4/bf-sde-9.9.0/p4studio

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/monitor/p4app/IBLT

# Utility rule file for IBLT_IN-tofino.

# Include the progress variables for this target.
include CMakeFiles/IBLT_IN-tofino.dir/progress.make

CMakeFiles/IBLT_IN-tofino: IBLT_IN/tofino/bf-rt.json


IBLT_IN/tofino/bf-rt.json: IBLT_IN.p4
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/monitor/p4app/IBLT/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating IBLT_IN/tofino/bf-rt.json"
	/home/monitor/p4/bf-sde-9.9.0/install/bin/bf-p4c --std p4-16 --target tofino --arch tna --bf-rt-schema IBLT_IN/tofino/bf-rt.json -o /home/monitor/p4app/IBLT/IBLT_IN/tofino -g /home/monitor/p4app/IBLT/IBLT_IN.p4
	/home/monitor/p4/bf-sde-9.9.0/install/bin/p4c-gen-bfrt-conf --name IBLT_IN --device tofino --testdir ./IBLT_IN/tofino --installdir share/tofinopd/IBLT_IN --pipe `/home/monitor/p4/bf-sde-9.9.0/install/bin/p4c-manifest-config --pipe ./IBLT_IN/tofino/manifest.json`

IBLT_IN-tofino: CMakeFiles/IBLT_IN-tofino
IBLT_IN-tofino: IBLT_IN/tofino/bf-rt.json
IBLT_IN-tofino: CMakeFiles/IBLT_IN-tofino.dir/build.make

.PHONY : IBLT_IN-tofino

# Rule to build all files generated by this target.
CMakeFiles/IBLT_IN-tofino.dir/build: IBLT_IN-tofino

.PHONY : CMakeFiles/IBLT_IN-tofino.dir/build

CMakeFiles/IBLT_IN-tofino.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/IBLT_IN-tofino.dir/cmake_clean.cmake
.PHONY : CMakeFiles/IBLT_IN-tofino.dir/clean

CMakeFiles/IBLT_IN-tofino.dir/depend:
	cd /home/monitor/p4app/IBLT && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/monitor/p4/bf-sde-9.9.0/p4studio /home/monitor/p4/bf-sde-9.9.0/p4studio /home/monitor/p4app/IBLT /home/monitor/p4app/IBLT /home/monitor/p4app/IBLT/CMakeFiles/IBLT_IN-tofino.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/IBLT_IN-tofino.dir/depend

