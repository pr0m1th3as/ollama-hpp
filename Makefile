# Check if a default C++ compiler exists, otherwise use g++
CXX ?= g++
CXXFLAGS = -Wall -Wextra -Wpedantic

CREATE_BUILD_DIR = mkdir -p build; cp -n llama.jpg build;
BUILD_TESTS = $(CXX) $(CXXFLAGS) test/test.cpp -Iinclude -Itest -pthread -latomic

all: examples test-cpp11 test-cpp14 test-cpp17 test-cpp20 test-cpp23 test-cpp26
build:
	mkdir -p build
ifeq ($(OS),Windows_NT)
		if not exist "build/llama.jpg" copy "llama.jpg" "build"
else
		cp -n llama.jpg build
endif
examples: build examples/main.cpp
	$(CXX) $(CXXFLAGS) examples/main.cpp -Iinclude -o build/examples -std=c++11 -pthread -latomic
test: test-cpp11
test-cpp11: build test/test.cpp
	$(BUILD_TESTS) -o build/test -std=c++11 -pthread -latomic
test-cpp14: build test/test.cpp
	$(BUILD_TESTS) -o build/test-cpp14 -std=c++14 -pthread -latomic
test-cpp17: build test/test.cpp
	$(BUILD_TESTS) -o build/test-cpp17 -std=c++17 -pthread -latomic	
test-cpp20: build test/test.cpp
	$(BUILD_TESTS) -o build/test-cpp20 -std=c++2a -pthread -latomic
test-cpp23: build test/test.cpp
	$(BUILD_TESTS) -o build/test-cpp23 -std=c++2b -pthread -latomic
test-cpp26: build test/test.cpp
	$(BUILD_TESTS) -o build/test-cpp26 -std=c++2c -pthread -latomic		
clean:
	rm -rf build
