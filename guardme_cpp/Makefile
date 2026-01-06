# GuardME C++ Console Application Makefile
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I/nix/store/*/include
LDFLAGS = -lcurl -lssl -lcrypto

# Output binary
TARGET = guardme_console

# Source files
SOURCES = src/console_main.cpp

# Build directory
BUILD_DIR = build

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SOURCES)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $(BUILD_DIR)/$(TARGET)"

clean:
	rm -rf $(BUILD_DIR)

run: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET)

.PHONY: all clean run
