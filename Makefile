# Makefile

SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/main.exe
SRC = $(SRC_DIR)/main.cpp

CXX = g++
CXXFLAGS = -Wall -O2

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -rf $(BUILD_DIR)
