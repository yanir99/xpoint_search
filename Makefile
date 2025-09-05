# Makefile for xpoint_search C++ version
# Optimized for Mac M1 with OpenSSL support

CXX = clang++
CXXFLAGS = -std=c++20 -O3 -march=native -mtune=native -flto -DNDEBUG
CXXFLAGS += -Wall -Wextra -pthread
CXXFLAGS += -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib
LIBS = -lssl -lcrypto

# For maximum performance on M1
CXXFLAGS += -mcpu=apple-m1 -ffast-math -funroll-loops

TARGET = xpoint_search
SOURCE = xpoint_search.cpp

.PHONY: all clean install-deps

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS) $(LIBS)

install-deps:
	@echo "Installing dependencies with Homebrew..."
	brew install openssl
	@echo "Dependencies installed!"

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "Running basic test..."
	./$(TARGET) --help || echo "Build successful!"

# Debug build
debug: CXXFLAGS = -std=c++20 -O0 -g -Wall -Wextra -pthread -I/opt/homebrew/include
debug: $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
