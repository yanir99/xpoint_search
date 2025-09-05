# Makefile for xpoint_search C++ version
# Optimized for Mac M1 with OpenSSL support

CXX = clang++
CXXFLAGS = -std=c++20 -O3 -march=native -mtune=native -flto -DNDEBUG
CXXFLAGS += -Wall -Wextra -pthread
CXXFLAGS += -Wno-deprecated-declarations  # Suppress OpenSSL deprecation warnings

# OpenSSL paths for Homebrew on M1 Mac
OPENSSL_PREFIX = /opt/homebrew
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib
LIBS = -lssl -lcrypto

# For maximum performance on M1
CXXFLAGS += -mcpu=apple-m1 -ffast-math -funroll-loops

TARGET = xpoint_search
SOURCE = xpoint_search_fixed.cpp

.PHONY: all clean install-deps check-openssl

all: check-openssl $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS) $(LIBS)

check-openssl:
	@echo "Checking OpenSSL installation..."
	@if [ ! -d "$(OPENSSL_PREFIX)/include/openssl" ]; then \
		echo "OpenSSL not found at $(OPENSSL_PREFIX)"; \
		echo "Please run 'make install-deps' first"; \
		exit 1; \
	fi
	@echo "OpenSSL found at $(OPENSSL_PREFIX)"
	@echo "OpenSSL version: $$($(OPENSSL_PREFIX)/bin/openssl version)"

install-deps:
	@echo "Installing dependencies with Homebrew..."
	@if ! command -v brew >/dev/null 2>&1; then \
		echo "Homebrew not found. Installing Homebrew first..."; \
		/bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; \
	fi
	brew install openssl
	@echo "Dependencies installed!"
	@echo "OpenSSL version: $$($(OPENSSL_PREFIX)/bin/openssl version)"

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "Running basic test..."
	@if ./$(TARGET) 2>&1 | grep -q "Usage:"; then \
		echo "✅ Build successful! Program runs correctly."; \
	else \
		echo "❌ Build failed or program doesn't run correctly."; \
		exit 1; \
	fi

# Debug build with all warnings
debug: CXXFLAGS = -std=c++20 -O0 -g -Wall -Wextra -pthread
debug: CXXFLAGS += -I$(OPENSSL_PREFIX)/include -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: $(TARGET)

# Profile build for performance analysis
profile: CXXFLAGS += -pg -fprofile-arcs -ftest-coverage
profile: LDFLAGS += -pg
profile: $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Show system info
info:
	@echo "System Information:"
	@echo "OS: $$(uname -s) $$(uname -r)"
	@echo "Architecture: $$(uname -m)"
	@echo "Compiler: $$($(CXX) --version | head -n1)"
	@echo "CPU cores: $$(sysctl -n hw.ncpu)"
	@echo "Memory: $$(sysctl -n hw.memsize | awk '{print int($$1/1024/1024/1024) "GB"}')"
	@echo "OpenSSL: $$($(OPENSSL_PREFIX)/bin/openssl version 2>/dev/null || echo 'Not found')"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build the optimized version (default)"
	@echo "  debug        - Build debug version with sanitizers"
	@echo "  profile      - Build with profiling support"
	@echo "  install-deps - Install required dependencies"
	@echo "  check-openssl- Check OpenSSL installation"
	@echo "  test         - Test the built binary"
	@echo "  clean        - Remove built files"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  info         - Show system information"
	@echo "  help         - Show this help message"
