# Makefile for Java mock classes
# This provides simple targets for building the mock classes

.PHONY: all classes dex clean help

# Default target
all: dex

# Build only .class files (no Android tools required)
classes:
	./build_java_only.sh

# Build classes.dex (requires Android build tools)
dex:
	./build_classes.sh

# Clean build artifacts
clean:
	rm -rf build_java java_classes
	rm -f ../classes.dex

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Build classes.dex (default)"
	@echo "  dex      - Build classes.dex using Android tools"
	@echo "  classes  - Build .class files only (no Android tools required)"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Files built:"
	@echo "  classes.dex - Android dex file (built in parent directory)"
	@echo "  java_classes/ - Directory with .class files (classes target only)"

# Make build scripts executable if needed
$(shell chmod +x build_classes.sh build_java_only.sh 2>/dev/null || true)
