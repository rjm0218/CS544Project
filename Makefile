.PHONY: all clean build

# Define the output directories
BINDIR := bin
SRCDIR := cmd/echo

# Define the Go build command
GOCMD := go build

# Define the binary
BINARY := $(BINDIR)/echo

all: build

build: $(BINARY)

$(BINARY): $(SRCDIR)/echo.go
	@echo "Building binary..."
	$(GOCMD) -o $(BINARY) $(SRCDIR)/echo.go

clean:
	@echo "Cleaning up..."
	rm -rf $(BINDIR)