CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lcrypto
TARGET = cryptocore
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Source files
SOURCES = $(SRCDIR)/main.c \
          $(SRCDIR)/cli_parser.c \
          $(SRCDIR)/file_io.c \
          $(SRCDIR)/crypto_utils.c \
          $(SRCDIR)/modes/ecb.c \
          $(SRCDIR)/modes/cbc.c \
          $(SRCDIR)/modes/cfb.c \
          $(SRCDIR)/modes/ofb.c \
          $(SRCDIR)/modes/ctr.c

# Object files
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Header files
HEADERS = $(INCDIR)/crypto.h \
          $(INCDIR)/cli_parser.h \
          $(INCDIR)/file_io.h \
          $(INCDIR)/modes/ecb.h \
          $(INCDIR)/modes/cbc.h \
          $(INCDIR)/modes/cfb.h \
          $(INCDIR)/modes/ofb.h \
          $(INCDIR)/modes/ctr.h

.PHONY: all clean test install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

test: $(TARGET)
	@echo "Running tests..."
	@./test_runner.sh

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Dependencies
$(OBJDIR)/main.o: $(INCDIR)/crypto.h $(INCDIR)/cli_parser.h
$(OBJDIR)/cli_parser.o: $(INCDIR)/cli_parser.h $(INCDIR)/crypto.h
$(OBJDIR)/file_io.o: $(INCDIR)/file_io.h $(INCDIR)/crypto.h
$(OBJDIR)/modes/ecb.o: $(INCDIR)/modes/ecb.h $(INCDIR)/crypto.h
$(OBJDIR)/modes/cbc.o: $(INCDIR)/modes/cbc.h $(INCDIR)/crypto.h
$(OBJDIR)/modes/cfb.o: $(INCDIR)/modes/cfb.h $(INCDIR)/crypto.h
$(OBJDIR)/modes/ofb.o: $(INCDIR)/modes/ofb.h $(INCDIR)/crypto.h
$(OBJDIR)/modes/ctr.o: $(INCDIR)/modes/ctr.h $(INCDIR)/crypto.h
