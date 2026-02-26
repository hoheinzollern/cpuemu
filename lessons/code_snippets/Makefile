# Makefile for assembly code snippets
# NOTE: All .s files are Intel syntax x86-64 code
# These files are FOR STUDY on an ARM64 system (cannot run natively)
# To actually run them, use Docker with an x86-64 image or deploy on x86-64 hardware

CC = clang
CFLAGS = -g -O0 -fno-stack-protector

LESSON3_C = $(wildcard lesson3/*.c)
LESSON3_BIN_C = $(LESSON3_C:.c=)

.PHONY: all lesson1 lesson2 lesson3 clean

all: lesson3

# Only lesson3 with C code works on ARM64
lesson1:
	@echo "Lesson 1 contains x86-64 assembly - cannot compile on ARM64"
	@echo "Use Docker with x86-64 Linux to run these examples"

lesson2:
	@echo "Lesson 2 contains x86-64 assembly - cannot compile on ARM64" 
	@echo "Use Docker with x86-64 Linux to run these examples"

lesson3: $(LESSON3_BIN_C)

# Generic rule for .c files (C) - these work on ARM64
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f lesson3/04_array_normal
	rm -f lesson3/05_array_overflow
	rm -f lesson3/06_buffer_overflow_var
	rm -f lesson3/07_buffer_overflow_ret
	rm -f lesson3/*.dSYM
	find . -name "*.o" -delete

