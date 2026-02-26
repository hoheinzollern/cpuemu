# Code Snippets - Assembly & Debugging Examples

This directory contains runnable code examples extracted from the Cybermesterskaberne course on reverse-engineering and exploitation fundamentals. All assembly examples are designed to teach x86-64 architecture concepts.

## ⚠️ Important: Architecture Note

**Your system is ARM64 (Apple Silicon), but the assembly code is x86-64.** The x86-64 `.s` files cannot run natively on your ARM64 system. The C code examples in Lesson 3 (04-07) will compile and run fine, but the assembly files require one of these approaches:

### Option 1: Study the Assembly Code (No Execution)
- Read through all `.s` files as reference material
- Use GDB to study the disassembly patterns
- Understand the concepts without running them
- **Best for**: Learning the theory

### Option 2: Run in Docker with x86-64 Linux
```bash
docker run --rm -it ubuntu:latest
apt-get update && apt-get install -y gcc make binutils gdb
# Copy .s and .c files into container
# Run make to compile
# Use gdb to debug
```

### Option 3: Access x86-64 Hardware
- Compile on an Intel/AMD Linux system
- SSH into a remote x86-64 server
- Use cloud VMs (AWS EC2, etc.)

**The C examples in Lesson 3 work fine on ARM64:**
```bash
make lesson3        # Compiles C files for your ARM64 system
./lesson3/04_array_normal
./lesson3/05_array_overflow
./lesson3/06_buffer_overflow_var    # Interactive demo
./lesson3/07_buffer_overflow_ret    # Interactive demo
```

## Directory Structure

```
code_snippets/
├── lesson1/    - Basic x86-64 instructions (10 assembly files)
├── lesson2/    - Function calls and parameters (6 files: 5 assembly, 1 C)
├── lesson3/    - Stack frames and buffer overflows (7 files: 3 assembly, 4 C)
├── Makefile    - Build all examples
└── README.md   - This file
```

## File Formats

- **`.s` files**: Pure x86-64 assembly using AT&T syntax (native macOS format)
- **`.c` files**: C source code for higher-level demonstrations
- All files compile to standalone executables with debugging symbols

## Building

**Note:** Only C examples compile on ARM64. Assembly files are x86-64 only.

### Build only the C examples (Lesson 3):
```bash
make lesson3              # Compiles all C files in lesson3
```

### Failed assembly builds are expected:
```bash
make lesson1              # Will error - x86-64 on ARM64 system
make lesson2              # Will error - x86-64 on ARM64 system
```

### Clean build artifacts:
```bash
make clean
```

## Debugging with GDB

### Basic GDB workflow:

```bash
# Start GDB with a binary
gdb ./lesson1/01_program_compilation

# At gdb prompt:
(gdb) break _main          # Set breakpoint at _main
(gdb) run                  # Run program
(gdb) disassemble          # Show disassembly at current location
(gdb) next                 # Execute one instruction
(gdb) step                 # Step into calls
(gdb) info registers       # Show all registers
(gdb) p $rax               # Print register value
(gdb) print *(long*)($rbp - 8)  # Print memory [-8 from rbp]
(gdb) quit                 # Exit GDB
```

### Useful GDB commands:

| Command | Purpose |
|---------|---------|
| `break _main` | Set breakpoint at main |
| `run` | Start program |
| `next` / `n` | Next instruction |
| `step` / `s` | Step into calls |
| `continue` / `c` | Continue execution |
| `disassemble` | Show assembly |
| `info registers` | Show all registers |
| `p $rax` | Print register |
| `x/4gx $rsp` | Examine 4 quadwords at RSP |
| `backtrace` | Show call stack |
| `quit` / `q` | Exit |

## Lesson 1: Basic Instructions (10 files)

Demonstrates fundamental x86-64 instructions in isolated examples.

| File | Topic |
|------|-------|
| 01_program_compilation.s | Simple arithmetic (add) |
| 02_simple_snippet.s | Parameter passing (rdi, rsi) |
| 03_nop.s | No-operation instruction |
| 04_mov_registers.s | Moving between registers |
| 05_mov_memory.s | Stack memory operations |
| 06_add_sub.s | Addition instruction |
| 07_jmp.s | Unconditional jump |
| 08_cmp.s | Compare instruction |
| 09_conditional_jmp.s | Conditional jumps (jl) |
| 10_call.s | Function call and return |

**Example - Compile and debug:**
```bash
make lesson1
gdb ./lesson1/01_program_compilation
(gdb) break _main
(gdb) run
(gdb) next
(gdb) info registers
(gdb) quit
```

## Lesson 2: Functions and Parameters (6 files)

Demonstrates function calls, return values, and parameter passing.

| File | Topic |
|------|-------|
| 01_hello_world.s | String printing (calls _puts) |
| 02_push_pop_demo.s | Stack LIFO behavior |
| 03_simple_function_calls.s | Basic function calls |
| 04_nested_function_calls.s | Nested call chains (main -> foo -> bar) |
| 05_return_value_example.s | Return value in rax |
| 06_parameters_example.s | Parameter passing (rdi, rsi, rdx, rcx, r8) |

**x86-64 ABI Parameter Convention:**
- 1st param: `rdi` (or `edi` for 32-bit)
- 2nd param: `rsi` (or `esi`)
- 3rd param: `rdx` (or `edx`)
- 4th param: `rcx` (or `ecx`)
- 5th param: `r8` (or `r8d`)
- 6th param: `r9` (or `r9d`)
- Return value: `rax` (or `eax`)

**Example - Debug nested calls:**
```bash
make lesson2
gdb ./lesson2/04_nested_function_calls
(gdb) break _main
(gdb) run
(gdb) break _foo
(gdb) continue
(gdb) backtrace      # Show call stack
(gdb) info frame     # Show current frame details
(gdb) continue
```

## Lesson 3: Stack and Memory (7 files)

Demonstrates stack frames, local variables, and vulnerable buffer patterns.

| File | Topic |
|------|-------|
| 01_stack_operations.s | Push/pop with allocated stack space |
| 02_local_variables.s | Local integer variables on stack |
| 03_function_stacks.s | Multiple nested stack frames |
| 04_array_normal.c | Normal array access (bounds-safe) |
| 05_array_overflow.c | Out-of-bounds array reads |
| 06_buffer_overflow_var.c | Overflow overwrites local variable |
| 07_buffer_overflow_ret.c | Overflow overwrites return address |

**Stack Layout Example:**
```
Before function call:
    [Return address]     <- RSP
    
After prologue:
    [Old RBP]
    [Local var 1]        <- RSP (after subq)
    [Local var 2]
    ...
```

### Buffer Overflow Demonstrations

**File 06** - Overflow overwrites variable:
```c
void foo(void) {
    int secret = 0xdeadbeef;
    char buf[8];
    gets(buf);  /* Unsafe - can overflow and modify secret */
}
```

**File 07** - Overflow overwrites return address:
```c
void evil(void) {
    printf("PWNED!\n");
}

void vulnerable(void) {
    char buf[8];
    gets(buf);  /* Unsafe - can overflow and redirect to evil() */
}
```

**Example - Observe buffer overflow:**
```bash
make lesson3
gdb ./lesson3/06_buffer_overflow_var
(gdb) break foo
(gdb) run
(gdb) info frame                    # See frame layout
(gdb) x/2gx $rbp-16                 # Examine local variables
(gdb) shell python3 -c "print('A'*16)"  # Generate 16 'A's
# Copy output and paste when prompted
(gdb) quit
```

## Assembly Syntax Guide (x86-64 Intel Syntax)

All assembly files use **Intel syntax** (not AT&T):

```asm
# Register naming (no % prefix in Intel syntax)
mov rax, rbx         # Move rbx to rax

# Immediate values (no $ prefix)
mov eax, 0x1337      # Move immediate

# Memory addressing
mov rbx, [rax]       # Move from address in rax
mov rcx, [rbp - 8]   # Move from [rbp-8]
mov rdx, [rbp + 16]  # Move from [rbp+16]

# Size prefixes for Intel syntax
mov al, bl           # byte (8-bit)
mov ax, bx           # word (16-bit)
mov eax, ebx         # dword (32-bit)
mov rax, rbx         # qword (64-bit)

# Operand order: destination first, source last (Intel style)
add rbx, rax         # rbx += rax
mov rcx, [rbp]       # rcx = *rbp
```

### Syntax Declaration
All files start with `.intel_syntax noprefix` to tell the assembler to use Intel syntax without the `%` register prefix.

## macOS-Specific Details

### Global Symbols
- Entry point must be named `_main` (with underscore)
- All external/global functions must be declared: `.global _foo`
- Called functions use underscore prefix: `call _printf`

### Sections
- Code: `.section __TEXT,__text`
- String constants: `.section __TEXT,__cstring`
- Data: `.section __DATA,__data`

### String Constants
```asm
.section __TEXT,__cstring
msg:
    .asciz "Hello\n"
```

## Common GDB Debugging Patterns

### Inspect stack frames:
```
(gdb) backtrace
(gdb) frame 0           # Select frame 0
(gdb) info frame        # Details of current frame
(gdb) info locals       # Local variables
```

### Watch memory location:
```
(gdb) watch *(int*)($rbp - 4)          # Watch local variable
(gdb) x/8gx $rsp                       # Examine 8 quadwords at RSP
(gdb) x/16b $rsp                       # Examine 16 bytes (byte format)
```

### Step through function call:
```
(gdb) step              # Step into function
(gdb) next              # Skip over function
(gdb) finish            # Run until return
```

### Print register values:
```
(gdb) p $rax
(gdb) p/x $rax          # Hex format
(gdb) p $rbp - $rsp      # Compute expression
```

## Troubleshooting

### Binary won't run:
```bash
# Check if build succeeded
ls -la lesson1/01_program_compilation

# Check architecture
file lesson1/01_program_compilation

# Try running directly
./lesson1/01_program_compilation
```

### GDB symbol issues:
```bash
# Rebuild with debugging symbols
make clean
make all

# In GDB, verify symbols loaded
(gdb) info functions _main
```

### Assembly syntax errors:
- Ensure all .s files use AT&T syntax
- Register names must have `%` prefix
- Immediates must have `$` prefix
- Size suffixes: b/w/l/q on all operations

## References

- [x86-64 System V ABI](https://refspecs.linuxbase.org/elf/x86-64-abi-0.99.pdf)
- [GDB Documentation](https://sourceware.org/gdb/documentation/)
- [AT&T Assembly Syntax](https://en.wikibooks.org/wiki/X86_Assembly/GAS_Syntax)
- [macOS Mach-O Binary Format](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachORuntime/)
