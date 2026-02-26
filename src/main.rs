mod gui;

use hex;
use unicorn_engine::*;
use capstone::prelude::*;
use ncurses::*;

const ADDRESS: u64 = 0x1000;
const STACK_ADDRESS: u64 = 0x2000;
const STACK_SIZE: usize = 0x1000;
const HEAP_ADDRESS: u64 = 0x3000;
const HEAP_SIZE: usize = 0x1000;

fn cli() {
    // Load the provided binary code
    let binary = hex::decode("554889e5897dfc8b45fc0fafc05dc3000000f30f1efa4883ec084883c408c3")
        .expect("Failed to decode hex string");
    let binary_len = ((binary.len() + 0xFFF) / 0x1000) * 0x1000;

    // Initialize Unicorn engine
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).expect("Failed to initialize Unicorn engine");

    // Map memory
    uc.mem_map(STACK_ADDRESS, STACK_SIZE as u64, Prot::ALL).expect("Failed to map stack memory");
    uc.mem_map(HEAP_ADDRESS, HEAP_SIZE as u64, Prot::ALL).expect("Failed to map heap memory");
    uc.mem_map(ADDRESS, binary_len as u64, Prot::ALL).expect("Failed to map binary memory");
    uc.mem_write(ADDRESS, &binary).expect("Failed to write binary to memory");

    // Set initial stack pointer
    uc.reg_write(RegisterX86::RSP, STACK_ADDRESS + STACK_SIZE as u64).expect("Failed to set stack pointer");
    // Set initial base pointer
    uc.reg_write(RegisterX86::RBP, STACK_ADDRESS + STACK_SIZE as u64).expect("Failed to set base pointer");
    // Set initial instruction pointer
    uc.reg_write(RegisterX86::RIP, ADDRESS).expect("Failed to set instruction pointer");
    uc.reg_write(RegisterX86::RDI, 10).unwrap();

    // Initialize ncurses
    initscr();
    raw();
    keypad(stdscr(), true);
    noecho();
    // Emulate step-by-step
    loop {
        // Display registers, stack, and heap
        clear();
        display_registers(&uc);
        display_instruction(&uc);
        display_memory(&uc, STACK_ADDRESS, 128, "\n\nStack");
        display_memory(&uc, HEAP_ADDRESS, 128, "\n\nHeap");
        refresh();

        // Wait for user input to step
        let ch = getch();
        if ch == 'q' as i32 {
            break;
        }

        let addr = uc.reg_read(RegisterX86::RIP).expect("Failed to read RIP");
        // Step one instruction
        uc.emu_start(addr, ADDRESS + binary.len() as u64, 0, 1).unwrap();
    }

    // End ncurses
    endwin();
}

fn display_registers(uc: &Unicorn<()>) {
    let rip: u64 = uc.reg_read(RegisterX86::RIP).expect("Failed to read RIP");
    let rsp: u64 = uc.reg_read(RegisterX86::RSP).expect("Failed to read RSP");
    let rbp: u64 = uc.reg_read(RegisterX86::RBP).expect("Failed to read RBP");
    let rax: u64 = uc.reg_read(RegisterX86::RAX).expect("Failed to read RAX");
    let rbx: u64 = uc.reg_read(RegisterX86::RBX).expect("Failed to read RBX");
    let rcx: u64 = uc.reg_read(RegisterX86::RCX).expect("Failed to read RCX");
    let rdx: u64 = uc.reg_read(RegisterX86::RDX).expect("Failed to read RDX");
    let rsi: u64 = uc.reg_read(RegisterX86::RSI).expect("Failed to read RSI");
    let rdi: u64 = uc.reg_read(RegisterX86::RDI).expect("Failed to read RDI");
    let r8: u64 = uc.reg_read(RegisterX86::R8).expect("Failed to read R8");
    let r9: u64 = uc.reg_read(RegisterX86::R9).expect("Failed to read R9");
    let r10: u64 = uc.reg_read(RegisterX86::R10).expect("Failed to read R10");
    let r11: u64 = uc.reg_read(RegisterX86::R11).expect("Failed to read R11");
    let r12: u64 = uc.reg_read(RegisterX86::R12).expect("Failed to read R12");
    let r13: u64 = uc.reg_read(RegisterX86::R13).expect("Failed to read R13");
    let r14: u64 = uc.reg_read(RegisterX86::R14).expect("Failed to read R14");
    let r15: u64 = uc.reg_read(RegisterX86::R15).expect("Failed to read R15");

    let _ = addstr(&format!("RIP: {:016x}\n", rip));
    let _ = addstr(&format!("RSP: {:016x}\n", rsp));
    let _ = addstr(&format!("RBP: {:016x}\n", rbp));
    let _ = addstr(&format!("RAX: {:016x}\n", rax));
    let _ = addstr(&format!("RBX: {:016x}\n", rbx));
    let _ = addstr(&format!("RCX: {:016x}\n", rcx));
    let _ = addstr(&format!("RDX: {:016x}\n", rdx));
    let _ = addstr(&format!("RSI: {:016x}\n", rsi));
    let _ = addstr(&format!("RDI: {:016x}\n", rdi));
    let _ = addstr(&format!("R8 : {:016x}\n", r8));
    let _ = addstr(&format!("R9 : {:016x}\n", r9));
    let _ = addstr(&format!("R10: {:016x}\n", r10));
    let _ = addstr(&format!("R11: {:016x}\n", r11));
    let _ = addstr(&format!("R12: {:016x}\n", r12));
    let _ = addstr(&format!("R13: {:016x}\n", r13));
    let _ = addstr(&format!("R14: {:016x}\n", r14));
    let _ = addstr(&format!("R15: {:016x}\n", r15));
}

fn display_memory(uc: &Unicorn<()>, address: u64, size: usize, label: &str) {
    let mut buffer = vec![0u8; size];
    uc.mem_read(address, &mut buffer).expect("Failed to read memory");

    let _ = addstr(&format!("{}:\n", label));
    for (i, byte) in buffer.iter().enumerate() {
        if i % 16 == 0 {
            let _ = addstr(&format!("\n{:08x}: ", address + i as u64));
        }
        let _ = addstr(&format!("{:02x} ", byte));
    }
    let _ = addstr("\n");
}

fn display_instruction(uc: &Unicorn<()>) {
    let rip: u64 = uc.reg_read(RegisterX86::RIP).expect("Failed to read RIP");
    let mut buffer = vec![0u8; 16];
    uc.mem_read(rip, &mut buffer).expect("Failed to read memory");

    let disassembler = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().expect("Failed to create Capstone disassembler");

    let instructions = disassembler.disasm_all(&buffer, rip).expect("Failed to disassemble instructions");
    for instruction in instructions.iter() {
        let _ = addstr(&format!("{}\n", instruction));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "cli" {
        cli();
    } else {
        gui::gui();
    }
}