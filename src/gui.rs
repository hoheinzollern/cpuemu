use std::vec;
use std::fmt;

use iced::widget::{column, row, button, pick_list, text, text_editor};
use iced::{Element, Theme, Alignment, Length, Font};

use unicorn_engine::*;
use capstone::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MyArch {
    X86,
    ARM,
}

struct State {
    architecture: Arch,
    unicorn: Unicorn<'static, ()>,
    changed_registers: Vec<u8>,
    code: text_editor::Content,
    heap: text_editor::Content,
    stack: text_editor::Content,
}

const HEXBIN_X86 : &str = "554889e5897dfc8b45fc0fafc05dc3";
const HEXBIN_ARM : &str = "ff4300d1ff0f00b9e00b00b9e80b40b9e90b40b9007d091bff430091c0035fd6";

impl Default for State {
    fn default() -> Self {
        let binary = hex::decode(HEXBIN_X86)
            .expect("Failed to decode hex string");
        let binary_len = ((binary.len() + 0xFFF) / 0x1000) * 0x1000;

        let arch = Arch::X86;
        let mode = Mode::MODE_64;

        let mut uc = Unicorn::new(arch, mode).expect("Failed to initialize Unicorn engine");

        uc.mem_map(0x2000, 0x1000, Permission::ALL).expect("Failed to map stack memory");
        uc.mem_map(0x3000, 0x1000, Permission::ALL).expect("Failed to map heap memory");
        uc.mem_map(0x1000, binary_len, Permission::ALL).expect("Failed to map binary memory");
        uc.mem_write(0x1000, &binary).expect("Failed to write binary to memory");

        match arch {
            Arch::X86 => {
                uc.reg_write(RegisterX86::RSP, 0x2000 + 0x1000).expect("Failed to set stack pointer");
                uc.reg_write(RegisterX86::RBP, 0x2000 + 0x1000).expect("Failed to set base pointer");
                uc.reg_write(RegisterX86::RIP, 0x1000).expect("Failed to set instruction pointer");
                uc.reg_write(RegisterX86::RDI, 10).unwrap();
            },
            Arch::ARM64 => {
                uc.reg_write(RegisterARM64::SP, 0x2000 + 0x1000).expect("Failed to set stack pointer");
                uc.reg_write(RegisterARM64::PC, 0x1000).expect("Failed to set instruction pointer");
                uc.reg_write(RegisterARM64::X0, 10).unwrap();
            },
            _ => panic!("Unsupported architecture"),
        }

        let code = disassemble(&uc);
        let heap = heap(&uc);
        let stack = stack(&uc);

        State {
            architecture: arch,
            unicorn: uc,
            changed_registers: vec![],
            code: text_editor::Content::with_text(&code),
            heap: text_editor::Content::with_text(&heap),
            stack: text_editor::Content::with_text(&stack),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    Execute,
    Restart,
    Step,
    Edit(text_editor::Action),
    EditHeap(text_editor::Action),
    EditStack(text_editor::Action),
    SelectArchitecture(MyArch),
}

fn reset_state(state: &mut State) {
    let bin = match state.architecture {
        Arch::X86 => HEXBIN_X86,
        Arch::ARM64 => HEXBIN_ARM,
        _ => panic!("Unsupported architecture"),
    };
    let binary = hex::decode(bin)
        .expect("Failed to decode hex string");
    let binary_len = ((binary.len() + 0xFFF) / 0x1000) * 0x1000;
    let mode = match state.architecture {
        Arch::X86 => Mode::MODE_64,
        Arch::ARM64 => Mode::ARM,
        _ => panic!("Unsupported architecture"),
    };

    state.unicorn = Unicorn::new(state.architecture, mode).expect("Failed to initialize Unicorn engine");
    state.unicorn.mem_map(0x2000, 0x1000, Permission::ALL).expect("Failed to map stack memory");
    state.unicorn.mem_map(0x3000, 0x1000, Permission::ALL).expect("Failed to map heap memory");
    state.unicorn.mem_map(0x1000, binary_len, Permission::ALL).expect("Failed to map binary memory");
    state.unicorn.mem_write(0x1000, &binary).expect("Failed to write binary to memory");

    match state.architecture {
        Arch::X86 => {
            state.unicorn.reg_write(RegisterX86::RSP, 0x2000 + 0x1000).expect("Failed to set stack pointer");
            state.unicorn.reg_write(RegisterX86::RBP, 0x2000 + 0x1000).expect("Failed to set base pointer");
            state.unicorn.reg_write(RegisterX86::RIP, 0x1000).expect("Failed to set instruction pointer");
            state.unicorn.reg_write(RegisterX86::RDI, 10).unwrap();
        },
        Arch::ARM64 => {
            state.unicorn.reg_write(RegisterARM64::SP, 0x2000 + 0x1000).expect("Failed to set stack pointer");
            state.unicorn.reg_write(RegisterARM64::PC, 0x1000).expect("Failed to set instruction pointer");
            state.unicorn.reg_write(RegisterARM64::X0, 10).unwrap();
        },
        _ => panic!("Unsupported architecture"),
    }

    let code = disassemble(&state.unicorn);
    state.code = text_editor::Content::with_text(&code);

    let heap = heap(&state.unicorn);
    state.heap = text_editor::Content::with_text(&heap);

    let stack = stack(&state.unicorn);
    state.stack = text_editor::Content::with_text(&stack);

    state.changed_registers.clear();
}

fn update(state: &mut State, message: Message) {
    match message {
        Message::Execute => {
            let pc: u8 = match state.architecture {
                Arch::X86 => RegisterX86::RIP as u8,
                Arch::ARM64 => RegisterARM64::PC as u8,
                _ => panic!("Unsupported architecture"),
            };

            let addr = state.unicorn.reg_read(pc).expect("Failed to read RIP");
            if state.unicorn.emu_start(addr, 0x1000 + 0x2D, 0, 1).is_err() {
                reset_state(state);
                return;
            }

            let code = disassemble(&state.unicorn);
            state.code = text_editor::Content::with_text(&code);

            let heap = heap(&state.unicorn);
            state.heap = text_editor::Content::with_text(&heap);

            let stack = stack(&state.unicorn);
            state.stack = text_editor::Content::with_text(&stack);
        },
        Message::Restart => {
            reset_state(state);
        },
        Message::Step => {
            let registers: Vec<u8> = match state.architecture {
                Arch::X86 => vec![
                    RegisterX86::RIP as u8,
                    RegisterX86::RBP as u8,
                    RegisterX86::RSP as u8,
                    RegisterX86::RAX as u8,
                    RegisterX86::RBX as u8,
                    RegisterX86::RCX as u8,
                    RegisterX86::RDX as u8,
                    RegisterX86::RSI as u8,
                    RegisterX86::RDI as u8,
                    RegisterX86::R8 as u8,
                    RegisterX86::R9 as u8,
                    RegisterX86::R10 as u8,
                    RegisterX86::R11 as u8,
                    RegisterX86::R12 as u8,
                    RegisterX86::R13 as u8,
                    RegisterX86::R14 as u8,
                    RegisterX86::R15 as u8,
                ],
                Arch::ARM64 => vec![
                    RegisterARM64::PC as u8,
                    RegisterARM64::SP as u8,
                    RegisterARM64::X0 as u8,
                    RegisterARM64::X1 as u8,
                    RegisterARM64::X2 as u8,
                    RegisterARM64::X3 as u8,
                    RegisterARM64::X4 as u8,
                    RegisterARM64::X5 as u8,
                    RegisterARM64::X6 as u8,
                    RegisterARM64::X7 as u8,
                    RegisterARM64::X8 as u8,
                    RegisterARM64::X9 as u8,
                    RegisterARM64::X10 as u8,
                    RegisterARM64::X11 as u8,
                    RegisterARM64::X12 as u8,
                    RegisterARM64::X13 as u8,
                    RegisterARM64::X14 as u8,
                    RegisterARM64::X15 as u8,
                    RegisterARM64::X16 as u8,

                ],
                _ => panic!("Unsupported architecture"),
            };
            state.changed_registers.clear();
            let mut register_values: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
            for &reg in &registers {
                let value = state.unicorn.reg_read(reg).expect("Failed to read register");
                register_values.insert(reg as u32, value);
            }

            let pc: u8 = match state.architecture {
                Arch::X86 => RegisterX86::RIP as u8,
                Arch::ARM64 => RegisterARM64::PC as u8,
                _ => panic!("Unsupported architecture"),
            };
            let addr = state.unicorn.reg_read(pc).expect("Failed to read PC");
            if state.unicorn.emu_start(addr, 0x1000 + 0x2D, 0, 1).is_err() {
                reset_state(state);
                return;
            }

            for &reg in &registers {
                let value = state.unicorn.reg_read(reg).expect("Failed to read register");
                if (register_values[&(reg as u32)]) != value {
                    state.changed_registers.push(reg);
                }
            }

            let code = disassemble(&state.unicorn);
            state.code = text_editor::Content::with_text(&code);

            let heap = heap(&state.unicorn);
            state.heap = text_editor::Content::with_text(&heap);

            let stack = stack(&state.unicorn);
            state.stack = text_editor::Content::with_text(&stack);
        },
        Message::Edit(action) => {
            state.code.perform(action);
        },
        Message::EditHeap(action) => {
            state.heap.perform(action);
        },
        Message::EditStack(action) => {
            state.stack.perform(action);
        },
        Message::SelectArchitecture(arch) => {
            state.architecture = myarch_to_arch(arch);

            let binary = match state.architecture {
                Arch::X86 => HEXBIN_X86,
                Arch::ARM64 => HEXBIN_ARM,
                _ => panic!("Unsupported architecture"),
            };
            let mode = match state.architecture {
                Arch::X86 => Mode::MODE_64,
                Arch::ARM64 => Mode::ARM,
                _ => panic!("Unsupported architecture"),
            };
            let binary = hex::decode(binary)
                .expect("Failed to decode hex string");
            let binary_len = ((binary.len() + 0xFFF) / 0x1000) * 0x1000;

            state.unicorn = Unicorn::new(state.architecture, mode).expect("Failed to initialize Unicorn engine");

            state.unicorn.mem_map(0x2000, 0x1000, Permission::ALL).expect("Failed to map stack memory");
            state.unicorn.mem_map(0x3000, 0x1000, Permission::ALL).expect("Failed to map heap memory");
            state.unicorn.mem_map(0x1000, binary_len, Permission::ALL).expect("Failed to map binary memory");
            state.unicorn.mem_write(0x1000, &binary).expect("Failed to write binary to memory");

            match state.architecture {
                Arch::X86 => {
                    state.unicorn.reg_write(RegisterX86::RSP, 0x2000 + 0x1000).expect("Failed to set stack pointer");
                    state.unicorn.reg_write(RegisterX86::RBP, 0x2000 + 0x1000).expect("Failed to set base pointer");
                    state.unicorn.reg_write(RegisterX86::RIP, 0x1000).expect("Failed to set instruction pointer");
                    state.unicorn.reg_write(RegisterX86::RDI, 10).unwrap();
                },
                Arch::ARM64 => {
                    state.unicorn.reg_write(RegisterARM64::SP, 0x2000 + 0x1000).expect("Failed to set stack pointer");
                    state.unicorn.reg_write(RegisterARM64::PC, 0x1000).expect("Failed to set instruction pointer");
                    state.unicorn.reg_write(RegisterARM64::X0, 10).unwrap();
                },
                _ => panic!("Unsupported architecture"),
            }

            let code = disassemble(&state.unicorn);
            state.code = text_editor::Content::with_text(&code);
            
            let heap = heap(&state.unicorn);
            state.heap = text_editor::Content::with_text(&heap);

            let stack = stack(&state.unicorn);
            state.stack = text_editor::Content::with_text(&stack);

            state.changed_registers.clear();
        },
    }
}

fn myarch_to_arch(arch: MyArch) -> Arch {
    match arch {
        MyArch::X86 => Arch::X86,
        MyArch::ARM => Arch::ARM64,
    }
}

fn disassemble(uc: &Unicorn<'static, ()>) -> String {
    match uc.get_arch() {
        Arch::X86 => disassemble_x86(uc),
        Arch::ARM64 => disassemble_arm(uc),
        _ => panic!("Unsupported architecture"),
    }
}

fn disassemble_x86(uc: &Unicorn<()>) -> String {
    let rip: u64 = uc.reg_read(RegisterX86::RIP).expect("Failed to read RIP");
    let len: usize = HEXBIN_X86.len() / 2;
    let mut buffer = vec![0u8; len];
    uc.mem_read(0x1000, &mut buffer).expect("Failed to read memory");

    let disassembler = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().expect("Failed to create Capstone disassembler");

    let instructions = disassembler.disasm_all(&buffer, 0x1000).expect("Failed to disassemble instructions");
    let mut result = String::new();
    for instruction in instructions.iter() {
        let cursor = if instruction.address() == rip { "-> " } else { "   " };
        result.push_str(&format!("{}{}\n", cursor, instruction));
    }

    result
}

fn disassemble_arm(uc: &Unicorn<()>) -> String {
    let pc: u64 = uc.reg_read(RegisterARM64::PC).expect("Failed to read PC");
    let len: usize = HEXBIN_ARM.len() / 2;
    let mut buffer = vec![0u8; len];
    uc.mem_read(0x1000, &mut buffer).expect("Failed to read memory");

    let disassembler = Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).build().expect("Failed to create Capstone disassembler");

    let instructions = disassembler.disasm_all(&buffer, 0x1000).expect("Failed to disassemble instructions");
    let mut result = String::new();
    for instruction in instructions.iter() {
        let cursor = if instruction.address() == pc { "-> " } else { "   " };
        result.push_str(&format!("{}{}\n", cursor, instruction));
    }

    result
}

fn heap(uc: &Unicorn<()>) -> String {
    format_memory(uc, 0x3000, 0x100)
}

fn stack(uc: &Unicorn<()>) -> String {
    let pc: u8 = match uc.get_arch() {
        Arch::X86 => RegisterX86::RSP as u8,
        Arch::ARM64 => RegisterARM64::SP as u8,
        _ => panic!("Unsupported architecture"),
    };
    let sp: u64 = uc.reg_read(pc).expect("Failed to read RSP");
    let up = (sp - 0x10) & !0xF;
    let heap_start: u64 = 0x3000;
    let size = if up < heap_start { (heap_start - up) as usize } else { 0x0 };
    format_memory(uc, up, size)
}

impl fmt::Display for MyArch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MyArch::X86 => write!(f, "x86"),
            MyArch::ARM => write!(f, "ARM"),
        }
    }
}

fn arch_to_myarch(arch: Arch) -> MyArch {
    match arch {
        Arch::X86 => MyArch::X86,
        Arch::ARM64 => MyArch::ARM,
        _ => panic!("Unsupported architecture"),
    }
}

fn view(state: &State) -> Element<Message> {
    column![
        row![
            text("Architecture:"),
            pick_list(
                vec![MyArch::X86, MyArch::ARM],
                Some(arch_to_myarch(state.architecture)),
                Message::SelectArchitecture,
            ),
            button(text("Execute")).on_press(Message::Execute),
            button(text("Restart")).on_press(Message::Restart),
            button(text("Step")).on_press(Message::Step),
        ].padding(10).spacing(10).align_y(Alignment::Center),
        row![
            column![
                row![text("Disassembled Code:").width(Length::Fill), button(text("Save"))]
                .spacing(10).align_y(Alignment::Center),
                text_editor::<_, Theme, _>(&state.code)
                    .on_action(Message::Edit),
            ].width(Length::Fill).spacing(10),
            column![
                row![text("Registers:").width(Length::Fill), button(text("Save"))]
                .spacing(10).align_y(Alignment::Center),
                text(format_registers(&state.unicorn)),
            ].width(Length::Fixed(250.)).spacing(10),
        ].padding(10).spacing(10),
        row![
            column![
                row![text("Heap:").width(Length::Fill), button(text("Save"))].spacing(10).align_y(Alignment::Center),
                text_editor::<_, Theme, _>(&state.heap).on_action(Message::EditHeap),
            ].width(iced::Length::FillPortion(1)).spacing(10),
            column![
                row![text("Stack:").width(Length::Fill), button(text("Save"))].spacing(10).align_y(Alignment::Center),
                text_editor::<_, Theme, _>(&state.stack).on_action(Message::EditStack),
            ].width(iced::Length::FillPortion(1)).spacing(10),
        ].padding(10).spacing(10)
    ].into()
}

fn theme(_state: &State) -> Theme {
    Theme::TokyoNight
}

fn format_registers(uc: &Unicorn<()>) -> String {
    match uc.get_arch() {
        Arch::X86 => format_registers_x86(uc),
        Arch::ARM64 => format_registers_arm(uc),
        _ => panic!("Unsupported architecture"),
    }
}

fn format_registers_x86(uc: &Unicorn<()>) -> String {
    let registers = vec![
        RegisterX86::RIP,
        RegisterX86::RBP,
        RegisterX86::RSP,
        RegisterX86::RAX,
        RegisterX86::RBX,
        RegisterX86::RCX,
        RegisterX86::RDX,
        RegisterX86::RSI,
        RegisterX86::RDI,
        RegisterX86::R8,
        RegisterX86::R9,
        RegisterX86::R10,
        RegisterX86::R11,
        RegisterX86::R12,
        RegisterX86::R13,
        RegisterX86::R14,
        RegisterX86::R15,
    ];

    let mut result = String::new();
    for reg in registers.iter() {
        let value = uc.reg_read(*reg).expect("Failed to read register");
        result.push_str(&format!("{:?}: 0x{:016x}\n", reg, value));
    }

    result
}

fn format_registers_arm(uc: &Unicorn<()>) -> String {
    let registers = vec![
        RegisterARM64::PC,
        RegisterARM64::SP,
        RegisterARM64::X0,
        RegisterARM64::X1,
        RegisterARM64::X2,
        RegisterARM64::X3,
        RegisterARM64::X4,
        RegisterARM64::X5,
        RegisterARM64::X6,
        RegisterARM64::X7,
        RegisterARM64::X8,
        RegisterARM64::X9,
        RegisterARM64::X10,
        RegisterARM64::X11,
        RegisterARM64::X12,
        RegisterARM64::X13,
        RegisterARM64::X14,
        RegisterARM64::X15,
        RegisterARM64::X16,
    ];

    let mut result = String::new();
    for reg in registers.iter() {
        let value = uc.reg_read(*reg).expect("Failed to read register");
        result.push_str(&format!("{:?}: 0x{:016x}\n", reg, value));
    }

    result
}

fn format_memory(uc: &Unicorn<()>, address: u64, size: usize) -> String {
    let mut buffer = vec![0u8; size];
    uc.mem_read(address, &mut buffer).expect("Failed to read memory");

    let mut memory = String::new();
    for (i, byte) in buffer.iter().enumerate() {
        if i % 16 == 0 {
            memory.push_str(&format!("0x{:04x}: ", address + i as u64));
        }
        memory.push_str(&format!("{:02x} ", byte));
        if i % 16 == 15 {
            memory.push_str("\n");
        }
    }
    memory
}

pub fn gui() {
    iced::application("Unicorn Engine GUI", update, view)
        .theme(theme)
        .default_font(Font::MONOSPACE)
        .window_size((800., 600.))
        .run()
        .unwrap();
}