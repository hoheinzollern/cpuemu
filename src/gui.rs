use std::vec;
use std::fmt;
use std::collections::HashMap;

use iced::widget::{column, row, button, pick_list, text, text_editor, text_input, container, tooltip, mouse_area, Column};
use iced::{Element, Theme, Alignment, Length, Font, Color, Border};
use iced::widget::tooltip::Position;

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
    register_inputs: HashMap<u8, String>,
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

        let mut state = State {
            architecture: arch,
            unicorn: uc,
            changed_registers: vec![],
            register_inputs: HashMap::new(),
            code: text_editor::Content::with_text(&code),
            heap: text_editor::Content::with_text(&heap),
            stack: text_editor::Content::with_text(&stack),
        };

        sync_register_inputs(&mut state);
        state
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
    EditRegister { reg: u8, value: String },
    ResetRegister { reg: u8 },
    SaveRegisters,
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
    sync_register_inputs(state);
}

fn sync_register_inputs(state: &mut State) {
    state.register_inputs.clear();
    match state.architecture {
        Arch::X86 => {
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
            for reg in registers {
                let value = state.unicorn.reg_read(reg).expect("Failed to read register");
                state.register_inputs.insert(reg as u8, format!("0x{:016x}", value));
            }
        }
        Arch::ARM64 => {
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
            for reg in registers {
                let value = state.unicorn.reg_read(reg).expect("Failed to read register");
                state.register_inputs.insert(reg as u8, format!("0x{:016x}", value));
            }
        }
        _ => panic!("Unsupported architecture"),
    }
}

fn parse_register_input(input: &str) -> Option<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let has_hex_prefix = trimmed.starts_with("0x") || trimmed.starts_with("0X");
    let is_hex = has_hex_prefix || trimmed.chars().any(|ch| matches!(ch, 'a'..='f' | 'A'..='F'));
    if has_hex_prefix {
        u64::from_str_radix(trimmed.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
    } else if is_hex {
        u64::from_str_radix(trimmed, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

fn is_register_input_valid(input: &str) -> bool {
    parse_register_input(input).is_some()
}

fn has_invalid_register_inputs(state: &State) -> bool {
    state
        .register_inputs
        .values()
        .any(|value| !is_register_input_valid(value))
}

fn has_pending_register_edits(state: &State) -> bool {
    if has_invalid_register_inputs(state) {
        return false;
    }

    for (&reg, value) in state.register_inputs.iter() {
        if let Some(parsed) = parse_register_input(value) {
            let current = state.unicorn.reg_read(reg).expect("Failed to read register");
            if parsed != current {
                return true;
            }
        }
    }

    false
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
            sync_register_inputs(state);
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
            sync_register_inputs(state);
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
        Message::EditRegister { reg, value } => {
            state.register_inputs.insert(reg, value.clone());
        },
        Message::ResetRegister { reg } => {
            let value = state.unicorn.reg_read(reg).expect("Failed to read register");
            state.register_inputs.insert(reg, format!("0x{:016x}", value));
        },
        Message::SaveRegisters => {
            let mut has_invalid = false;
            for value in state.register_inputs.values() {
                if !is_register_input_valid(value) {
                    has_invalid = true;
                    break;
                }
            }
            if has_invalid {
                return;
            }

            for (&reg, value) in state.register_inputs.iter() {
                if let Some(parsed) = parse_register_input(value) {
                    state.unicorn.reg_write(reg, parsed).expect("Failed to write register");
                }
            }
            sync_register_inputs(state);
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
            sync_register_inputs(state);
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
    let can_save_registers = has_pending_register_edits(state);

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
                row![
                    text("Registers:").width(Length::Fill),
                    if can_save_registers {
                        button(text("Save")).on_press(Message::SaveRegisters)
                    } else {
                        button(text("Save"))
                    },
                ]
                .spacing(10).align_y(Alignment::Center),
                register_view(state),
            ].width(Length::Fixed(650.)).spacing(10),
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

fn register_view<'a>(state: &'a State) -> Element<'a, Message> {
    match state.unicorn.get_arch() {
        Arch::X86 => register_view_x86(&state.unicorn, &state.changed_registers, &state.register_inputs),
        Arch::ARM64 => register_view_arm(&state.unicorn, &state.changed_registers, &state.register_inputs),
        _ => panic!("Unsupported architecture"),
    }
}

fn register_view_x86<'a>(
    uc: &Unicorn<()>,
    changed_registers: &[u8],
    register_inputs: &HashMap<u8, String>,
) -> Element<'a, Message> {
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

    let mut col = Column::new().spacing(12);
    let mut pending: Option<Element<'_, Message>> = None;
    
    for reg in registers.iter() {
        let value = uc.reg_read(*reg).expect("Failed to read register");
        let is_changed = changed_registers.contains(&(*reg as u8));

        let normal_text_color = Color::from_rgb(0.78, 0.82, 0.88);
        let changed_text_color = Color::from_rgb(0.95, 0.84, 0.35);
        let text_color = if is_changed { changed_text_color } else { normal_text_color };
        let background_color = Color::from_rgb(0.13, 0.14, 0.2);
        
        let reg_name = format!("{:?}", reg);
        let reg_id = *reg as u8;
        let input_value = register_inputs
            .get(&reg_id)
            .cloned()
            .unwrap_or_else(|| format!("0x{:016x}", value));
        let is_valid = is_register_input_valid(&input_value);
        let input = text_input("", &input_value)
            .size(12)
            .width(Length::Fixed(180.0))
            .on_input(move |text| Message::EditRegister { reg: reg_id, value: text })
            .style(move |theme: &Theme, status| {
                let mut style = text_input::default(theme, status);
                style.value = text_color;
                style
            });

        let border_color = if is_valid {
            Color::from_rgb(0.3, 0.3, 0.35)
        } else {
            Color::from_rgb(0.85, 0.3, 0.3)
        };

        let base_widget = container(
            row![
                text(reg_name)
                    .size(12)
                    .color(text_color)
                    .width(Length::Fixed(100.0)),
                input,
            ]
            .spacing(15)
            .align_y(Alignment::Center)
        )
        .padding(12)
        .style(move |_theme: &Theme| {
            container::Style {
                background: Some(iced::Background::Color(background_color)),
                border: Border {
                    color: border_color,
                    width: 1.0,
                    radius: 2.0.into(),
                },
                ..Default::default()
            }
        });

        let base_element: Element<'_, Message> = if is_valid {
            base_widget.into()
        } else {
            mouse_area(base_widget)
                .on_press(Message::ResetRegister { reg: reg_id })
                .into()
        };
        
        // Add tooltip for 64-bit general purpose registers
        let reg_element: Element<'_, Message> = match reg {
            RegisterX86::RAX | RegisterX86::RBX | RegisterX86::RCX | RegisterX86::RDX |
            RegisterX86::RSI | RegisterX86::RDI | RegisterX86::RBP | RegisterX86::RSP => {
                let tooltip_content = format_x86_register_breakdown(*reg, value);
                tooltip(base_element, text(tooltip_content).size(11), Position::Right)
                    .style(|_theme: &Theme| {
                        container::Style {
                            background: Some(iced::Background::Color(Color::from_rgb(0.1, 0.1, 0.15))),
                            border: Border {
                                color: Color::from_rgb(0.4, 0.4, 0.5),
                                width: 1.0,
                                radius: 4.0.into(),
                            },
                            text_color: Some(Color::WHITE),
                            ..Default::default()
                        }
                    })
                    .into()
            },
            _ => base_element
        };
        
        let reg_cell: Element<'_, Message> = container(reg_element)
            .width(Length::FillPortion(1))
            .into();

        if let Some(left) = pending.take() {
            col = col.push(row![left, reg_cell].spacing(16));
        } else {
            pending = Some(reg_cell);
        }
    }

    if let Some(left) = pending.take() {
        let empty: Element<'_, Message> = container(text(""))
            .width(Length::FillPortion(1))
            .into();
        col = col.push(row![left, empty].spacing(16));
    }

    col.into()
}

fn register_view_arm<'a>(
    uc: &Unicorn<()>,
    changed_registers: &[u8],
    register_inputs: &HashMap<u8, String>,
) -> Element<'a, Message> {
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
    ];

    let mut col = Column::new().spacing(12);
    let mut pending: Option<Element<'_, Message>> = None;
    
    for reg in registers.iter() {
        let value = uc.reg_read(*reg).expect("Failed to read register");
        let is_changed = changed_registers.contains(&(*reg as u8));

        let normal_text_color = Color::from_rgb(0.78, 0.82, 0.88);
        let changed_text_color = Color::from_rgb(0.95, 0.84, 0.35);
        let text_color = if is_changed { changed_text_color } else { normal_text_color };
        let background_color = Color::from_rgb(0.13, 0.14, 0.2);
        
        let reg_name = format!("{:?}", reg);
        let reg_id = *reg as u8;
        let input_value = register_inputs
            .get(&reg_id)
            .cloned()
            .unwrap_or_else(|| format!("0x{:016x}", value));
        let is_valid = is_register_input_valid(&input_value);
        let input = text_input("", &input_value)
            .size(12)
            .width(Length::Fixed(180.0))
            .on_input(move |text| Message::EditRegister { reg: reg_id, value: text })
            .style(move |theme: &Theme, status| {
                let mut style = text_input::default(theme, status);
                style.value = text_color;
                style
            });

        let border_color = if is_valid {
            Color::from_rgb(0.3, 0.3, 0.35)
        } else {
            Color::from_rgb(0.85, 0.3, 0.3)
        };

        let base_widget = container(
            row![
                text(reg_name)
                    .size(12)
                    .color(text_color)
                    .width(Length::Fixed(100.0)),
                input,
            ]
            .spacing(15)
            .align_y(Alignment::Center)
        )
        .padding(12)
        .style(move |_theme: &Theme| {
            container::Style {
                background: Some(iced::Background::Color(background_color)),
                border: Border {
                    color: border_color,
                    width: 1.0,
                    radius: 2.0.into(),
                },
                ..Default::default()
            }
        });

        let base_element: Element<'_, Message> = if is_valid {
            base_widget.into()
        } else {
            mouse_area(base_widget)
                .on_press(Message::ResetRegister { reg: reg_id })
                .into()
        };
        
        // Add tooltip for X registers showing W variant
        let reg_element: Element<'_, Message> = match reg {
            RegisterARM64::X0 | RegisterARM64::X1 | RegisterARM64::X2 | RegisterARM64::X3 |
            RegisterARM64::X4 | RegisterARM64::X5 | RegisterARM64::X6 | RegisterARM64::X7 |
            RegisterARM64::X8 | RegisterARM64::X9 | RegisterARM64::X10 | RegisterARM64::X11 |
            RegisterARM64::X12 | RegisterARM64::X13 => {
                let tooltip_content = format_arm_register_breakdown(*reg, value);
                tooltip(base_element, text(tooltip_content).size(11), Position::Right)
                    .style(|_theme: &Theme| {
                        container::Style {
                            background: Some(iced::Background::Color(Color::from_rgb(0.1, 0.1, 0.15))),
                            border: Border {
                                color: Color::from_rgb(0.4, 0.4, 0.5),
                                width: 1.0,
                                radius: 4.0.into(),
                            },
                            text_color: Some(Color::WHITE),
                            ..Default::default()
                        }
                    })
                    .into()
            },
            _ => base_element
        };
        
        let reg_cell: Element<'_, Message> = container(reg_element)
            .width(Length::FillPortion(1))
            .into();

        if let Some(left) = pending.take() {
            col = col.push(row![left, reg_cell].spacing(12));
        } else {
            pending = Some(reg_cell);
        }
    }

    if let Some(left) = pending.take() {
        let empty: Element<'_, Message> = container(text(""))
            .width(Length::FillPortion(1))
            .into();
        col = col.push(row![left, empty].spacing(12));
    }

    col.into()
}

fn format_x86_register_breakdown(reg: RegisterX86, value: u64) -> String {
    let reg_name = format!("{:?}", reg);
    
    // Extract sub-registers for general purpose registers
    match reg {
        RegisterX86::RAX | RegisterX86::RBX | RegisterX86::RCX | RegisterX86::RDX => {
            let prefix = &reg_name[1..2]; // Get A, B, C, or D
            let exx = value as u32;
            let xx = (value & 0xFFFF) as u16;
            let xl = (value & 0xFF) as u8;
            let xh = ((value >> 8) & 0xFF) as u8;
            
            format!(
                "{}: 0x{:016x}\nE{}: 0x{:08x}\n{}: 0x{:04x}\n{}L: 0x{:02x}\n{}H: 0x{:02x}",
                reg_name, value,
                prefix, exx,
                prefix, xx,
                prefix, xl,
                prefix, xh
            )
        },
        RegisterX86::RSI | RegisterX86::RDI | RegisterX86::RBP | RegisterX86::RSP => {
            let prefix = &reg_name[1..]; // Get SI, DI, BP, SP
            let exx = value as u32;
            let xx = (value & 0xFFFF) as u16;
            
            format!(
                "{}: 0x{:016x}\nE{}: 0x{:08x}\n{}: 0x{:04x}",
                reg_name, value,
                prefix, exx,
                prefix, xx
            )
        },
        _ => format!("{}: 0x{:016x}", reg_name, value)
    }
}

fn format_arm_register_breakdown(reg: RegisterARM64, value: u64) -> String {
    let reg_name = format!("{:?}", reg);
    
    // Show W register (lower 32 bits) for X registers
    if reg_name.starts_with("X") {
        let w_val = value as u32;
        let w_name = reg_name.replace("X", "W");
        
        format!(
            "{}: 0x{:016x}\n{}: 0x{:08x}",
            reg_name, value,
            w_name, w_val
        )
    } else {
        format!("{}: 0x{:016x}", reg_name, value)
    }
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