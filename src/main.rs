use bytes::{Buf, BufMut};

#[derive(Clone, Debug)]
enum VMMachineSpec {
    RV32,
}

#[derive(Clone, Debug)]
struct VMConfig {
    machine: VMMachineSpec,
    memory_mb: usize,
    bios_path: String,
    kernel_path: String,
    drive: String,
}

#[derive(Clone, Debug)]
struct TLBEntry {
    //TODO
}

#[derive(Clone, Debug)]
struct RV32CPU {
    mem: VMMemory,
    pc: u32,
    regs: [u32; 32],

    mhartid: u32,
    mtvec: u32,
    mscratch: u32,
    misa: u32,
}

impl RV32CPU {
    fn new() -> Self {
        Self {
            mem: VMMemory::new(),
            pc: 0x1000,
            regs: [0u32; 32],
            mhartid: 0,
            mtvec: 0,
            mscratch: 0,
            misa: (1<<18) | // S
                (1<<20) |   // U
                (1<<8) |    // I
                (1<<12) |   // M
                (1<<0) |    // A
                (1<<2), // C
        }
    }

    fn read_csr(&self, csr: u32) -> u32 {
        match csr {
            0xf14 => self.mhartid,
            0x301 => self.misa,
            0x305 => self.mtvec,
            0x340 => self.mscratch,
            _ => unimplemented!("unimplemented csr read value {csr:#x}"),
        }
    }

    fn write_csr(&mut self, csr: u32, val: u32) {
        match csr {
            0x305 => {
                self.mtvec = val & !3;
            }
            0x340 => {
                self.mscratch = val;
            }
            _ => unimplemented!("unimplemented csr write value {csr:#x}"),
        }
    }

    fn write_u32(&mut self, addr: u32, val: u32) {
        println!("writing {:#010x} at {:#010x}", val, addr);
    }

    fn run(&mut self) {
        //TODO: check interrupts
        //TODO: TLB (this probably needs a caching system, reading from memory
        // would need to search the ranges and then the tlb to translate an addr)

        let insn = self.mem.read_ins(self.pc as usize);
        println!("executing {:#010x}: {:#010x}", self.pc, insn);

        let opcode = insn & 0x7f;
        let rd = (insn >> 7) & 0x1f;
        let rs1 = (insn >> 15) & 0x1f;
        let rs2 = (insn >> 20) & 0x1f;

        match insn & 3 {
            0b00 => {
                unimplemented!("compact quadrant 0");
            }
            0b01 => {
                let funct3 = (insn >> 13) & 7;

                match funct3 {
                    0 => {
                        if rd != 0 {
                            let imm = ((insn >> 7) & 0x20) | ((insn >> 2) & 0x1f);
                            self.regs[rd as usize] += imm;
                            self.pc += 2;
                        }
                    }
                    _ => unimplemented!("compact1 function {}", funct3),
                }
            }
            0b10 => {
                let funct3 = (insn >> 13) & 7;
                let rs2 = (insn >> 2) & 0x1f;

                match funct3 {
                    4 => {
                        if ((insn >> 12) & 1) == 0 {
                            if rs2 == 0 {
                                if rd == 0 {
                                    panic!("illegal instruction");
                                }

                                self.pc = self.regs[rd as usize] & !1;
                            } else {
                                if rd != 0 {
                                    self.regs[rd as usize] = self.regs[rs2 as usize];
                                }

                                self.pc += 2;
                            }
                        } else {
                            todo!();
                        }
                    }
                    6 => {
                        // c.swsp
                        let imm = ((insn >> 5) & 0x3c) |
                            ((insn >> 1) & 0xc0);
                        let addr = self.regs[2] + imm;
                        self.write_u32(addr, self.regs[rs2 as usize]);

                        self.pc += 2;
                    }
                    _ => unimplemented!("compact2 function {}", funct3),
                }
            }
            0b11 => {
                match opcode {
                    0x17 => {
                        // auipc
                        if rd != 0 {
                            self.regs[rd as usize] = self.pc + (insn & 0xfffff000);
                        }
                        self.pc += 4;
                    }
                    0x13 => {
                        // addi...

                        let funct3 = (insn >> 12) & 7;
                        let imm = insn >> 20;
                        let val;

                        match funct3 {
                            // addi
                            0 => {
                                val = self.regs[rs1 as usize] + imm;
                            }
                            1 => {
                                val = self.regs[rs1 as usize] << imm;
                            }
                            _ => {
                                panic!("Unknown function {}, core: {:x?}", funct3, self)
                            }
                        }

                        if rd != 0 {
                            self.regs[rd as usize] = val;
                        }
                        self.pc += 4;
                    }
                    0x73 => {
                        // csrr

                        let funct3 = (insn >> 12) & 7;
                        let imm = insn >> 20;
                        let mut val;

                        if funct3 & 4 > 0 {
                            val = rs1;
                        } else {
                            val = self.regs[rs1 as usize];
                        }

                        match funct3 & 3 {
                            1 => {
                                let val2 = self.read_csr(imm);
                                self.write_csr(imm, val);

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }
                            }
                            2 => {
                                let val2 = self.read_csr(imm);
                                if rs1 != 0 {
                                    val = val2 | val;
                                    self.write_csr(imm, val);
                                }

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }
                            }
                            _ => {
                                panic!("Unknown csr function {}, core: {:x?}", funct3, self)
                            }
                        }

                        self.pc += 4;
                    }
                    0x67 => {
                        let imm = insn >> 20;
                        let val = self.pc + 4;
                        self.pc = self.regs[rs1 as usize] + imm;

                        if rd != 0 {
                            self.regs[rd as usize] = val;
                        }
                    }
                    0x6f => {
                        let imm = ((insn >> (31 - 20)) & (1 << 20))
                            | ((insn >> (21 - 1)) & 0x7fe)
                            | ((insn >> (20 - 11)) & (1 << 11))
                            | (insn & 0xff000);

                        if rd != 0 {
                            self.regs[rd as usize] = self.pc + 4;
                        }
                        self.pc += imm;
                    }
                    0x63 => {
                        // branching

                        let funct3 = (insn >> 12) & 7;
                        let cond;

                        match funct3 >> 1 {
                            0 => {
                                // beq, bne
                                cond = self.regs[rs1 as usize] == self.regs[rs2 as usize];
                            }
                            2 => {
                                // blt, bge
                                cond = self.regs[rs1 as usize] < self.regs[rs2 as usize];
                            }
                            _ => {
                                unimplemented!("branch {:#x}", funct3 >> 1)
                            }
                        }

                        if cond ^ (funct3 & 1 > 0) {
                            let imm = ((insn >> (31 - 12)) & (1 << 12))
                                | ((insn >> (25 - 5)) & 0x7e0)
                                | ((insn >> (8 - 1)) & 0x1e)
                                | ((insn << (11 - 7)) & (1 << 11));
                            self.pc += imm;
                        } else {
                            self.pc += 4;
                        }
                    }
                    0x33 => {
                        let imm = insn >> 25;
                        let mut val = self.regs[rs1 as usize];
                        let val2 = self.regs[rs2 as usize];

                        if imm == 1 {
                            unimplemented!();
                        } else {
                            if (imm & !0x20) != 0 {
                                panic!("illegal instruction");
                            }

                            let funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                            match funct3 {
                                0 => {
                                    val += val2;
                                }
                                1 => {
                                    val <<= val2;
                                }
                                2 | 3 => {
                                    val = if val < val2 { 1 } else { 0 };
                                }
                                4 => {
                                    val ^= val2;
                                }
                                5 | 13 => {
                                    val >>= val2;
                                }
                                6 => {
                                    val |= val2;
                                }
                                7 => {
                                    val &= val2;
                                }
                                8 => {
                                    val -= val2;
                                }
                                _ => panic!("illegal instruction"),
                            }

                            if rd != 0 {
                                self.regs[rd as usize] = val;
                            }
                            self.pc += 4;
                        }
                    }
                    _ => {
                        panic!("Unknown opcode {:#x}, core: {:x?}", opcode, self)
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
struct VMMachine {
    cpu: RV32CPU,
    ram_size: usize,

    // HTIF
    // TODO: Abstract
    htif_tohost: u64,
    htif_fromhost: u64,
    // TODO: PLIC
    // TODO: VirtIO
}

#[derive(Clone)]
struct VMRAMRange {
    base: usize,
    // Not ideal, because we have to allocate all of memory immediately
    // maybe we can use mmap
    mem: Vec<u8>,
}

impl VMRAMRange {
    fn new(base: usize, size: usize) -> Self {
        let mut mem = Vec::new();
        mem.resize(size, 0);

        Self { base, mem }
    }
}

impl std::fmt::Debug for VMRAMRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMRAMRange")
            .field("base", &self.base)
            .field("len", &self.mem.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct VMMemory {
    //TODO: abstract, so not only vec-ram can be used
    ranges: Vec<VMRAMRange>,
}

impl VMMemory {
    fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    fn register_ram(&mut self, base: usize, size: usize) {
        println!("creating RAM with len {:#x}", size);
        let range = VMRAMRange::new(base, size);
        self.ranges.push(range);
    }

    fn load_from_slice(&mut self, base: usize, data: &[u8]) -> usize {
        for mem in &mut self.ranges {
            if base >= mem.base && (base + data.len()) <= (mem.base + mem.mem.len()) {
                let offset = base - mem.base;

                mem.mem[offset..][..data.len()].copy_from_slice(&data[..]);
                return data.len();
            }
        }

        panic!("No fitting mem range found.");
    }

    /// Returns the size of the loaded data.
    fn load_from_file(&mut self, base: usize, path: &str) -> usize {
        println!("loading file: {} at {:#x}", path, base);
        let data = std::fs::read(path).unwrap();
        self.load_from_slice(base, &data)
    }

    fn read_ins(&self, base: usize) -> u32 {
        for mem in &self.ranges {
            if base >= mem.base && base < (mem.base + mem.mem.len()) {
                let offset = base - mem.base;

                return (&mem.mem[offset..]).get_u32_le();
            }
        }

        panic!("No fitting mem range found.");
    }
}

impl VMMachine {
    fn from_config(cfg: &VMConfig) -> Self {
        const RAM_BASE: usize = 0x80000000;

        let mut cpu = RV32CPU::new();
        let ram_size = cfg.memory_mb << 20;

        cpu.mem.register_ram(0, 0x10000);
        cpu.mem.register_ram(RAM_BASE, ram_size);

        let bl_len = cpu.mem.load_from_file(RAM_BASE, &cfg.bios_path);
        let kernel_align = 4 << 20;
        let kernel_base = (RAM_BASE + bl_len + kernel_align - 1) & !(kernel_align - 1);
        let _kernel_len = cpu.mem.load_from_file(kernel_base, &cfg.kernel_path);
        let initrd_base = RAM_BASE + ram_size / 2;
        let _initrd_len = cpu.mem.load_from_file(initrd_base, &cfg.drive);

        // TODO: device tree
        let fdt_base = 0x1000 + 8 * 8;

        // jump_addr = 0x80000000
        //
        // auipc t0, jump_addr
        // auipc a1, dtb
        // addi a1, a1, dtb
        // csrr a0, mhartid
        // jalr zero, t0, jump_addr

        let mut trampoline: Vec<u8> = Vec::new();
        trampoline.put_u32_le(0x297 + 0x80000000 - 0x1000);
        trampoline.put_u32_le(0x597);
        trampoline.put_u32_le(0x58593 + ((fdt_base - 4) << 20));
        trampoline.put_u32_le(0xf1402573);
        trampoline.put_u32_le(0x00028067);

        cpu.mem.load_from_slice(0x1000, &trampoline);

        Self {
            cpu,
            ram_size,

            htif_tohost: 0,
            htif_fromhost: 0,
        }
    }

    fn run(&mut self) {
        self.cpu.run();
    }

    fn end(&mut self) {}
}

fn main() {
    let cfg = VMConfig {
        machine: VMMachineSpec::RV32,
        memory_mb: 128,
        bios_path: String::from("./configs/bbl32.bin"),
        kernel_path: String::from("./configs/kernel-riscv32.bin"),
        drive: String::from("./configs/root-riscv32.bin"),
    };

    let mut machine = VMMachine::from_config(&cfg);

    println!("Starting VM.");
    loop {
        machine.run();
    }
}
