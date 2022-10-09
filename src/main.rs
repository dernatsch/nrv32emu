use bytes::{Buf, BufMut};

macro_rules! sext {
    ($val:expr, $topbit:expr) => {
        (($val << (31 - $topbit)) >> (31 - $topbit))
    };
}

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
    dtb_path: String,
    drive: String,
}

struct RV32CPU {
    mem: VMMemory,
    pc: u32,
    regs: [u32; 32],

    mhartid: u32,
    mtvec: u32,
    mscratch: u32,
    misa: u32,
    mstatus: u32,
    mcounteren: u32,
    mie: u32,
    mip: u32,
    mepc: u32,
    mideleg: u32,
    medeleg: u32,

    scounteren: u32,
    satp: u32,
    sstatus: u32,
    stvec: u32,
    sie: u32,

    pmpaddr: [u32; 16],
    pmpcfg: [u32; 4],

    callstack: Vec<usize>,
}

const CLINT_BASE: usize = 0x02000000;
const CLINT_SIZE: usize = 0x000c0000;
const PLIC_BASE: usize = 0x40100000;
const PLIC_SIZE: usize = 0x00400000;

impl RV32CPU {
    fn new() -> Self {
        Self {
            mem: VMMemory::new(),
            pc: 0x1000,
            regs: [0u32; 32],
            mhartid: 0,
            mtvec: 0,
            mscratch: 0,
            mstatus: 0,
            misa: (1<<18) | // S
                (1<<20) |   // U
                (1<<8) |    // I
                (1<<12) |   // M
                (1<<0) |    // A
                (1<<2), // C

            mcounteren: 0,

            mepc: 0,
            mie: 0,
            mip: 0,
            mideleg: 0,
            medeleg: 0,

            scounteren: 0,
            satp: 0,
            sstatus: 0,
            stvec: 0,
            sie: 0,

            pmpcfg: [0u32; 4],
            pmpaddr: [0u32; 16],

            callstack: Vec::new(),
        }
    }

    fn clint_write_u32(&mut self, offset: usize, val: u32) {}

    fn plic_write_u32(&mut self, offset: usize, val: u32) {}

    fn read_ins(&self, base: usize) -> u32 {
        for mem in &self.mem.ranges {
            if base >= mem.base && base < (mem.base + mem.mem.len()) {
                let offset = base - mem.base;

                return (&mem.mem[offset..]).get_u32_le();
            }
        }

        panic!("No fitting mem range found for {:#010x}.", base);
    }

    fn write_u32(&mut self, addr: u32, val: u32) {
        let addr = addr as usize;
        for mem in &mut self.mem.ranges {
            if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                let offset = addr - mem.base;

                (&mut mem.mem[offset..]).put_u32_le(val);
                return;
            }
        }

        if addr >= CLINT_BASE && addr <= (CLINT_BASE + CLINT_SIZE - 4) {
            let offset = addr - CLINT_BASE;
            self.clint_write_u32(offset, val);
            return;
        }

        if addr >= PLIC_BASE && addr <= (PLIC_BASE + PLIC_SIZE - 4) {
            let offset = addr - PLIC_BASE;
            self.plic_write_u32(offset, val);
            return;
        }

        panic!("No fitting mem range found for {:#010x}.", addr);
    }

    fn read_u32(&mut self, addr: u32) -> u32 {
        let addr = addr as usize;
        for mem in &self.mem.ranges {
            if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                let offset = addr - mem.base;

                return (&mem.mem[offset..]).get_u32_le();
            }
        }

        panic!("No fitting mem range found for {:#010x}.", addr);
    }

    fn write_u16(&mut self, addr: u32, val: u32) {
        let addr = addr as usize;
        for mem in &mut self.mem.ranges {
            if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 2) {
                let offset = addr - mem.base;

                (&mut mem.mem[offset..]).put_u16_le(val as u16);
                return;
            }
        }

        panic!("No fitting mem range found for {:#010x}.", addr);
    }

    fn read_u16(&mut self, addr: u32) -> u32 {
        let addr = addr as usize;
        for mem in &self.mem.ranges {
            if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 2) {
                let offset = addr - mem.base;

                return (&mem.mem[offset..]).get_u16_le() as u32;
            }
        }

        panic!("No fitting mem range found for {:#010x}.", addr);
    }

    fn write_u8(&mut self, addr: u32, val: u32) {
        let addr = addr as usize;
        for mem in &mut self.mem.ranges {
            if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 1) {
                let offset = addr - mem.base;

                mem.mem[offset] = val as u8;
                return;
            }
        }

        panic!("No fitting mem range found for {:#010x}.", addr);
    }

    fn read_u8(&mut self, addr: u32) -> u8 {
        let addr = addr as usize;
        for mem in &self.mem.ranges {
            if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 1) {
                let offset = addr - mem.base;

                return mem.mem[offset];
            }
        }

        panic!("No fitting mem range found for {:#010x}.", addr);
    }

    fn die(&self, reason: &str) -> ! {
        println!("{:?}", self);
        println!("callstack: {:#010x?}", self.callstack);
        panic!("{}", reason);
    }

    fn illegal_instruction(&self) -> ! {
        self.die("illegal instruction");
    }

    fn read_csr(&self, csr: u32) -> u32 {
        match csr {
            0x100 => self.sstatus,
            0x104 => self.sie,
            0x105 => self.stvec,
            0x106 => self.scounteren,
            0x180 => self.satp,
            0x300 => self.mstatus,
            0x301 => self.misa,
            0x302 => self.medeleg,
            0x303 => self.mideleg,
            0x304 => self.mie,
            0x305 => self.mtvec,
            0x306 => self.mcounteren,
            0x340 => self.mscratch,
            0x341 => self.mepc,
            0x344 => self.mip,
            0xf14 => self.mhartid,
            0x3a0 | 0x3a1 | 0x3a2 | 0x3a3 => self.pmpcfg[(csr & 0x0f) as usize],

            0x3b0 | 0x3b1 | 0x3b2 | 0x3b3 | 0x3b4 | 0x3b5 | 0x3b6 | 0x3b7 | 0x3b8 | 0x3b9
            | 0x3ba | 0x3bb | 0x3bc | 0x3bd | 0x3be | 0x3bf => self.pmpaddr[(csr & 0x0f) as usize],
            _ => unimplemented!("unimplemented csr read value {csr:#x}"),
        }
    }

    fn write_csr(&mut self, csr: u32, val: u32) {
        match csr {
            0x100 => {
                self.sstatus = val;
            }
            0x104 => {
                self.sie = val;
            }
            0x105 => {
                self.stvec = val;
            }
            0x106 => {
                self.scounteren = val;
            }
            0x180 => {
                self.satp = val;
            }
            0x300 => {
                self.mstatus = val;
            }
            0x302 => {
                self.medeleg = val;
            }
            0x303 => {
                self.mideleg = val;
            }
            0x304 => {
                self.mie = val;
            }
            0x305 => {
                self.mtvec = val & !3;
            }
            0x306 => {
                self.mcounteren = val;
            }
            0x340 => {
                self.mscratch = val;
            }
            0x341 => {
                self.mepc = val;
            }
            0x344 => {
                self.mip = val;
            }
            0x3a0 | 0x3a1 | 0x3a2 | 0x3a3 => {
                self.pmpcfg[(csr & 0x0f) as usize] = val;
            }
            0x3b0 | 0x3b1 | 0x3b2 | 0x3b3 | 0x3b4 | 0x3b5 | 0x3b6 | 0x3b7 | 0x3b8 | 0x3b9
            | 0x3ba | 0x3bb | 0x3bc | 0x3bd | 0x3be | 0x3bf => {
                self.pmpaddr[(csr & 0x0f) as usize] = val;
            }
            _ => unimplemented!("unimplemented csr write value {csr:#x}"),
        }
    }

    fn run(&mut self) {
        //TODO: check interrupts
        //TODO: TLB (this probably needs a caching system, reading from memory
        // would need to search the ranges and then the tlb to translate an addr)

        let insn = self.read_ins(self.pc as usize);

        let opcode = insn & 0x7f;
        let quadrant = insn & 3;
        let rd = (insn >> 7) & 0x1f;
        let rs1 = (insn >> 15) & 0x1f;
        let rs2 = (insn >> 20) & 0x1f;

        println!("pc={:#010x} insn={:08x}", self.pc, insn);

        // println!("\tq={} op={:#04x}", quadrant, opcode);

        if false && self.pc == 0x80000de6 {
            self.die("");
        }

        match quadrant {
            0b00 => {
                let funct3 = (insn >> 13) & 7;
                let rd = ((insn >> 2) & 7) | 8;

                match funct3 {
                    0 => {
                        // c.addi4spn
                        let imm = ((insn >> 7) & 0x30)
                            | ((insn >> 1) & 0x3c0)
                            | ((insn >> 4) & 0x04)
                            | ((insn >> 2) & 0x08);
                        if imm == 0 {
                            self.illegal_instruction();
                        }
                        self.regs[rd as usize] = self.regs[2] + imm;
                        self.pc += 2;
                    }
                    2 => {
                        // c.lw
                        let imm =
                            ((insn >> 7) & 0x38) | ((insn >> 4) & 0x04) | ((insn << 1) & 0x40);
                        let rs1 = (insn >> 7) & 7 | 8;
                        let addr = self.regs[rs1 as usize] + imm;

                        let val = self.read_u32(addr);
                        self.regs[rd as usize] = val;
                        self.pc += 2;
                    }
                    6 => {
                        // c.sw
                        let imm =
                            ((insn >> 7) & 0x38) | ((insn >> 4) & 0x04) | ((insn << 1) & 0x40);
                        let rs1 = (insn >> 7) & 7 | 8;
                        let addr = self.regs[rs1 as usize].wrapping_add(imm);
                        let val = self.regs[rd as usize];
                        self.write_u32(addr, val);
                        self.pc += 2;
                    }
                    _ => unimplemented!("compact0 function {}", funct3),
                }
            }
            0b01 => {
                let funct3 = (insn >> 13) & 7;

                match funct3 {
                    0 => {
                        // c.addi else c.nop
                        if rd != 0 {
                            let imm = ((insn >> 7) & 0x20) | ((insn >> 2) & 0x1f);
                            let imm = sext!(imm as i32, 5);

                            self.regs[rd as usize] =
                                self.regs[rd as usize].wrapping_add(imm as u32);
                        }
                        self.pc += 2;
                    }
                    1 => {
                        // c.jal
                        let imm = ((insn >> 1) & 0x800)
                            | ((insn >> 7) & 0x10)
                            | ((insn >> 1) & 0x300)
                            | ((insn << 2) & 0x400)
                            | ((insn >> 1) & 0x40)
                            | ((insn << 1) & 0x80)
                            | ((insn >> 2) & 0x0e)
                            | ((insn << 3) & 0x20);
                        let imm = sext!(imm as i32, 11);

                        self.regs[1] = self.pc + 2;
                        self.callstack.push(self.pc as usize);
                        self.pc = self.pc.wrapping_add(imm as u32);
                    }
                    2 => {
                        // c.li
                        if rd != 0 {
                            let imm = ((insn >> 7) & 0x20) | ((insn >> 2) & 0x1f);
                            let imm = sext!(imm as i32, 5);
                            self.regs[rd as usize] = imm as u32;
                        }
                        self.pc += 2;
                    }
                    3 => {
                        if rd == 2 {
                            // c.addi16sp
                            let imm = ((insn >> 3) & 0x200)
                                | ((insn >> 2) & 0x10)
                                | ((insn << 1) & 0x40)
                                | ((insn << 4) & 0x180)
                                | ((insn << 3) & 0x20);
                            let imm = sext!(imm as i32, 9);

                            if imm == 0 {
                                self.illegal_instruction();
                            }

                            self.regs[2] = self.regs[2].wrapping_add(imm as u32);
                            self.pc += 2;
                        } else {
                            // c.lui
                            let imm = ((insn << 10) & 0x1f000) | ((insn << 5) & 0x20000);
                            let imm = sext!(imm as i32, 17);

                            if imm == 0 || rd == 0 || rd == 2 {
                                self.illegal_instruction();
                            }

                            self.regs[rd as usize] = imm as u32;
                            self.pc += 2;
                        }
                    }
                    4 => {
                        let funct3 = (insn >> 10) & 3;
                        let rd = ((insn >> 7) & 7) | 8;

                        match funct3 {
                            0 | 1 => {
                                let imm = ((insn >> 7) & 0x20) | ((insn >> 2) & 0x1f);

                                if imm & 0x20 > 0 {
                                    self.illegal_instruction();
                                }

                                if funct3 == 0 {
                                    // c.srli
                                    self.regs[rd as usize] >>= imm;
                                } else {
                                    // c.srai
                                    let r = self.regs[rd as usize] as i32 >> imm as i32;
                                    self.regs[rd as usize] = r as u32;
                                }
                            }
                            2 => {
                                // c.andi
                                let imm = ((insn >> 7) & 0x20) | ((insn >> 2) & 0x1f);
                                let imm = sext!(imm as i32, 5) as u32;

                                self.regs[rd as usize] &= imm;
                            }
                            3 => {
                                let rs2 = ((insn >> 2) & 7) | 8;
                                let funct3 = ((insn >> 5) & 3) | ((insn >> 10) & 4);
                                match funct3 {
                                    0 => self.regs[rd as usize] -= self.regs[rs2 as usize], // c.sub
                                    1 => self.regs[rd as usize] ^= self.regs[rs2 as usize], // c.xor
                                    2 => self.regs[rd as usize] |= self.regs[rs2 as usize], // c.or
                                    3 => self.regs[rd as usize] &= self.regs[rs2 as usize], // c.and
                                    _ => self.illegal_instruction(),
                                }
                            }
                            _ => unreachable!(),
                        }

                        self.pc += 2;
                    }
                    5 => {
                        // c.j
                        let imm = ((insn >> 1) & 0x800)
                            | ((insn >> 7) & 0x10)
                            | ((insn >> 1) & 0x300)
                            | ((insn << 2) & 0x400)
                            | ((insn >> 1) & 0x40)
                            | ((insn << 1) & 0x80)
                            | ((insn >> 2) & 0x0e)
                            | ((insn << 3) & 0x20);
                        let imm = sext!(imm as i32, 11);

                        self.pc = self.pc.wrapping_add(imm as u32);
                    }
                    6 => {
                        // c.beqz
                        let rs1 = ((insn >> 7) & 7) | 8;
                        let imm = ((insn >> 4) & 0x100)
                            | ((insn >> 7) & 0x18)
                            | ((insn << 1) & 0xc0)
                            | ((insn >> 2) & 0x06)
                            | ((insn << 3) & 0x20);
                        let imm = sext!(imm as i32, 8);
                        let target = self.pc.wrapping_add(imm as u32);

                        if self.regs[rs1 as usize] == 0 {
                            self.pc = target;
                        } else {
                            self.pc += 2;
                        }
                    }
                    7 => {
                        // c.bnez
                        let rs1 = ((insn >> 7) & 7) | 8;
                        let imm = ((insn >> 4) & 0x100)
                            | ((insn >> 7) & 0x18)
                            | ((insn << 1) & 0xc0)
                            | ((insn >> 2) & 0x06)
                            | ((insn << 3) & 0x20);
                        let imm = sext!(imm as i32, 8);
                        let target = self.pc.wrapping_add(imm as u32);

                        if self.regs[rs1 as usize] != 0 {
                            self.pc = target;
                        } else {
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
                    0 => {
                        // c.slli
                        let imm = ((insn >> 7) & 0x20) | rs2;
                        if imm & 0x20 > 0 {
                            self.illegal_instruction();
                        }

                        if rd != 0 {
                            self.regs[rd as usize] <<= imm;
                        }
                        self.pc += 2;
                    }
                    2 => {
                        // c.lwsp
                        let imm = ((insn >> 7) & 0x20) | ((insn << 4) & 0xc0) | (rs2 & 0x1c);
                        let addr = self.regs[2] + imm;
                        let val = self.read_u32(addr);
                        if rd != 0 {
                            self.regs[rd as usize] = val;
                        }

                        self.pc += 2;
                    }
                    4 => {
                        if ((insn >> 12) & 1) == 0 {
                            if rs2 == 0 {
                                // c.jr
                                if rd == 0 {
                                    self.illegal_instruction();
                                }

                                if rd == 1 {
                                    self.callstack.pop();
                                }

                                self.pc = self.regs[rd as usize] & 0xfffffffe;
                            } else {
                                // c.mv
                                if rd != 0 {
                                    self.regs[rd as usize] = self.regs[rs2 as usize];
                                }

                                self.pc += 2;
                            }
                        } else {
                            if rs2 == 0 {
                                if rd == 0 {
                                    // c.ebreak
                                    todo!();
                                } else {
                                    // c.jalr
                                    let val = self.pc + 2;
                                    self.callstack.push(self.pc as usize);
                                    self.pc = self.regs[rd as usize] & 0xfffffffe;
                                    self.regs[1] = val;
                                }
                            } else {
                                // c.add
                                if rd != 0 {
                                    self.regs[rd as usize] = self.regs[rd as usize]
                                        .wrapping_add(self.regs[rs2 as usize]);
                                }
                                self.pc += 2;
                            }
                        }
                    }
                    6 => {
                        // c.swsp
                        let imm = ((insn >> 7) & 0x3c) | ((insn >> 1) & 0xc0);
                        let addr = self.regs[2] + imm;
                        self.write_u32(addr, self.regs[rs2 as usize]);

                        self.pc += 2;
                    }
                    _ => unimplemented!("compact2 function {}", funct3),
                }
            }
            0b11 => {
                match opcode {
                    0x03 => {
                        // load
                        let funct3 = (insn >> 12) & 7;
                        let imm = (insn as i32) >> 20;
                        let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                        let val;

                        match funct3 {
                            2 => {
                                // lw
                                val = self.read_u32(addr);
                            }
                            4 => {
                                // lbu
                                val = self.read_u8(addr) as u32;
                            }
                            _ => unimplemented!("load {}", funct3),
                        }

                        if rd != 0 {
                            self.regs[rd as usize] = val;
                        }
                        self.pc += 4;
                    }
                    0x0f => {
                        // fence
                        self.pc += 4;
                    }
                    0x23 => {
                        // store
                        let funct3 = (insn >> 12) & 7;
                        let imm = ((insn >> 20) & 0xfe0) | ((insn >> 7) & 0x1f);
                        let imm = sext!(imm as i32, 11);
                        let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);

                        match funct3 {
                            0 => {
                                // sb
                                self.write_u8(addr, self.regs[rs2 as usize]);
                            }
                            1 => {
                                // sh
                                self.write_u16(addr, self.regs[rs2 as usize]);
                            }
                            2 => {
                                // sw
                                self.write_u32(addr, self.regs[rs2 as usize]);
                            }
                            _ => unimplemented!("store {}", funct3),
                        }

                        self.pc += 4;
                    }
                    0x17 => {
                        // auipc
                        if rd != 0 {
                            self.regs[rd as usize] = self.pc.wrapping_add(insn & 0xfffff000);
                        }
                        self.pc += 4;
                    }
                    0x13 => {
                        // addi...

                        let funct3 = (insn >> 12) & 7;
                        let imm = (insn as i32 >> 20) as u32;
                        let val;

                        match funct3 {
                            0 => {
                                // addi
                                val = self.regs[rs1 as usize].wrapping_add(imm);
                            }
                            1 => {
                                // slli
                                val = self.regs[rs1 as usize] << imm;
                            }
                            4 => {
                                // xori
                                val = self.regs[rs1 as usize] ^ imm;
                            }
                            5 => {
                                if imm & 0x400 > 0 {
                                    //srai
                                    let imm = imm & 0x1f;
                                    let r = (self.regs[rs1 as usize] as i32) >> imm as i32;
                                    val = r as u32;
                                } else {
                                    // srli
                                    let imm = imm & 0x1f;
                                    val = self.regs[rs1 as usize] >> imm;
                                }
                            }
                            6 => {
                                // ori
                                val = self.regs[rs1 as usize] | imm;
                            }
                            7 => {
                                // andi
                                val = self.regs[rs1 as usize] & imm;
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
                            0 => {
                                // xret
                                let funct12 = insn >> 20;
                                match funct12 {
                                    0x302 => {
                                        // mret
                                        self.pc = self.mepc;
                                    }
                                    0x120 => {
                                        self.pc += 4;
                                    }
                                    _ => todo!("{:#x}ret", funct12)
                                }
                            }
                            1 => {
                                // csrrw
                                let val2 = self.read_csr(imm);
                                self.write_csr(imm, val);

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }
                                self.pc += 4;
                            }
                            2 | 3 => {
                                // csrrs, csrrc
                                let val2 = self.read_csr(imm);
                                if rs1 != 0 {
                                    val = val2 | val;
                                    self.write_csr(imm, val);
                                }

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }
                                self.pc += 4;
                            }
                            _ => {
                                panic!("Unknown csr function {}, core: {:x?}", funct3, self)
                            }
                        }

                    }
                    0x67 => {
                        // jalr
                        let imm = insn >> 20;
                        let val = self.pc + 4;
                        self.pc = self.regs[rs1 as usize] + imm;

                        if rd != 0 {
                            self.regs[rd as usize] = val;
                            self.callstack.push((val - 4) as usize);
                        } else {
                            self.callstack.pop();
                        }
                    }
                    0x6f => {
                        // jal
                        let imm = ((insn >> 11) & 0x100000)
                            | ((insn >> 20) & 0x7fe)
                            | ((insn >> 9) & 0x800)
                            | (insn) & 0xff000;

                        let imm = sext!(imm as i32, 20);

                        if rd != 0 {
                            self.regs[rd as usize] = self.pc + 4;
                            self.callstack.push(self.pc as usize);
                        }

                        let (target, _) = u32::overflowing_add(self.pc, imm as u32);
                        self.pc = target;
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
                                cond = (self.regs[rs1 as usize] as i32)
                                    < (self.regs[rs2 as usize] as i32);
                            }
                            3 => {
                                // bltu, bgeu
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
                            let imm = sext!(imm as i32, 12);
                            let (target, _) = self.pc.overflowing_add(imm as u32);
                            self.pc = target;
                        } else {
                            self.pc += 4;
                        }
                    }
                    0x33 => {
                        let imm = insn >> 25;
                        let imm = sext!(imm as i32, 6) as u32;
                        let mut val = self.regs[rs1 as usize];
                        let val2 = self.regs[rs2 as usize];

                        if imm == 1 {
                            unimplemented!();
                        } else {
                            if (imm & !0x20) != 0 {
                                self.illegal_instruction();
                            }

                            let funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                            match funct3 {
                                0 => {
                                    val += val2;
                                }
                                1 => {
                                    val = val.wrapping_shl(val2);
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
                                    val = val.wrapping_sub(val2);
                                }
                                _ => self.illegal_instruction(),
                            }

                            if rd != 0 {
                                self.regs[rd as usize] = val;
                            }
                            self.pc += 4;
                        }
                    }
                    0x37 => {
                        // lui
                        if rd != 0 {
                            let imm = insn & 0xfffff000;
                            self.regs[rd as usize] = imm;
                        }
                        self.pc += 4;
                    }
                    0x2f => {
                        // amo
                        let funct3 = (insn >> 12) & 7;
                        let funct5 = insn >> 27;
                        let addr = self.regs[rs1 as usize];

                        match funct3 { // data width
                            2 => {
                                // amox.w
                                match funct5 {
                                    0 => {
                                        // amoadd.w
                                        let val = self.read_u32(addr);
                                        let val2 = self.regs[rs2 as usize];
                                        let res = val.wrapping_add(val2);
                                        self.write_u32(addr, res);
                                        self.regs[rd as usize] = val;
                                    }
                                    _ => unimplemented!("amoX.w {}", funct5)
                                }
                            }
                            _ => unimplemented!("amo width {}", funct5)
                        }

                        self.pc += 4;
                    }
                    0x93 => {
                        panic!();
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

#[derive(Debug)]
struct VMMachine {
    cpu: RV32CPU,
    ram_size: usize,
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

impl std::fmt::Debug for RV32CPU {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CORE:")?;
        writeln!(f, "pc: {:#010x}", self.pc)?;

        for n in 0..32 {
            writeln!(f, "r{:02}: {:#010x}", n, self.regs[n])?;
        }

        Ok(())
    }
}

struct VMMemory {
    //TODO: abstract, so not only vec-ram can be used
    ranges: Vec<VMRAMRange>,
}

impl VMMemory {
    fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    fn register_ram(&mut self, base: usize, size: usize) {
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

        panic!("No fitting mem range found for {:#010x}.", base);
    }

    /// Returns the size of the loaded data.
    fn load_from_file(&mut self, base: usize, path: &str) -> usize {
        println!("loading file: {} at {:#x}", path, base);
        let data = std::fs::read(path).unwrap();
        self.load_from_slice(base, &data)
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
        cpu.mem.load_from_file(fdt_base, &cfg.dtb_path);

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
        trampoline.put_u32_le(0x58593 + ((fdt_base as u32 - 4) << 20));
        trampoline.put_u32_le(0xf1402573);
        trampoline.put_u32_le(0x00028067);

        cpu.mem.load_from_slice(0x1000, &trampoline);

        Self { cpu, ram_size }
    }

    fn run(&mut self) {
        self.cpu.run();
    }
}

fn main() {
    let cfg = VMConfig {
        machine: VMMachineSpec::RV32,
        memory_mb: 128,
        bios_path: String::from("./configs/rv32-zephyr/zephyr.bin"),
        kernel_path: String::from("/dev/null"),
        dtb_path: String::from("/dev/null"),
        drive: String::from("/dev/null"),
    };

    let mut machine = VMMachine::from_config(&cfg);

    loop {
        machine.run();
    }
}
