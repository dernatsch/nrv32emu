/*
* nrv32emu
* Copyright © 2022 Jannik Birk

* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation
* the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:

* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
* OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

use bytes::{Buf, BufMut};
use log::{info, debug, trace, warn};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

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

    privl: u32,

    mhartid: u32,
    mtvec: u32,
    mscratch: u32,
    misa: u32,
    mstatus: u32,
    mstatush: u32,
    mcounteren: u32,
    mie: u32,
    mip: u32,
    mepc: u32,
    mideleg: u32,
    medeleg: u32,
    mcause: u32,
    mtval: u32,

    scounteren: u32,
    satp: u32,
    sstatus: u32,
    stvec: u32,
    sie: u32,
    scause: u32,
    sepc: u32,
    stval: u32,

    pmpaddr: [u32; 64],
    pmpcfg: [u32; 4],

    pending_exception: Option<u32>,
    pending_tval: u32,

    power_down: bool,

    timecmp: u64,

    load_res: u32,
}

const CLINT_BASE: usize = 0x02000000;
const CLINT_SIZE: usize = 0x0010000;
const PLIC_BASE: usize = 0x40100000;
const PLIC_SIZE: usize = 0x04000000;
const UART_BASE: usize = 0x10000000;
const UART_SIZE: usize = 0x00000100;

const CAUSE_BREAKPOINT: u32 = 0x3;
const CAUSE_LOAD_ACCESS: u32 = 0x5;
const CAUSE_USER_ECALL: u32 = 0x8;
const CAUSE_FETCH_PAGE_FAULT: u32 = 0x0c;
const CAUSE_LOAD_PAGE_FAULT: u32 = 0xd;
const CAUSE_INTERRUPT: u32 = 0x80;

impl RV32CPU {
    fn new() -> Self {
        Self {
            mem: VMMemory::new(),
            pc: 0x1000,
            regs: [0u32; 32],
            privl: 3,
            mhartid: 0,
            mtvec: 0,
            mscratch: 0,
            mstatus: 0,
            mstatush: 0,
            misa: (1<<18) | // S
                (1<<20) |   // U
                (1<<8) |    // I
                (1<<12) |   // M
                (1<<0) |    // A
                // (1<<5) |    // F
                // (1<<3) |    // D
                (1<<2) | // C
                (1<<30), // XLEN=32

            mcounteren: 0,

            mepc: 0,
            mie: 0,
            mip: 0,
            mideleg: 0,
            medeleg: 0,
            mcause: 0,
            mtval: 0,

            scounteren: 0,
            satp: 0,
            sstatus: 0,
            stvec: 0,
            sie: 0,
            scause: 0,
            sepc: 0,
            stval: 0,

            pmpcfg: [0u32; 4],
            pmpaddr: [0u32; 64],

            pending_exception: None,
            pending_tval: 0,

            power_down: false,

            timecmp: 0xffffffff,

            load_res: 0,
        }
    }

    fn rtc_time() -> u64 {
        let ts = std::time::SystemTime::UNIX_EPOCH.elapsed().unwrap();
        (ts.as_nanos() / 100) as u64
    }

    fn clint_write_u32(&mut self, offset: usize, val: u32) {
        match offset {
            0x4000 => {
                self.timecmp = (self.timecmp & !0xffffffff) | val as u64;
                self.unset_mip(0x80);
            }
            0x4004 => {
                self.timecmp = (self.timecmp & 0xffffffff) | ((val as u64) << 32);
                self.unset_mip(0x80);
            }
            _ => unimplemented!("clint write off={:#010x}", offset),
        }
    }

    fn clint_read_u32(&mut self, offset: usize) -> u32 {
        match offset {
            0xbff8 => Self::rtc_time() as u32,
            0xbffc => (Self::rtc_time() >> 32) as u32,
            0x4000 => self.timecmp as u32,
            0x4004 => (self.timecmp >> 32) as u32,
            _ => unimplemented!("clint read off={:#010x}", offset),
        }
    }

    fn plic_write_u32(&mut self, offset: usize, _val: u32) {
        match offset {
            _ => {},
            // _ => unimplemented!("PLIC write offset {:#010x}", offset),
        }
    }

    fn plic_read_u32(&mut self, offset: usize) -> u32 {
        match offset {
            _ => 0,
            // _ => unimplemented!("PLIC read offset {:#010x}", offset),
        }
    }

    fn uart_write_u8(&mut self, offset: usize, val: u32) {
        match offset {
            0 => {
                // transmit buffer
                print!("{}", (val as u8) as char);
            }
            _ => {}
        }
    }

    fn uart_read_u8(&mut self, offset: usize) -> u8 {
        match offset {
            0x05 => {
                // line status register
                // return fifos empty, no errors
                0x60
            }
            _ => 0,
        }
    }

    fn set_mip(&mut self, mask: u32) {
        self.mip |= mask;

        if self.power_down && (self.mip & self.mie) > 0 {
            self.power_down = false;
        }
    }

    fn unset_mip(&mut self, mask: u32) {
        self.mip &= !mask;
    }

    fn get_phys_addr(&self, base: u32) -> Option<u32> {
        const LEVELS: i32 = 2;

        if self.privl == 3 {
            // no paging in M mode
            return Some(base);
        }

        let mode = self.satp >> 31;
        if mode == 0 {
            // paging disabled
            Some(base)
        } else {
            let mut level = LEVELS - 1;
            let mut pte_addr = (self.satp << 12) as usize;
            while level >= 0 {
                let vaddr_shift = 12 + level * 10;
                let vpn = (base as usize >> vaddr_shift) & 0x3ff;
                pte_addr += vpn * 4;
                let pte = self.read_phys(pte_addr);
                let paddr = (pte as usize >> 10) << 12;

                if pte & 1 == 0 {
                    // invalid entry
                    warn!("invalid pte entry");
                    return None;
                }

                let xwr = (pte >> 1) & 7;
                if xwr == 0 {
                    pte_addr = paddr;
                    level -= 1;
                } else {
                    if xwr == 2 || xwr == 6 {
                        return None;
                    }

                    // TODO: check privilege
                    // TODO: check protection
                    // TODO: check access type
                    // TODO: set access flag
                    // TODO: set dirty flag on write

                    let vaddr_mask: u32 = (1 << vaddr_shift) - 1;
                    let phys_addr: u32 = (base & vaddr_mask) | (paddr as u32 & !vaddr_mask);
                    return Some(phys_addr);
                }
            }

            None
        }
    }

    fn read_phys(&self, base: usize) -> u32 {
        let base = base;
        for mem in &self.mem.ranges {
            if base >= mem.base && base < (mem.base + mem.mem.len()) {
                let offset = base - mem.base;

                return (&mem.mem[offset..]).get_u32_le();
            }
        }

        self.die(&format!("No fitting mem range found for {:#010x}.", base));
    }

    fn read_ins(&mut self, base: usize) -> Option<u32> {
        if let Some(base) = self.get_phys_addr(base as u32) {
            let base = base as usize;
            for mem in &self.mem.ranges {
                if base >= mem.base && base < (mem.base + mem.mem.len()) {
                    let offset = base - mem.base;

                    let ins = (&mem.mem[offset..]).get_u32_le();
                    return Some(ins);
                }
            }

            self.die(&format!("No fitting mem range found for {:#010x}.", base));
        } else {
            self.pending_tval = base as u32;
            self.pending_exception = Some(CAUSE_FETCH_PAGE_FAULT);
            None
        }
    }

    /// Perform a 32-bit write to memory.
    /// Returns false when a fault occured, else true.
    fn write_u32(&mut self, addr: u32, val: u32) -> bool {
        if let Some(addr) = self.get_phys_addr(addr) {
            let addr = addr as usize;
            for mem in &mut self.mem.ranges {
                if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                    let offset = addr - mem.base;

                    (&mut mem.mem[offset..]).put_u32_le(val);
                    return true;
                }
            }

            if (CLINT_BASE..=(CLINT_BASE + CLINT_SIZE - 4)).contains(&addr) {
                let offset = addr - CLINT_BASE;
                self.clint_write_u32(offset, val);
                return true;
            }

            if (PLIC_BASE..=(PLIC_BASE + PLIC_SIZE - 4)).contains(&addr) {
                let offset = addr - PLIC_BASE;
                self.plic_write_u32(offset, val);
                return true;
            }

            self.die(&format!("No fitting mem range found for {:#010x}.", addr));
        } else {
            self.pending_tval = addr as u32;
            self.pending_exception = Some(CAUSE_LOAD_PAGE_FAULT);
            return false;
        }
    }

    fn read_u32(&mut self, addr: u32) -> Option<u32> {
        if let Some(addr) = self.get_phys_addr(addr) {
            let addr = addr as usize;
            for mem in &self.mem.ranges {
                if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                    let offset = addr - mem.base;

                    return Some((&mem.mem[offset..]).get_u32_le());
                }
            }

            if (CLINT_BASE..=(CLINT_BASE + CLINT_SIZE - 4)).contains(&addr) {
                let offset = addr - CLINT_BASE;
                return Some(self.clint_read_u32(offset));
            }

            if (PLIC_BASE..=(PLIC_BASE + PLIC_SIZE - 4)).contains(&addr) {
                let offset = addr - PLIC_BASE;
                return Some(self.plic_read_u32(offset));
            }

            panic!("No fitting mem range found for {:#010x}.", addr);
        } else {
            self.pending_tval = addr;
            self.pending_exception = Some(CAUSE_LOAD_PAGE_FAULT);
            None
        }
    }

    fn write_u16(&mut self, addr: u32, val: u32) {
        if let Some(addr) = self.get_phys_addr(addr) {
            let addr = addr as usize;
            for mem in &mut self.mem.ranges {
                if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                    let offset = addr - mem.base;

                    (&mut mem.mem[offset..]).put_u16_le(val as u16);
                    return;
                }
            }

            panic!("No fitting mem range found for {:#010x}.", addr);
        } else {
            self.pending_tval = addr;
            self.pending_exception = Some(CAUSE_LOAD_PAGE_FAULT);
        }
    }

    fn read_u16(&mut self, addr: u32) -> Option<u32> {
        if let Some(addr) = self.get_phys_addr(addr) {
            let addr = addr as usize;
            for mem in &self.mem.ranges {
                if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                    let offset = addr - mem.base;

                    return Some((&mem.mem[offset..]).get_u16_le() as u32);
                }
            }

            panic!("No fitting mem range found for {:#010x}.", addr);
        } else {
            self.pending_tval = addr;
            self.pending_exception = Some(CAUSE_LOAD_PAGE_FAULT);
            None
        }
    }

    fn write_u8(&mut self, addr: u32, val: u32) {
        if let Some(addr) = self.get_phys_addr(addr) {
            let addr = addr as usize;
            for mem in &mut self.mem.ranges {
                if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 1) {
                    let offset = addr - mem.base;

                    mem.mem[offset] = val as u8;
                    return;
                }
            }

            if (UART_BASE..=(UART_BASE + UART_SIZE - 1)).contains(&addr) {
                let offset = addr - UART_BASE;
                self.uart_write_u8(offset, val);
                return;
            }

            panic!("No fitting mem range found for {:#010x}.", addr);
        } else {
            self.pending_tval = addr;
            self.pending_exception = Some(CAUSE_LOAD_PAGE_FAULT);
        }
    }

    fn read_u8(&mut self, addr: u32) -> Option<u8> {
        if let Some(addr) = self.get_phys_addr(addr) {
            let addr = addr as usize;
            for mem in &self.mem.ranges {
                if addr >= mem.base && addr <= (mem.base + mem.mem.len() - 4) {
                    let offset = addr - mem.base;

                    return Some(mem.mem[offset]);
                }
            }

            if (UART_BASE..=(UART_BASE + UART_SIZE - 1)).contains(&addr) {
                let offset = addr - UART_BASE;
                return Some(self.uart_read_u8(offset));
            }

            self.die(&format!("No fitting mem range found for {:#010x}.", addr));
        } else {
            self.pending_tval = addr;
            self.pending_exception = Some(CAUSE_LOAD_PAGE_FAULT);
            None
        }
    }

    fn die(&self, reason: &str) -> ! {
        println!("{:?}", self);
        panic!("{}", reason);
    }

    fn illegal_instruction(&self) -> ! {
        self.die("illegal instruction");
    }

    fn read_csr(&mut self, csr: u32) -> u32 {
        match csr {
            0x100 => self.sstatus,
            0x104 => self.sie,
            0x105 => self.stvec,
            0x106 => self.scounteren,
            0x140 => self.sscratch,
            0x143 => self.stval,
            0x144 => self.sip,
            0x180 => self.satp,
            0x300 => self.mstatus,
            0x301 => self.misa,
            0x302 => self.medeleg,
            0x303 => self.mideleg,
            0x304 => self.mie,
            0x305 => self.mtvec,
            0x306 => self.mcounteren,
            0x310 => self.mstatush,
            0x340 => self.mscratch,
            0x341 => self.mepc,
            0x344 => self.mip,
            0xf14 => self.mhartid,
            0x3a0 | 0x3a1 | 0x3a2 | 0x3a3 => self.pmpcfg[(csr & 0x0f) as usize],

            0x3b0..=0x3ff => self.pmpaddr[(csr & 0x3f) as usize],
            0xc01 => 0,
            0x320..=0x33f => 0, //XXX: counter setup

            0x340 => self.mscratch,
            0x341 => self.mepc,
            0x342 => self.mcause,
            0x343 => self.mtval,
            0x344 => self.mip,

            0xc01 => (Self::rtc_time() & 0xffffffff) as u32, // time
            0xc81 => (Self::rtc_time() >> 32) as u32, // timeh

            0xb00..=0xb9f => 0, //XXX: performance counter
            0xda0 => 0, // supervisor count overflow
            0xf11..=0xf13 => 0, // mvendorid, marchid, mimpid

            x => {
                warn!("csr {:#05x} access fault", x);
                self.pending_exception = Some(CAUSE_LOAD_ACCESS);
                0
            }

            /*
            // forbidden csrs
            0x14d..=0x15d => {
                self.pending_exception = Some(CAUSE_LOAD_ACCESS);
                self.pending_tval = 0x14d;
                0
            },

            _ => 0, // unimplemented
            */
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
            0x140 => {
                self.sscratch = val;
            }
            0x143 => {
                self.stval = val;
            }
            0x144 => {
                self.sip = val;
            }
            0x180 => {
                self.satp = val & 0x801fffff;
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
                info!("mie set to {:#010x} pc={:#010x}", val, self.pc);
                self.mie = val;
            }
            0x305 => {
                self.mtvec = val & !3;
            }
            0x306 => {
                self.mcounteren = val;
            }
            0x310 => {
                self.mstatush = val;
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
            0x3b0..=0x3ff => {
                self.pmpaddr[(csr & 0x3f) as usize] = val;
            }
            0xb00..=0xb9f => {}

            // forbidden csrs
            0x14d | 0x15d => {
                self.pending_exception = Some(CAUSE_LOAD_ACCESS);
                self.pending_tval = 0x14d;
            },

            _ => {},
            // _ => self.die(&format!("unimplemented csr write value {csr:#x}")),
        }
    }

    fn do_mret(&mut self) {
        let mpp = (self.mstatus >> 11) & 3;
        let mpie = (self.mstatus >> 7) & 1;

        self.mstatus &= !(1 << mpp);
        self.mstatus |= mpie << mpp;

        // set MPIE
        self.mstatus |= 1 << 7;

        self.mstatus &= !(3 << 11);
        self.privl = mpp;
        self.pc = self.mepc;
    }

    fn raise_exception(&mut self) {
        let cause = self.pending_exception.unwrap();
        let tval = self.pending_tval;

        debug!("EXCEPTION: cause={:#010x} tval={:#010x}", cause, tval);

        let deleg;
        if self.privl <= 2 {
            if cause & CAUSE_INTERRUPT > 0 {
                deleg = (self.mideleg & (1 << cause)) > 0;
            } else {
                deleg = (self.medeleg & (1 << cause)) > 0;
            }
        } else {
            deleg = false;
        }

        if deleg {
            self.scause = cause;
            self.sepc = self.pc;
            self.stval = tval;

            // set spie
            self.mstatus &= !(1 << 5);
            self.mstatus |= (self.privl & 1) << 5;

            // set spp
            self.mstatus &= !(1 << 8);
            self.mstatus |= self.privl << 8;

            // unset sie
            self.mstatus &= !(1 << 1);

            self.privl = 1;
            self.pc = self.stvec;
        } else {
            self.mcause = cause;
            self.mepc = self.pc;
            self.mtval = tval;

            // set mpie
            self.mstatus &= !(1 << 7);
            self.mstatus |= (self.privl & 1) << 7;

            // set mpp
            self.mstatus &= !(3 << 11);
            self.mstatus |= (self.privl & 3) << 11;

            // unset mie
            self.mstatus &= !(1 << 3);
            self.privl = 3;
            self.pc = self.mtvec;
        }
    }

    fn get_pending_irq_mask(&self) -> u32 {
        let pending = self.mip & self.mie;
        if pending == 0 {
            return 0;
        }

        let enabled = match self.privl {
            3 => {
                // M mode
                if self.mstatus & 0x08 > 0 {
                    !self.mideleg
                } else {
                    0
                }
            }
            1 => {
                // S mode
                if self.mstatus & 0x02 > 0 {
                    0xffffffff
                } else {
                    !self.mideleg
                }
            }
            _ => {
                // U mode (or invalid)
                0xffffffff
            }
        };

        enabled & pending
    }

    /// Raise an interrupt and jump to interrupt handler.
    /// Returns true if any interrup was triggered.
    fn raise_interrupt(&mut self) -> bool {
        let mask = self.get_pending_irq_mask();
        if mask != 0 {
            let irq_no = mask.trailing_zeros();
            debug!("INTERRUPT {} raised", irq_no);
            self.pending_exception = Some(irq_no | 0x80000000);
            true
        } else {
            false
        }
    }

    fn run(&mut self) {
        //TODO: check interrupts
        //TODO: TLB (this probably needs a caching system, reading from memory
        // would need to search the ranges and then the tlb to translate an addr)

        debug_assert!(self.regs[0] == 0);

        if self.pending_exception.is_some() {
            self.raise_exception();
            self.pending_exception = None;
            return;
        }

        if self.mip & self.mie != 0 && self.raise_interrupt() {
            // we only bail if an interrupt was actually triggered
            return;
        }

        let insn = self.read_ins(self.pc as usize);
        if insn.is_none() {
            return;
        }
        let insn = insn.unwrap();

        trace!("pc: {:#010x} insn={:08x}", self.pc, insn);

        let opcode = insn & 0x7f;
        let quadrant = insn & 3;
        let rd = (insn >> 7) & 0x1f;
        let rs1 = (insn >> 15) & 0x1f;
        let rs2 = (insn >> 20) & 0x1f;

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

                        if let Some(val) = self.read_u32(addr) {
                            self.regs[rd as usize] = val;
                            self.pc += 2;
                        } else {
                            
                        }
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
                                    0 => {
                                        self.regs[rd as usize] = self.regs[rd as usize]
                                            .wrapping_sub(self.regs[rs2 as usize])
                                    } // c.sub
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
                        if let Some(val) = self.read_u32(addr) {
                            if rd != 0 {
                                self.regs[rd as usize] = val;
                            }

                            self.pc += 2;
                        } else {
                            
                        }
                    }
                    4 => {
                        if ((insn >> 12) & 1) == 0 {
                            if rs2 == 0 {
                                // c.jr
                                if rd == 0 {
                                    self.illegal_instruction();
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
                                    debug!("ebreak! pc={:#010x}", self.pc);
                                    debug!("mtvec={:#010x} stvec={:#010x}", self.mtvec, self.stvec);
                                    self.pending_exception = Some(CAUSE_BREAKPOINT);
                                    return;
                                } else {
                                    // c.jalr
                                    let val = self.pc + 2;
                                    self.pc = self.regs[rd as usize] & !1;
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
                        let val: u32;

                        match funct3 {
                            0 => {
                                // lb
                                if let Some(v) = self.read_u8(addr) {
                                    val = sext!(v as i32, 7) as u32;
                                } else {
                                    return;
                                }
                            }
                            1 => {
                                // lh
                                if let Some(v) = self.read_u16(addr) {
                                    val = sext!(v as i32, 15) as u32;
                                } else {
                                    return;
                                }
                            }
                            2 => {
                                // lw
                                if let Some(v) = self.read_u32(addr) {
                                    val = v;
                                } else {
                                    return;
                                }
                            }
                            4 => {
                                // lbu
                                if let Some(v) = self.read_u8(addr) {
                                    val = v as u32;
                                } else {
                                    return;
                                }
                            }
                            5 => {
                                // lhu
                                if let Some(v) = self.read_u16(addr) {
                                    val = v;
                                } else {
                                    return;
                                }
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
                            2 => {
                                // slti
                                val = if (self.regs[rs1 as usize] as i32) < (imm as i32) { 1 } else { 0 };
                            }
                            3 => {
                                // sltiu
                                val = if self.regs[rs1 as usize] < imm { 1 } else { 0 };
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
                                // xret...
                                let funct12 = insn >> 20;
                                match funct12 {
                                    0x000 => {
                                        // ecall
                                        debug!("ecall! a7={:#010x} a6={:#010x}", self.regs[17], self.regs[16]);
                                        self.pending_exception = Some(CAUSE_USER_ECALL + self.privl);
                                        return
                                    }
                                    0x001 => {
                                        // ebreak
                                        debug!("ebreak! pc={:#010x}", self.pc);
                                        self.pending_exception = Some(CAUSE_BREAKPOINT);
                                        return;
                                    }
                                    0x302 => {
                                        // mret
                                        self.do_mret();
                                    }
                                    0x120 => {
                                        self.pc += 4;
                                    }
                                    0x105 => {
                                        // wfi
                                        if self.mip & self.mie == 0 {
                                            self.power_down = true;
                                            self.pc += 4;
                                            
                                        } else {
                                            self.pc += 4;
                                        }
                                    }
                                    _ => todo!("{:#x}ret", funct12),
                                }
                            }
                            1 => {
                                // csrrw
                                let val2 = self.read_csr(imm);
                                self.write_csr(imm, val);

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }

                                if self.pending_exception.is_some() {
                                    return;
                                }

                                self.pc += 4;
                            }
                            2 => {
                                // csrrs
                                let val2 = self.read_csr(imm);
                                if rs1 != 0 {
                                    val |= val2;
                                    self.write_csr(imm, val);
                                }

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }

                                if self.pending_exception.is_some() {
                                    return;
                                }

                                self.pc += 4;
                            }
                            3 => {
                                // csrrc
                                let val2 = self.read_csr(imm);
                                if rs1 != 0 {
                                    val = val2 & !val;
                                    self.write_csr(imm, val);
                                }

                                if rd != 0 {
                                    self.regs[rd as usize] = val2;
                                }

                                if self.pending_exception.is_some() {
                                    return;
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
                        let imm = sext!(imm as i32, 11) as u32;
                        let val = self.pc + 4;
                        let target = self.regs[rs1 as usize].wrapping_add(imm);
                        self.pc = target;

                        if rd != 0 {
                            self.regs[rd as usize] = val;
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
                            let funct3 = (insn >> 12) & 7;
                            match funct3 {
                                0 => {
                                    // mul
                                    val = (val as u64 * val2 as u64) as u32;
                                }
                                1 => {
                                    // mulh
                                    val = ((val as i64 * val2 as i64) >> 32) as u32;
                                }
                                3 => {
                                    // mulhu
                                    val = ((val as u64 * val2 as u64) >> 32) as u32;
                                }
                                4 => {
                                    // div
                                    if val2 == 0 {
                                        val = (-1i32) as u32;
                                    } else if val == 0x80000000 && val2 == (-1i32) as u32 {
                                        val = val;
                                    } else {
                                        val = (val as i32 / val2 as i32) as u32;
                                    }
                                }
                                5 => {
                                    // divu
                                    if val2 == 0 {
                                        val = (-1i32) as u32;
                                    } else {
                                        val /= val2;
                                    }
                                }
                                6 => {
                                    // rem
                                    if val2 == 0 {
                                        val = val;
                                    } else if val == 0x80000000 && val2 == (-1i32) as u32 {
                                        val = 0;
                                    } else {
                                        val = (val as i32 % val2 as i32) as u32;
                                    }
                                }
                                7 => {
                                    // remu
                                    if val2 == 0 {
                                        val = val;
                                    } else {
                                        val %= val2;
                                    }
                                }
                                _ => todo!("mul {}", funct3),
                            }

                            if rd != 0 {
                                self.regs[rd as usize] = val;
                            }
                            self.pc += 4;
                        } else {
                            if (imm & !0x20) != 0 {
                                self.illegal_instruction();
                            }

                            let funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                            match funct3 {
                                0 => {
                                    val = val.wrapping_add(val2);
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
                                    val >>= val2 & 0x1f;
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
                                _ => self.die(&format!("funct3 {}", funct3)),
                                //_ => self.illegal_instruction(),
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

                        match funct3 {
                            // data width
                            2 => {
                                // amox.w
                                match funct5 {
                                    0 => {
                                        // amoadd.w
                                        if let Some(val) = self.read_u32(addr) {
                                            let val2 = self.regs[rs2 as usize];
                                            let res = val.wrapping_add(val2);
                                            self.write_u32(addr, res);
                                            if rd != 0 {
                                                self.regs[rd as usize] = val;
                                            }
                                        } else {
                                            return;
                                        }
                                    }
                                    1 => {
                                        // amoswap.w
                                        if let Some(val) = self.read_u32(addr) {
                                            let val2 = self.regs[rs2 as usize];
                                            self.write_u32(addr, val2);
                                            if rd != 0 {
                                                self.regs[rd as usize] = val;
                                            }
                                        } else {
                                            return;
                                        }

                                    }
                                    2 => {
                                        // lr.w
                                        if rs2 != 0 {
                                            self.die("illegal instruction");
                                        }

                                        if let Some(val) = self.read_u32(addr) {
                                            self.regs[rd as usize] = val;
                                            self.load_res = addr;
                                        } else {
                                            return;
                                        }
                                    }
                                    3 => {
                                        // sc.w
                                        if self.load_res == addr {
                                            if !self.write_u32(addr, self.regs[rs2 as usize]) {
                                                return;
                                            }
                                            
                                            if rd != 0 {
                                                self.regs[rd as usize] = 0;
                                            }
                                        } else {
                                            if rd != 0 {
                                                self.regs[rd as usize] = 1;
                                            }
                                        }
                                    }
                                    8 => {
                                        // amoor.w
                                        if let Some(val) = self.read_u32(addr) {
                                            let val2 = self.regs[rs2 as usize];
                                            let res = val | val2;
                                            self.write_u32(addr, res);
                                            if rd != 0 {
                                                self.regs[rd as usize] = val;
                                            }
                                        } else {
                                            return;
                                        }
                                    }
                                    12 => {
                                        // amoand.w
                                        if let Some(val) = self.read_u32(addr) {
                                            let val2 = self.regs[rs2 as usize];
                                            let res = val & val2;
                                            self.write_u32(addr, res);
                                            if rd != 0 {
                                                self.regs[rd as usize] = val;
                                            }
                                        } else {
                                            return;
                                        }
                                    }
                                    _ => unimplemented!("amoX.w {}", funct5),
                                }
                            }
                            _ => unimplemented!("amo width {}", funct5),
                        }

                        self.pc += 4;
                    }
                    0x1b => {
                        // OP-32
                        panic!("OP-32");
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

const PRIVL_NAMES: [&str; 4] = ["U", "S", "?", "M"];
const SATP_NAMES: [&str; 2] = ["BASE", "Sv32"];

impl std::fmt::Debug for RV32CPU {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CORE:")?;
        writeln!(f, "pc: {:#010x}", self.pc)?;
        if let Some(pc_phys) = self.get_phys_addr(self.pc) {
            writeln!(f, "pc_phys: {:#010x}", pc_phys)?;
        }
        writeln!(f, "privl: {}", PRIVL_NAMES[self.privl as usize])?;
        writeln!(f, "mstatus: {:#010x}", self.mstatus)?;
        writeln!(f, "mie: {:#010x} mip: {:#010x}", self.mie, self.mip)?;
        writeln!(f, "mtvec: {:#010x} stvec: {:#010x}", self.mtvec, self.stvec)?;
        writeln!(f, "mtimecmp: {:#018x} ({:#018x})", self.timecmp, Self::rtc_time())?;
        writeln!(
            f,
            "satp: {} {:#010x}",
            SATP_NAMES[(self.satp >> 31) as usize],
            self.satp << 12
        )?;

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

                mem.mem[offset..][..data.len()].copy_from_slice(data);
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

        Self { cpu }
    }

    fn run(&mut self) {
        self.cpu.run();
    }
}

fn main() {
    env_logger::init();

    let cfg = VMConfig {
        machine: VMMachineSpec::RV32,
        memory_mb: 128,
        bios_path: String::from("./configs/rv32-opensbi/fw_jump.bin"),
        kernel_path: String::from("./configs/rv32-opensbi/Image"),
        dtb_path: String::from("./configs/rv32-opensbi/riscvemu.dtb"),
        drive: String::from("/dev/null"),
    };

    let mut machine = VMMachine::from_config(&cfg);

    let mut killed = Arc::new(AtomicBool::new(false));
    let k2 = killed.clone();
    ctrlc::set_handler(move || {
        k2.store(true, Ordering::Relaxed);
    }).expect("setting Ctrl+C handler");

    loop {
        if killed.load(Ordering::Relaxed) {
            machine.cpu.die("stopped by signal");
        }

        machine.run();

        const MAX_SLEEP_TIME: u64 = 10000000; // [ns] = 10 ms

        let mut sleeptime = 0;
        let now = RV32CPU::rtc_time();
        if machine.cpu.mip & 0x80 == 0 {
            if now > machine.cpu.timecmp {
                machine.cpu.set_mip(0x80); // MIP
            } else if machine.cpu.power_down {
                sleeptime = machine.cpu.timecmp - now;
                sleeptime = sleeptime.max(MAX_SLEEP_TIME);

                debug!("power down for {}ns", sleeptime);
            }
        }

        if false && sleeptime > 0 {
            std::thread::sleep(std::time::Duration::from_nanos(sleeptime));
        }
    }
}
