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
struct RV32CPU {
    mem: VMMemory,
    pc: u32,
    regs: [u32; 32],
}

impl RV32CPU {
    fn new() -> Self {
        Self {
            mem: VMMemory::new(),
            pc: 0x1000,
            regs: [0u32; 32],
        }
    }
    fn run(&mut self) {
        panic!("Don't know how to continue. Core:\n{:x?}", self);
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result<> {
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
        let fdt_base = 0x1000 + 8*8;


        let mut trampoline: Vec<u8> = Vec::new();
        trampoline.put_u32_le(0x297 + 0x80000000 - 0x1000);
        trampoline.put_u32_le(0x597);
        trampoline.put_u32_le(0x58593 + ((fdt_base-4) << 20));
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
