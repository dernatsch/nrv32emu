# nrv32emu - RISCV emulator

This project contains an emulator that currently only supports the RISC-V
32-bit architecture.
I wrote this as a learning project for myself, so it is not as performant as it
could be.

My goal is to get linux to boot and have a usable shell. I have not reached this
completely yet. The emulator can run the bootloader and starts booting linux but
fails before reaching userspace.
Currently I mostly test the project with Zephyr RTOS.

A lot of the ideas, structure and implementation details are taken from Fabrice
Bellards TinyEMU project.

## Usage

To run, simply use `cargo run`. This will load the zephyr image into RAM and
start executing.
