# nrv32emu - RISCV emulator

This project contains an emulator that currently only supports the RISC-V
32-bit architecture.
I wrote this as a learning project for myself, so it is not as performant as it
could be.

My goal would be to get linux to boot and have a usable shell. I have not
reached this yet, but I tested the program with some examples that are included
in the Zephyr RTOS.

A lot of the ideas, structure and implementation details are taken from Fabrice
Bellards TinyEMU project.

## Usage

To run, simply use `cargo run`. This will load the zephyr image into RAM and
start executing.
