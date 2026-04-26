# EsetVM2

> A custom virtual machine engine that parses and executes `.EVM` bytecode files, with support for multi-processor and multi-threaded execution.

![multi-processor](https://img.shields.io/badge/multi--processor-supported-blue)
![multi-threaded](https://img.shields.io/badge/multi--threaded-supported-blue)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Multi-processor support** — A single VM instance can run multiple virtual processors simultaneously, enabling parallel workload distribution.
- **Multi-threaded execution** — The VM supports concurrent execution threads, allowing programs to leverage true parallelism.
- **Processor-per-thread architecture** — Each virtual processor is implemented as a dedicated OS thread, giving clean isolation and native OS-level scheduling.
- **`.EVM` file format** — Parses and executes a custom `.EVM` bytecode format, a purpose-built instruction set for this VM.

---

