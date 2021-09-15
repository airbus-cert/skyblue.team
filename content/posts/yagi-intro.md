---
title: "Welcome Yagi, Yet Another Ghidra Integration for IDA"
date: 2021-09-15T08:31:46+02:00
draft: true
---

# TL;DR

Love IDA (Pro|Freeware) but can't afford the Hex-Rays decompiler?

- Head over to https://github.com/airbus-cert/Yagi/releases
- Download and install the plugin for your favourite architecture
- Run IDA, open a project and browse some assembly code
- Press F3
- Be amazed!

# Rationale

First and foremost, this project is made possible by [Ghidra](https://ghidra-sre.org/), the NSA's open-source reverse engineering framework that comes with a built-in disassembler.

Furthermore, Yagi would probably not exist without prior projects that inspired us and drove us to overcome limitations we encountered with them:

[GhIDA](https://github.com/Cisco-Talos/GhIDA) by Cisco's Talos team
- Uses the Python plugin interface exclusive to IDA Pro - so no compatibility with IDA Freeware
- Requires both IDA and Ghidra to be installed

[r2ghidra](https://github.com/radareorg/r2ghidra) by the Radare team
- Uses the cross-platform CMake build system
- Exclusive to radare2, no IDA

[blc](https://github.com/cseagle/blc) by Chris Eagle (someone who [knows their shit](https://nostarch.com/idapro2.htm))
- Uses the C++ plugin interface compatible with both IDA Freeware and IDA Pro
- Focuses on showing a decomplied view with no further integration

# Yagi features

Beyond the raw decompiler support, Yagi integrates the following elements:

- Maps global symbols from IDA to the decompiled view

- Supports editing stack and registry variables' names and types

# Under the hood

FIXME
