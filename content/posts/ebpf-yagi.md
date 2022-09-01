# Reversing eBPF using IDA

eBPF was introduced in the Linux Kernel to add powerful monitoring capabilities. It allow to quickly hook any syscall, or any kernel or user land function, to produce statistics, logs etc...
These eBPF programs are compiled in a particularly low-level machine code-named CO-RE (Compile Once - Run Everywhere)  executed by a virtual machine inside the Linux kernel.
eBPF is a RISC register machine with a total of eleven 64-bits registers, a program counter, and a 512 byte fixed-size stack. 9 registers are general purpose read-write, one is a read-only stack pointer and the program counter is implicit,
we can only jump to a certain offset from it. The eBPF registers are always 64-bits wide.

But you can't do what you want in an eBPF program. When you load an eBPF program, a checking step is performed, which is the target of most of the vulnerabilities on eBPF: For example, the checker will check arbitrary memory readings. To read memory in an eBPF program you need to use the helper function `bpf_probe_read` or `bpf_probe_read_user`.

Currently, there are 165 helper functions, used to perform a lot of different tasks.
For example, you can write userland memory using `bpf_probe_write_user`, or send a signal using `bpf_send_signal` to the current process, or `bpf_send_signal_thread` or for the current thread (Interesting to create new joke).

It's not surprising to see more and more security researchers using `eBPF` for offensive purposes:
- [bad-ebpf](https://github.com/pathtofile/bad-bpf) is a collection of `eBPF` programs to perform PID hide, process hijack ...
- [ebpfkit](https://github.com/Gui774ume/ebpfkit) is an entire rootkit implemented in `eBPF`
- [pamspy](https://github.com/citronneur/pamspy) is a credential stealer

All these programs rely on [libbpf](https://github.com/libbpf/libbpf). So we focused  on how to reverse `eBPF` program loaded by [libbpf](https://github.com/libbpf/libbpf), to know if it's malicious or not.

As we are users of IDA, we want to produce a simple way to produce C code from a program that uses [libbpf](https://github.com/libbpf/libbpf).

We used the last version of [pamspy](https://github.com/citronneur/pamspy/releases/tag/v0.2) as a source to reverse.

## Extracting eBPF code

eBPF programs handled by [libbpf](https://github.com/libbpf/libbpf) are compiled using `llvm` to produce an `ELF` binary.

The first thing is to find the ELF header (which can be easily obfuscated but it's not the purpose of this blog post):

[](/images/ebpf-yagi-1.png)

That's indeed an interesting function:

[](/images/ebpf-yagi-2.png)

This function initialises the *libbpf*'s structure to load the eBPF program: It declares its name, a pointer to ELF header, and the size of the program.

Here, we need to extract 4008 bytes to have the eBPF program.

Now we have our original `ELF` with `eBPF` bytecode inside.

## Disassemble eBPF

Unfortunately, IDA will fail to open in because it doesn't know the compiler ID `247`. In `IDA`, processor plugins are in charge to load new types of architecture. Fortunately for us, It exist an `IDA` processor for eBPF : [eBPF_processor](https://github.com/zandi/eBPF_processor). 
This is an up-to-date version of the one made by [Clément Berthaux ](https://github.com/saaph/eBPF_processor) for a challenge (I suppose for a SSTIC challenge ;-) ), with a lot of additions!

After loading this plugin, IDA will disassemble it perfectly using this new engine.

[](/images/ebpf-yagi-3.png)

## Decompile eBPF

The famous *Hex-Ray* decompiler is only available for a restricted set of processors while Ghidra decompiling engine supports a lot more. This is why we  developed [Yagi](https://github.com/airbus-cert/Yagi). 

Yagi is a an intgegration of the Ghidra decompiler in IDA. But Ghidra, in the main branch, doesn't support eBPF. But a security researcher implement the eBPF part for Ghidra : [eBPF-for-Ghidra](https://github.com/Nalen98/eBPF-for-Ghidra)

In [Yagi v1.5.0](https://github.com/airbus-cert/Yagi/releases/tag/v1.5.0) we added support for eBPF.

So after adding 165 *bpf* helpers signatures to help in the decompilation process, here is the result :

[](/images/ebpf-yagi-4.png)

Voila! Enjoy!

# Ref
 - https://github.com/Nalen98/eBPF-for-Ghidra
 - https://github.com/pathtofile/bad-bpf
 - https://github.com/Gui774ume/ebpfkit
 - https://github.com/citronneur/pamspy
 - https://github.com/zandi/eBPF_processor
 - https://blogs.blackberry.com/en/2021/12/reverse-engineering-ebpfkit-rootkit-with-blackberrys-free-ida-processor-tool
 
