# Reversing eBPF using IDA

For our short blog post, we will take as a sample the eBPF credential stealer [pamspy](https://github.com/citronneur/pamspy)

`pamspy` rely on [libbpf](https://github.com/libbpf/libbpf) to load the ebpf program.
The programs handled by libbpf are compiled using llvm. This pipeline is also used by many eBPF malicious programs like [bad-ebpf](https://github.com/pathtofile/bad-bpf) or [ebpfkit](https://github.com/Gui774ume/ebpfkit).

So the first thing is to find a clear reference to the ELF header (which can be easily obfuscated but it's not the purpose of this blog post) :

[](/images/ebpf-yagi-1.png)

So we found an interesting function :

[](/images/ebpf-yagi-2.png)

This function is in charge to set the correct structure of the libbpf to load the ebpf program. It set the name, a pointer to ELF header, and the size of the ELF.

We just need to extract 4008 bytes to have the eBPF program.

If we want to open it in IDA, It will fail because it doesn't know the compiler id 247.
To load eBPF program we found a very great blog post from [Blackberry](https://blogs.blackberry.com/en/2021/12/reverse-engineering-ebpfkit-rootkit-with-blackberrys-free-ida-processor-tool) security team which explain in details how to load an eBPF program into IDA.

It's based on a [processor](https://github.com/saaph/eBPF_processor) written by Clément Berthaux for a challenge (I suppose for a SSTIC challenge ;-) ), with a lot of adding!

Once we have our eBPF program loaded into IDA, it can decompile it. But we found that a security researcher implements it for [Ghidra](https://github.com/Nalen98/eBPF-for-Ghidra).
So we decided to include it in Yagi v1.5.0.

So after adding 165 bpf helpers signatures to improve decompilation, and some of them are very interesting, here is the result :

[](/images/ebpf-yagi-3.png)

Enjoy !

# Ref
 - https://github.com/Nalen98/eBPF-for-Ghidra
 - https://blogs.blackberry.com/en/2021/12/reverse-engineering-ebpfkit-rootkit-with-blackberrys-free-ida-processor-tool