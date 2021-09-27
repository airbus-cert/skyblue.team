---
title: "Welcome Yagi, Yet Another Ghidra Integration for IDA"
date: 2021-09-15T08:31:46+02:00
draft: true
---

# TL;DR

Love IDA (Pro|Freeware) and want more decompiled code?

- Head over to https://github.com/airbus-cert/Yagi/releases
- Download and install the plugin for your favorite architecture
- Run IDA, open a project, and browse some assembly code
- Press F3
- Be amazed!

# Rationale

Reverse engineering is an important task for every blue team, and the essential tool is a decompiler. A decompiler is a complex piece of software that tries to perform the way back of a compiler. He tries to go back to high-level source code (C, Java, etc…) from a binary file.

A lot of languages have a dedicated decompiler because on the contrary to languages like C, C++, or Rust, that sometimes called low-level languages, modern programming languages, like C# or Java, are based on an intermediate language that keeps a lot of semantics. This is why they are very easy to decompile.

But in the case of languages like C, C++, or Rust, the compiler step will make a lot of optimization that will remove most of the original semantics. Here we need a very powerful decompiler and the three most advanced are:

- [IDA](https://hex-rays.com/)
- [Ghidra](https://ghidra-sre.org/)
- [Radare2](https://github.com/radareorg/radare2)

Furthermore, Yagi would probably not exist without prior projects that inspired us and drove us to overcome limitations we encountered with them:

[GhIDA](https://github.com/Cisco-Talos/GhIDA) by Cisco's Talos team
- Uses the Python plugin interface exclusive to IDA Pro - so no compatibility with IDA Freeware
- Requires both IDA and Ghidra to be installed

[r2ghidra](https://github.com/radareorg/r2ghidra) by the Radare team
- Uses the cross-platform CMake build system
- Exclusive to radare2, no IDA

[blc](https://github.com/cseagle/blc) by Chris Eagle (someone who [knows their shit](https://nostarch.com/idapro2.htm))
- Uses the C++ plugin interface compatible with both IDA Freeware and IDA Pro
- Focuses on showing a decompiled view with no further integration

All decompilers have the same architecture, that can be split into two, the analysis part and the proper decompiler part.

# What is included in the analysis part?

To perform a good analysis, we need to merge information from every part of the binary. So we need a good binary file parser at the first step.
From the binary file, we can extract the compiler type, which is deducted from the [RICH header](http://bytepointer.com/articles/the_microsoft_rich_header.htm) in the case of Windows Binaries. 
We can also find where the code, the data, etc… are. We can also detect the kind of assembly (x86, x86_64 …)

One of the important parts of decompilation is the type inference, a step that will try to guess the type of local variable, by grabbing information from many places. 
This kind of information can be found by looking at the import section of the binary file. Import functions are all functions that are used in the binary but not included in it. 
In software programming, we refer to it as a library. As these functions are publicly available we can know the type of input parameters. 

We can also build our type inference on symbols when they are present. 
Symbols are meta information that can be present in binary and can inform us about the function name, type, source code, etc...

Once we grab all this information we can start to analyze the code itself, by performing the translation from binary to assembly language. 
Some assembly instructions, like call and branch, are related to the control flow, to build the associated control flow graph.
But compared with a C source the CFG is not easily readable, this is why modern decompiler software proposes a translation from CFG to C source code.

Unfortunately, all this work can’t be made automatically, and the analyst, by its experience, has to add more context, by setting types, names, using static or dynamic analysis. 
This is why all modern decompiler software offers a robust database service.

# What is included in the decompilation part?

The main goal is to produce a comprehensive source code to facilitate the work of the analyst. 
The first work is to detect code structure from the CFG. 
With a mix of graph theory, we can easily match some code patterns, like if-else block, for or while loop, etc… 
All these techniques come from the thesis [Reverse Compilation Techniques](https://yurichev.com/mirrors/DCC_decompilation_thesis.pdf) by Cristina Cifuntes.

Once we get a macro view of our code, we have to find all local variables, including the function parameters.

To achieve it, most decompiler software transforms the code into [SSA (Static Single Assignment)](https://www.cs.utexas.edu/~pingali/CS380C/2010/papers/ssaCytron.pdf) form. This form is useful to perform dead code detection, constant propagation, and local variable computation.

# How are the Ghidra and IDA decomposed?

IDA split these two-part into as follows:
- The analysis part is the main software name IDA Pro (or IDA freeware and more recently IDA Home). IDA Pro supports a lot of architecture. IDA pro includes a very powerful plugin API.
- The decompiler is a plugin named Hex-Rays and sold in a commercial bundle. The decompiler only supports the most common architecture.

Ghidra is not commercial, but have the same software architecture:
- The analysis part is written in Java
- The decompiler part is written in C++

# Why Yagi?

At $WORK we use IDA and the Hex-Rays plugin, but sometimes we have to deal with exotic architecture not supported by the Hex-Rays plugin. 
So we had the idea to put the Ghidra decompiler and create an IDA plugin that will integrate it into our favorite decompiler.

And *Yagi (Yet Another Ghidra Integration)* is born. 

There have been some other attempts before, but not as seamless as we want.

# How does it work?

As Ghidra is built using Gradle, we chose to use CMake combined with the git submodule on the Ghidra repository, to control all our built systems. 
As our plugin is written in C++, CMake appears to be the best choice. CMake also includes CPack, with the help of Wix, can generate an easy-to-use installer!

From a software engineering perspective, It appears that we need to segregate between the code of IDA and Ghidra, due to type redefinition nightmare.
For IDA developers int8 means 8 bits, but for Ghidra developers int8 means 8 bytes… 

!(same but different)[https://media.giphy.com/media/UI7EYk96rzq24/giphy.gif]

In the end, this architecture helped during unit test writing.

We need to deeply understand the code of Ghidra and properly handle the IDA API. 
Both of them are masterpieces of software engineering, so It was easy to find the perfect place.

# All is about scope…

In Ghidra, during decompilation, it uses a Scope object to request the symbol database. 
The first work in Yagi was to implement the Scope interface to request the IDA database. 
We also did a mapping between the type definition between Ghidra and IDA. 
It was pretty easy, but I needed to understand when to lock a type, put a read-only attribute on varnode, etc… 

# How to print the exact output of Hex-Rays plugin?

One of the main interests of decompilation is to quickly identify the type of symbol, like import function, global variables, local variables, type, cast, etc… IDA uses a very famous syntax color for its decompilation. 
So we found a way to output the Ghidra decompilation by using the very flexible Ghidra and IDA API. 
Ghidra allows you to define a new output language. 
This Object class is called EmitPrettyPrint. 
This object can be viewed as a visitor pattern for the decompilation tree. 
So we just override a set of functions to emit meta char that will be used by the IDA viewer as a color tag.

But having only the static result of decompilation is not enough for any reverse engineer. 
We need to interact with the code, navigate, find cross-references, rename symbols, retype symbols. 
As a final step of the decompilation, we used the internal of Ghidra to find the calling functions. 
We used the internal variable tree (also known as Varnode in the Ghidra world) to find local and global variables. 
We can also determine the address of the symbol, where the variable is defined (the use address which refers to an assembly address). 
With all this information we can easily request the IDA database to jump, Xref, or retype global symbols.

# What about local variables?

Local variables are the result of the decompilation and could be unknown by IDA database. 
The stack variable could match between the two algorithms, actually, it’s true in most cases, so the work was easy, and we used a lot of *Action* systems in Ghidra.

Ghidra internally uses the "Entity Component System" (ECS) pattern. 
This pattern has become more and more famous, in particular in the video game industry. 
ECS is very flexible. If you want to see a beautiful implementation of ECS in Rust It’s [here](https://github.com/amethyst/specs). 
Here the decompiled function can be viewed as an entity, each tree is like a component, and Actions are systems. 
Systems must be ordered because some of them can have dependencies. 

We built most of our interaction with local variables using *Action*. 
We’ve added Actions for retyping and renaming.

Retyping will populate the local scope with a symbol that will have a type lock attribute. 
It means that the associate variable will have a type that can’t change during type inference, and maybe will influence other non-type locked variables.

Renaming action takes place after all action was done, by renaming symbols.

And magic happened!

# What’s next?

We planned to add more architecture supported by Yagi. 
We also start to think about using Ghidra more in a dynamic way (emulation, other output languages …). 
Ghidra offers a lot of features that can be easily included in IDA through the API!



