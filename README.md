# Project Nighthawk: Advanced Defense Evasion via Custom Direct Syscall Reflection

## 🚨 Project Overview and Threat Model

Project Nighthawk is a technical Proof of Concept (PoC) demonstrating a highly stealthy payload execution and Command and Control (C2) implant loader, written in C#/.NET.

The tool is engineered specifically for advanced **Defense Evasion (T1574)** and designed to defeat sophisticated Endpoint Detection and Response (EDR) solutions.

The threat model targets EDR products that rely on two main detection strategies:

- **User-land API hooking**: Where EDR monitors security-sensitive Win32 functions (e.g., `VirtualAllocEx`)
- **Static file analysis**: Which requires the malicious payload to exist on disk

Nighthawk counters these defenses through two integrated techniques: **Dynamic Direct System Calls (Syscalls)** for kernel interaction and **Custom Reflective DLL Loading** for in-memory execution.

## ⚙️ Evasion Technique 1: Direct Syscalls Implementation

### Rationale for Hook Bypass

Standard malware executes sensitive operations by calling high-level Win32 APIs (e.g., functions within `kernel32.dll`). These functions typically contain user-land hooks inserted by EDR agents to inspect or block suspicious activity before execution.

Direct Syscalls bypass these defensive hooks by directly calling the Native NTDLL API functions (e.g., `ZwAllocateVirtualMemory`) and immediately executing the specialized `syscall` instruction to transition directly into kernel mode, thus circumventing the monitored user-land space entirely.

### Dynamic Syscall Number Resolution

A significant challenge in implementing Direct Syscalls is that the Syscall numbers (the identifiers used by the kernel) are volatile and can change across Windows versions or patch levels. Hardcoding these numbers often leads to instability or detection by security software monitoring this variance.

Project Nighthawk implements dynamic resolution to ensure portability and stealth. The loader inspects the exported functions of `ntdll.dll` in memory, specifically targeting the native `Zw*` or `Nt*` functions. By sorting these functions based on their memory addresses, the tool can infer the correct sequential syscall number, an approach similar to techniques used by threat actors like Halo's Gate. This dynamic technique ensures the loader maintains integrity and avoids detection based on incorrect or hardcoded syscall numbers.

### Key EDR Evasion: Windows API Mapping

| Standard Win32 API Call (Hooked) | Native API/Syscall Used (Bypass) | Purpose | Evasion Rationale |
|----------------------------------|-----------------------------------|---------|-------------------|
| `VirtualAllocEx` | `ZwAllocateVirtualMemory` | Memory Allocation (Injection target) | Bypasses user-land hooks |
| `WriteProcessMemory` | `ZwWriteVirtualMemory` | Payload Write | Direct kernel manipulation access |
| `CreateRemoteThreadEx` | `NtCreateThreadEx` | Payload Execution | Avoids creation of suspicious threads |

## 📦 Evasion Technique 2: Custom Reflective DLL Loading

### In-Memory Execution and Artifact Avoidance

Reflective DLL loading is defined as loading a DLL directly from memory rather than relying on the Windows operating system loader to load it from the file system. The payload, typically a malicious DLL implant, is stored in an encrypted state within the Nighthawk loader binary. Upon execution, it is decrypted and injected directly into the memory space of a legitimate target process (**T1055.002**) without generating any corresponding file artifact on disk (**T1070.004**).

The Nighthawk tool incorporates custom logic to manually execute the functions normally handled by the Windows OS loader. This custom loader logic performs:

- Mapping the DLL image into a newly allocated executable memory region using the stealthy `ZwAllocateVirtualMemory` syscall
- Performing necessary base relocation
- Manually resolving all imported functions (Import Address Table - IAT), completely circumventing the standard `LoadLibrary` call

Because the payload never resides on the file system, static analysis and file-based detection mechanisms are rendered ineffective.

## 📊 MITRE ATT&CK Evasion Mapping

This project demonstrates the following techniques:

| Technique ID | Technique Name | Evasion Strategy | Adversary Tradecraft |
|-------------|----------------|------------------|---------------------|
| T1055.002 | Process Injection: Portable Executable Injection | Reflective DLL Loading using Syscalls | In-memory payload execution, no disk artifact |
| T1070.004 | File Deletion | Encrypted payload held in memory | Avoids file system detection mechanisms |
| T1070.006 | Indicator Removal on Host | Custom memory region setup | Avoids suspicious thread creation/start addresses |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Direct Syscall implementation | Bypassing user-land API hooks |

---

## 🛡️ Defense Considerations

> **Note for Blue Teams**: This technique demonstrates why monitoring for suspicious process behavior and memory anomalies is more effective than relying solely on API hooking for detection.

## 📁 Project Structure
