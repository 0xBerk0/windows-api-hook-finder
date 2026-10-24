# HookFinder

HookFinder is a small Windows command-line utility that inspects the named exports of a module already loaded in its own process. It reports an export when its first byte is `0xE9`, the opcode for a near relative `JMP` instruction on x86/x64.

This is a narrow heuristic for spotting one possible inline-hook pattern. It is not a general-purpose hook detector and a reported jump is not, by itself, proof of malicious activity.

## Requirements

- Windows
- Microsoft Visual C (MSVC) and the Windows SDK

Build the program from a Visual Studio Developer Command Prompt:

```bat
cl /nologo /W4 HookFinder.c /Fe:hookfinder.exe
```

## Usage

```text
hookfinder.exe <target module>
```

For example, to inspect `ntdll.dll`:

```bat
hookfinder.exe ntdll.dll
```

The module must already be loaded in the HookFinder process. HookFinder uses `GetModuleHandleA`; it does not load the requested module itself. If the module is not loaded, the program prints an error and exits.

When it finds a matching export, it prints the export name and the first five bytes at its address.

## Limitations

- Only named exports are examined; exports available only by ordinal are not reported.
- Detection checks only whether the first byte is `0xE9`. Other jump encodings and hook techniques are not detected.
- A legitimate function can also begin with a relative jump, so results require context.
- The program does not validate the module's PE headers or export-table bounds before reading them.
- The scan is limited to the current process and does not inspect other processes.
