# ProcessDumper

A tool that dumps encrypted processes from memory. It watches pages in real-time, waits for them to get decrypted, and rebuilds a working PE file from the result. Works with stuff like Hyperion and Theia protected apps.

## How it works

1. A kernel driver reads memory from the target process
2. The page monitor watches for `NOACCESS` pages that become readable (= decrypted)
3. Once you're done waiting, it rebuilds the PE with fixed headers, imports, and sections
4. You get a clean `.exe` dump

## Features

- **Kernel driver memory access** — uses an IOCTL driver (mappable with KDmapper) so it works even when usermode handles get stripped by anti-cheats
- **Page decryption monitoring** — catches pages as they transition from encrypted to readable
- **Import resolution** — scans `.rdata` for exported function addresses, builds a new `.rimport` section with a proper IAT, and patches all `call`/`jmp` references
- **Exception directory cleanup** — removes broken `RUNTIME_FUNCTION` entries from the dump
- **Auto-stop threshold** — set a target like 50% and it stops automatically when enough pages are decrypted
- **Disk file fallback** — if a page can't be read from memory, it tries to grab it from the on-disk PE instead

## Usage

```
ProcessDumper.exe <process.exe> [-t threshold]
```

- `-t` — auto-stop at a certain decryption percentage. `0.5` = 50%, `1.0` = 100%. Without this, press **F7** to stop manually.

**Example:**
```
ProcessDumper.exe game.exe -t 0.5
```

## Building

- Open `ProcessDumper.sln` in Visual Studio
- Build both projects: `ProcessDumper` (usermode) and `IOCTL Driver` (kernel)
- Map the driver with [KDmapper](https://github.com/TheCruZ/kdmapper) before running the dumper

## Credits

- Import resolution, exception directory fixing, decryption threshold, and disk fallback features are inspired by [Vulkan](https://github.com/atrexus/vulkan) by [@atrexus](https://github.com/atrexus)

the ReadMe has been generated from claude opus4.6 since I am too lazy :)
