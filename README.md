# Windows 1.0 Executable IDA Fix
IDA Python script to fix various Windows 1.0 executables to load properly in IDA Pro. IDA sometimes attempts to disassemble 16-bit segments as 32-bit ones.

Make sure you back your files up first, as it writes directly to the executable, without making a backup. The patched executable might still run, but not tested.

**Before:**
![Before](https://raw.githubusercontent.com/LucasBrooks/Windows-1.0-Executable-IDA-Fix/main/pictures/before.png)

**After:**
![Before](https://raw.githubusercontent.com/LucasBrooks/Windows-1.0-Executable-IDA-Fix/main/pictures/after.png)
