using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MetaSploit.NET
{
    class Program
    {

        static void Main(string[] args)
        {
            byte[] ShellCode = new byte[/**/] {

            };

            Console.WriteLine("MetaSploit.NET Shell code executer");
            /*
             * Local Process
            */
            MetaSploit.Run(ShellCode, false, 0);
            /*
             * Testing Remote Process(x86)
            */
            //Process.Start(@"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe");
            //Process RemoteProcess = Process.GetProcessesByName("powershell")[0];
            //Console.WriteLine("RemoteProcess PID : {0}", RemoteProcess.Id);
            //MetaSploit.Run(ShellCode, true, RemoteProcess.Id);

        }
    }
}
