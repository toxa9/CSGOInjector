using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CSGOInjector
{
    public static class VACBypass
    {
        private static List<FuncDLL> _functions = new List<FuncDLL>()
        {
            new FuncDLL("LoadLibraryExW", "kernel32"),
            new FuncDLL("VirtualAlloc", "kernel32"),
            new FuncDLL("FreeLibrary", "kernel32"),
            new FuncDLL("LoadLibraryExA", "kernel32"),
            new FuncDLL("LoadLibraryW", "kernel32"),
            new FuncDLL("LoadLibraryA", "kernel32"),
            new FuncDLL("VirtualAllocEx", "kernel32"),
            new FuncDLL("LdrLoadDll", "ntdll"),
            new FuncDLL("NtOpenFile", "ntdll"),
            new FuncDLL("VirtualProtect", "kernel32"),
            new FuncDLL("CreateProcessW", "kernel32"),
            new FuncDLL("CreateProcessA", "kernel32"),
            new FuncDLL("VirtualProtectEx", "kernel32"),
            new FuncDLL("FreeLibrary", "KernelBase"),
            new FuncDLL("LoadLibraryExA", "KernelBase"),
            new FuncDLL("LoadLibraryExW", "KernelBase"),
            new FuncDLL("ResumeThread", "KernelBase")
        };

        private static byte[,] originalBytes;
        private static IntPtr hGame = IntPtr.Zero;
        private static UInt32 pid = UInt32.MinValue;

        public static bool Run(string pathToDLL)
        {
            Init();

            pid = GetGamePID();

            if (pid == UInt32.MinValue)
            {
                throw new ApplicationException("The game was not found.");
            }

            hGame = OpenProcess(ProcessAccessFlags.All, false, (int)pid);

            if (hGame == IntPtr.Zero)
            {
                throw new ApplicationException("Failed to open process.");
            }

            BypassCSGOHook();
            InjectDLL(pathToDLL);
            RestoreCSGOHook();

            return true;
        }

        private static void Init()
        {
            originalBytes = new byte[17, 6];
            hGame = IntPtr.Zero;
            pid = UInt32.MinValue;
        }

        private static void InjectDLL(string path)
        {
            IntPtr handle = OpenProcess(ProcessAccessFlags.All, false, (Int32)pid);

            if (handle == IntPtr.Zero)
            {
                throw new ApplicationException("Failed to open process.");
            }

            IntPtr size = (IntPtr)path.Length;

            IntPtr DLLMemory = VirtualAllocEx(handle, IntPtr.Zero, size, AllocationType.Reserve | AllocationType.Commit,
                MemoryProtection.ExecuteReadWrite);

            if (DLLMemory == IntPtr.Zero)
            {
                throw new ApplicationException("Memory allocation error.");
            }

            byte[] bytes = Encoding.ASCII.GetBytes(path);

            if (!WriteProcessMemory(handle, DLLMemory, bytes, (int)bytes.Length, out _))
            {
                throw new ApplicationException("Memory read error");
            }

            IntPtr kernel32Handle = GetModuleHandle("Kernel32.dll");
            IntPtr loadLibraryAAddress = GetProcAddress(kernel32Handle, "LoadLibraryA");

            if (loadLibraryAAddress == IntPtr.Zero)
            {
                throw new ApplicationException("Failed to load LoadLibraryA.");
            }

            IntPtr threadHandle = CreateRemoteThread(handle, IntPtr.Zero, 0, loadLibraryAAddress, DLLMemory, 0, 
                IntPtr.Zero);

            if (threadHandle == IntPtr.Zero)
            {
                throw new ApplicationException("Failed to create thread.");
            }

            CloseHandle(threadHandle);
            CloseHandle(handle);
        }

        private static UInt32 GetGamePID()
        {
            UInt32 ret = UInt32.MinValue;
            Process[] proc = Process.GetProcessesByName("csgo");

            if (proc.Length == 0)
            {
                return ret;
            }

            IntPtr hwGame = proc[0].MainWindowHandle;

            if (hwGame == IntPtr.Zero)
            {
                return ret;
            }

            GetWindowThreadProcessId(hwGame, out ret);

            return ret;
        }

        private static void BypassCSGOHook()
        {
            for (int i = 0; i < _functions.Count; i++)
            {
                if (!Unhook(_functions[i].MethodName, _functions[i].DLLName, i))
                {
                    throw new ApplicationException($"Failed unhook {_functions[i].MethodName} in {_functions[i].DLLName}.");
                }
            }
        }

        private static void RestoreCSGOHook()
        {
            for (int i = 0; i < _functions.Count; i++)
            {
                if (!RestoreHook(_functions[i].MethodName, _functions[i].DLLName, i))
                {
                    throw new ApplicationException($"Failed restore {_functions[i].MethodName} in {_functions[i].DLLName}.");
                }
            }
        }

        private static bool Unhook(string methodName, string dllName, Int32 index)
        {
            IntPtr originalMethodAddress = GetProcAddress(LoadLibrary(dllName), methodName);

            if (originalMethodAddress == IntPtr.Zero)
            {
                throw new ApplicationException($"The {methodName} address in {dllName} is zero.");
            }

            byte[] originalGameBytes = new byte[6];

            ReadProcessMemory(hGame, originalMethodAddress, originalGameBytes, sizeof(byte) * 6, out _);

            for (int i = 0; i < originalGameBytes.Length; i++)
            {
                originalBytes[index, i] = originalGameBytes[i];
            }

            byte[] originalDLLBytes = new byte[6];

            GCHandle pinnedArray = GCHandle.Alloc(originalDLLBytes, GCHandleType.Pinned);
            IntPtr originalDLLBytesPointer = pinnedArray.AddrOfPinnedObject();

            memcpy(originalDLLBytesPointer, originalMethodAddress, (UIntPtr)(sizeof(byte) * 6));

            return WriteProcessMemory(hGame, originalMethodAddress, originalDLLBytes, sizeof(byte) * 6, out _);
        }

        private static bool RestoreHook(string methodName, string dllName, Int32 index)
        {
            IntPtr originalMethodAdress = GetProcAddress(LoadLibrary(dllName), methodName);

            if (originalMethodAdress == IntPtr.Zero)
            {
                return false;
            }

            byte[] origBytes = new byte[6];

            for (int i = 0; i < origBytes.Length; i++)
            {
                origBytes[i] = originalBytes[index, i];
            }

            return WriteProcessMemory(hGame, originalMethodAdress, origBytes, sizeof(byte) * 6, out _);
        }

        private class FuncDLL
        {
            public string MethodName { get; set; }
            public string DLLName { get; set; }

            public FuncDLL(string methodName, string dllName)
            {
                MethodName = methodName;
                DLLName = dllName;
            }
        }

        #region Win32 DLL Enum

        private const UInt32 INFINITY = 0xFFFFFFFF;

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


        #endregion

        #region Win32 DLL import

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UIntPtr count);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
            int dwSize, AllocationType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        #endregion

    }
}
