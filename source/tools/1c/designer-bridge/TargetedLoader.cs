// Targeted adapter for the official Core.As 1.0.2.4 x86 inject.dll.
// Only the loader's own import slot is temporarily redirected. No on-disk DLL
// or target process memory is patched. Never invoke inject_hook unguarded.
using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Threading;

public sealed class TargetedLoader : IDisposable {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct StartupInfo {
        public int cb; public string reserved, desktop, title;
        public int x,y,cx,cy,xCount,yCount,fill,flags;
        public short show, reservedBytes; public IntPtr reservedPtr, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr SetHook(int kind, IntPtr callback, IntPtr instance, uint threadId);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void HookEntry();
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcess(string app, StringBuilder command, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr environment, string cwd, ref StartupInfo si, out ProcessInfo pi);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetModuleFileName(IntPtr module, StringBuilder path, int size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool GetModuleHandleEx(uint flags, IntPtr address, out IntPtr module);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint protect, out uint previous);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint GetProcessIdOfThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,
        out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr SetWindowsHookEx(int kind, IntPtr callback, IntPtr instance, uint threadId);
    [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr hook);

    IntPtr library, hook;
    ProcessInfo child;
    MemoryMappedFile mapping;
    SetHook redirect;
    int intercepted;
    int hookError;
    int initialHookError;
    int hookAttempts;
    string hookGuard="not-called";
    bool resumed;
    bool stopped=true;
    string creationFileTimeUtc;
    string loadedModulePath;
    bool callbackInLoadedModule;
    public uint ProcessId { get { return child.pid; } }
    public string ProcessCreationFileTimeUtc { get { return creationFileTimeUtc; } }
    public bool ProcessStopped { get { return stopped; } }
    public bool OriginalProcessExited { get { return child.process!=IntPtr.Zero && WaitForSingleObject(child.process,0)==0; } }
    public uint ThreadId { get { return child.tid; } }
    public int InterceptedCalls { get { return intercepted; } }
    public string LoadedModulePath { get { return loadedModulePath; } }
    public bool CallbackInLoadedModule { get { return callbackInLoadedModule; } }
    public int HookError { get { return hookError; } }
    public int InitialHookError { get { return initialHookError; } }
    public int HookAttempts { get { return hookAttempts; } }

    static void Require(bool value, string code) { if (!value) throw new InvalidOperationException(code); }
    static uint U32(IntPtr p, int offset) { return unchecked((uint)Marshal.ReadInt32(p, offset)); }
    static IntPtr At(IntPtr p, uint offset) { return new IntPtr(p.ToInt64() + offset); }

    // Parse the PE32 import table rather than guessing an instruction offset.
    static IntPtr HookImport(IntPtr image) {
        Require(Marshal.ReadInt16(image) == 0x5a4d, "NOT_PE");
        int nt = Marshal.ReadInt32(image, 0x3c);
        Require(Marshal.ReadInt32(image, nt) == 0x4550 && Marshal.ReadInt16(image, nt+24) == 0x10b, "NOT_PE32");
        uint size = U32(image, nt+24+56), imports = U32(image, nt+24+104);
        Require(imports > 0 && imports + 20 < size, "IMPORT_TABLE_MISSING");
        for (uint d = imports; d + 20 < size && U32(image, (int)d+12) != 0; d += 20) {
            uint name = U32(image, (int)d+12), names = U32(image, (int)d), slots = U32(image, (int)d+16);
            Require(name < size && names > 0 && slots > 0, "IMPORT_BOUNDS");
            if (!String.Equals(Marshal.PtrToStringAnsi(At(image,name)), "USER32.dll", StringComparison.OrdinalIgnoreCase)) continue;
            for (uint j=0; names+j+4<size && slots+j+4<size; j+=4) {
                uint entry=U32(image,(int)(names+j)); if(entry==0) break;
                if ((entry & 0x80000000)!=0) continue;
                Require(entry+2<size,"IMPORT_NAME_BOUNDS");
                if (Marshal.PtrToStringAnsi(At(image,entry+2))=="SetWindowsHookExW") return At(image,slots+j);
            }
        }
        throw new InvalidOperationException("SET_HOOK_IMPORT_MISSING");
    }

    static uint WriteString(MemoryStream stream, string text, bool unicode) {
        uint at=(uint)stream.Position;
        byte[] data=(unicode ? Encoding.Unicode : Encoding.ASCII).GetBytes(text+"\0");
        stream.Write(data,0,data.Length);
        if ((stream.Position & 1)!=0) stream.WriteByte(0);
        return at;
    }
    void CreateMap(string module, string processName, bool native1c) {
        // CreateNew refuses an existing official starter/another loader; never overwrite it.
        mapping=MemoryMappedFile.CreateNew("CoreAsStarterList",4096);
        using(var stream=new MemoryStream()) {
            stream.SetLength(40); stream.Position=40;
            uint name=WriteString(stream,module,true), proc=WriteString(stream,processName,true);
            uint test=0, func=0;
            if(native1c) { test=WriteString(stream,"test.dll",true); func=WriteString(stream,"isNeedLoad",false); }
            uint length=(uint)stream.Length; stream.Position=0;
            using(var writer=new BinaryWriter(stream)) {
                writer.Write(length); writer.Write((uint)0); writer.Write((uint)1);
                writer.Write(name); writer.Write((uint)1); writer.Write(proc);
                writer.Write(test); writer.Write(func); writer.Write((uint)0); writer.Write((uint)0);
                using(var view=mapping.CreateViewStream()) { var bytes=stream.ToArray(); view.Write(bytes,0,bytes.Length); }
            }
        }
    }

    IntPtr InstallTargeted(int kind, IntPtr callback, IntPtr instance, uint requestedThread) {
        // This delegate must never throw across the unmanaged boundary.
        intercepted++;
        if(intercepted!=1 || kind!=5 || callback==IntPtr.Zero || instance!=library ||
            requestedThread!=0 || child.tid==0 || child.pid==0 || GetProcessIdOfThread(child.thread)!=child.pid)
            { hookGuard="rejected"; return IntPtr.Zero; }
        hookGuard="accepted";
        IntPtr callbackModule;
        callbackInLoadedModule=GetModuleHandleEx(6,callback,out callbackModule) && callbackModule==library;
        if(!callbackInLoadedModule) { hookGuard="callback-module-rejected"; return IntPtr.Zero; }
        hookAttempts++;
        hook=SetWindowsHookEx(kind,callback,instance,child.tid);
        if(hook==IntPtr.Zero) hookError=Marshal.GetLastWin32Error();
        initialHookError=hookError;
        // A suspended GUI target can reject the initial hook with 87.
        // Error 126 persisted in independent native controls; do not retry it.
        // Resume only our child and retry this exact TID within the same bound;
        // there is deliberately no fallback to a desktop-wide hook.
        if(hook==IntPtr.Zero && hookError==87) {
            if(ResumeThread(child.thread)==0xffffffff) return IntPtr.Zero;
            resumed=true;
            var watch=Stopwatch.StartNew();
            while(hook==IntPtr.Zero && watch.ElapsedMilliseconds<5000 && WaitForSingleObject(child.process,0)==258
                && GetProcessIdOfThread(child.thread)==child.pid) {
                Thread.Sleep(1);
                hookAttempts++;
                hook=SetWindowsHookEx(kind,callback,instance,child.tid);
                if(hook==IntPtr.Zero) { hookError=Marshal.GetLastWin32Error(); if(hookError!=87) break; }
            }
        }
        if(hook!=IntPtr.Zero) hookError=0;
        return hook;
    }

    public void Start(string executable, string arguments, string runtime, bool native1c) {
        Require(IntPtr.Size==4,"X86_LOADER_REQUIRED");
        Require(child.pid==0 && library==IntPtr.Zero,"ONE_PROCESS_ONLY");
        string file=Path.GetFileName(executable);
        Require(Path.IsPathRooted(executable) && File.Exists(executable),"EXECUTABLE_MISSING");
        Require(native1c ? file.Equals("1cv8.exe",StringComparison.OrdinalIgnoreCase) : file=="AHBridgeProbeHost.exe","UNEXPECTED_TARGET");
        try {
            CreateMap(native1c ? "Snegopat" : "AHBridgeProbe",file,native1c);
            library=LoadLibrary(Path.Combine(runtime,"lib/x86/inject.dll"));
            Require(library!=IntPtr.Zero,"LOAD_INJECT_FAILED");
            var moduleName=new StringBuilder(32768);
            uint moduleNameLength=GetModuleFileName(library,moduleName,moduleName.Capacity);
            Require(moduleNameLength>0 && moduleNameLength<moduleName.Capacity,"MODULE_PATH_REJECTED");
            loadedModulePath=moduleName.ToString();
            var entry=GetProcAddress(library,"?inject_hook@@YAXXZ");
            Require(entry!=IntPtr.Zero,"HOOK_EXPORT_MISSING");
            IntPtr slot=HookImport(library), original=Marshal.ReadIntPtr(slot);
            var si=new StartupInfo(); si.cb=Marshal.SizeOf(si); si.flags=1; si.show=0;
            // Own the child before installing the hook. If Windows needs the GUI
            // thread to initialize first, InstallTargeted handles that bounded race.
            Require(CreateProcess(executable,new StringBuilder("\""+executable+"\" "+arguments),
                IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,Path.GetDirectoryName(executable),ref si,out child),"CREATE_PROCESS_FAILED");
            stopped=false;
            long created, exited, kernelTime, userTime;
            Require(GetProcessTimes(child.process,out created,out exited,out kernelTime,out userTime),"PROCESS_IDENTITY_FAILED");
            creationFileTimeUtc=created.ToString("x16");
            redirect=new SetHook(InstallTargeted);
            uint old;
            Require(VirtualProtect(slot,(UIntPtr)4,0x04,out old),"IMPORT_PROTECT_FAILED");
            try {
                Marshal.WriteIntPtr(slot,Marshal.GetFunctionPointerForDelegate(redirect));
                ((HookEntry)Marshal.GetDelegateForFunctionPointer(entry,typeof(HookEntry)))();
            } finally {
                Marshal.WriteIntPtr(slot,original);
                uint ignored; Require(VirtualProtect(slot,(UIntPtr)4,old,out ignored),"IMPORT_RESTORE_FAILED");
                GC.KeepAlive(redirect);
            }
            Require(intercepted==1 && hook!=IntPtr.Zero,"TARGET_HOOK_FAILED:"+hookGuard+":"+intercepted+":"+hookError);
            if(!resumed) Require(ResumeThread(child.thread)!=0xffffffff,"RESUME_FAILED");
        } catch { Dispose(); throw; }
    }

    // The trial owns this child. Disposing always stops it before releasing the
    // hook/module/map; there is no unattended injected process after the probe.
    public void Dispose() {
        if(child.process!=IntPtr.Zero) {
            if(WaitForSingleObject(child.process,0)!=0) { TerminateProcess(child.process,1); WaitForSingleObject(child.process,5000); }
            stopped=WaitForSingleObject(child.process,0)==0;
            // Keep handles and the injected runtime if termination is unknown.
            // A subsequent PID-only lookup cannot substitute for this handle.
            if(!stopped) return;
            CloseHandle(child.process); child.process=IntPtr.Zero;
        }
        if(hook!=IntPtr.Zero) { UnhookWindowsHookEx(hook); hook=IntPtr.Zero; }
        if(child.thread!=IntPtr.Zero) { CloseHandle(child.thread); child.thread=IntPtr.Zero; }
        if(library!=IntPtr.Zero) { FreeLibrary(library); library=IntPtr.Zero; }
        if(mapping!=null) { mapping.Dispose(); mapping=null; }
        GC.KeepAlive(redirect);
    }
}
