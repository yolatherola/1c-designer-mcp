// Own Gold startup only; caller keeps protected arguments inside its process.
// Remote writes are confined to its two new private pathname/binding blocks.
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

public sealed class OwnedGoldLoaderV43 : IDisposable {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI {
  public int cb;public string reserved,desktop,title;
  public int x,y,cx,cy,xc,yc,fill,flags;public short show,reservedBytes;
  public IntPtr reservedPtr,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)] struct PI {public IntPtr process,thread;public uint pid,tid;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct ME {
  public uint size,moduleID,pid,globalUses,processUses;public IntPtr baseAddress;
  public uint baseSize;public IntPtr module;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string name;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string path;
 }
 [StructLayout(LayoutKind.Sequential)] struct Binding {public uint pid,tid,birthLow,birthHigh,version,fixture;}
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SI si,out PI pi);
 [DllImport("kernel32",SetLastError=true)] static extern bool GetProcessTimes(IntPtr p,out long born,out long exit,out long kernel,out long user);
 [DllImport("kernel32")] static extern uint GetProcessIdOfThread(IntPtr thread);
 [DllImport("kernel32")] static extern uint GetCurrentThreadId();
 [DllImport("kernel32",SetLastError=true)] static extern bool IsWow64Process2(IntPtr p,out ushort machine,out ushort native);
 [DllImport("kernel32")] static extern uint ResumeThread(IntPtr t);
 [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32")] static extern bool TerminateProcess(IntPtr p,uint code);
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibrary(string path);
 [DllImport("kernel32",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
 [DllImport("kernel32",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr m,string n);
 [DllImport("kernel32",CharSet=CharSet.Unicode)] static extern bool GetModuleHandleEx(uint flags,IntPtr address,out IntPtr module);
 [DllImport("kernel32",CharSet=CharSet.Unicode)] static extern uint GetModuleFileName(IntPtr m,StringBuilder path,int size);
 [DllImport("kernel32")] static extern bool FreeLibrary(IntPtr m);
 [DllImport("kernel32",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Module32First(IntPtr snapshot,ref ME entry);
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Module32Next(IntPtr snapshot,ref ME entry);
 [DllImport("kernel32",SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr p,IntPtr address,UIntPtr size,uint kind,uint protection);
 [DllImport("kernel32",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr p,IntPtr address,byte[] data,UIntPtr size,out UIntPtr written);
 [DllImport("kernel32",SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr p,IntPtr attr,UIntPtr stack,IntPtr start,IntPtr parameter,uint flags,IntPtr tid);
 [DllImport("kernel32")] static extern bool GetExitCodeThread(IntPtr t,out uint code);
 PI child;long born;IntPtr localDll;string directory;
 string phase="scope";
 void Mark(string value){
  phase=value;
  File.WriteAllText(Path.Combine(directory,"loader-state-v43.json"),"{\"phase\":\""+value+"\",\"pid\":"+child.pid+",\"birth\":\""+Birth+"\",\"remoteCalls\":"+RemoteCalls+",\"snapshotError\":"+InitialSnapshotError+",\"initializeResult\":"+InitializeResult+"}",Encoding.ASCII);
 }
 public uint ProcessId {get{return child.pid;}}
 public uint ThreadId {get{return child.tid;}}
 public string Birth {get{return born.ToString("x16");}}
 public string ProcessCreationFileTimeUtc {get{return Birth;}}
 public bool OriginalProcessExited {get{return child.process!=IntPtr.Zero && WaitForSingleObject(child.process,0)==0;}}
 public bool ProcessStopped {get{return Stopped;}}
 bool cleanCloseAuthorized;
 public void AuthorizeVerifiedCleanClose(){Live();cleanCloseAuthorized=true;}
 public uint InitializeResult {get;private set;}
 public uint ReplayResult {get;private set;}
 public int RemoteCalls {get;private set;}
 public int InitialSnapshotError {get;private set;}
 public int SnapshotRetries {get;private set;}
 public int StartupSnapshot299Retries {get;private set;}
 public bool Stopped {get;private set;}
 public OwnedGoldLoaderV43(){InitializeResult=ReplayResult=0xffffffff;}
 static void Need(bool condition,string code){if(!condition)throw new InvalidOperationException(code);}
 public static string ProcessBirth(IntPtr handle){long b,e,k,u;Need(GetProcessTimes(handle,out b,out e,out k,out u),"EARLY_BIRTH_UNKNOWN");return b.ToString("x16");}
 void Live(){
  long b,e,k,u;
  Need(child.process!=IntPtr.Zero && WaitForSingleObject(child.process,0)==258 &&
   GetProcessTimes(child.process,out b,out e,out k,out u) && b==born &&
   GetProcessIdOfThread(child.thread)==child.pid,"EARLY_ORIGINAL_NOT_LIVE");
 }
 IntPtr RemoteModule(string expected,out uint size){
  Live();size=0;IntPtr snapshot;Stopwatch watch=Stopwatch.StartNew();
  while(true){
   Live();snapshot=CreateToolhelp32Snapshot(0x18,child.pid);if(snapshot!=new IntPtr(-1))break;
   int error=Marshal.GetLastWin32Error();if(InitialSnapshotError==0)InitialSnapshotError=error;
   // Microsoft documents ERROR_BAD_LENGTH while the loader's module list
   // changes. Retry only that error, for this original child, within 5 seconds.
   ushort machine,native;
   bool initialSameX86=error==299 && RemoteCalls==0 && phase=="resolve-remote-system-module" &&
    watch.ElapsedMilliseconds<1000 && WaitForSingleObject(child.thread,0)==258 &&
    IsWow64Process2(child.process,out machine,out native) && machine==0x14c && native==0x8664;
   // Only initial, resumed, held-handle x86 startup before any remote call.
   // The same 299 after DLL/SDK dispatch is never retried: it can mean a dying child.
   Need((error==24 && watch.ElapsedMilliseconds<5000) || initialSameX86,"EARLY_MODULE_SNAPSHOT_FAILED:"+error);
   if(initialSameX86)StartupSnapshot299Retries++;
   SnapshotRetries++;Thread.Sleep(1);
  }
  try {ME entry=new ME();entry.size=(uint)Marshal.SizeOf(typeof(ME));
   if(Module32First(snapshot,ref entry))do {
    if(String.Equals(entry.path,expected,StringComparison.OrdinalIgnoreCase)){size=entry.baseSize;Live();return entry.baseAddress;}
   }while(Module32Next(snapshot,ref entry));
   Live();return IntPtr.Zero;
  }finally{CloseHandle(snapshot);}
 }
 public bool ModulePresent(string relative){
  Need(relative=="runtime/lib/x86/core_as.dll" || relative=="runtime/modules/Snegopat/lib/x86/snegopat.dll","EARLY_MODULE_SCOPE");
  uint size;return RemoteModule(Path.GetFullPath(Path.Combine(directory,relative)),out size)!=IntPtr.Zero;
 }
 IntPtr PrivateBlock(byte[] bytes){
  Live();IntPtr block=VirtualAllocEx(child.process,IntPtr.Zero,(UIntPtr)bytes.Length,0x3000,4);UIntPtr written;
  Need(block!=IntPtr.Zero && WriteProcessMemory(child.process,block,bytes,(UIntPtr)bytes.Length,out written) && written.ToUInt64()==(ulong)bytes.Length,"EARLY_PRIVATE_BLOCK_FAILED");
  return block;
 }
 uint Call(IntPtr function,IntPtr parameter){
  Live();RemoteCalls++;IntPtr thread=CreateRemoteThread(child.process,IntPtr.Zero,UIntPtr.Zero,function,parameter,0,IntPtr.Zero);
  Need(thread!=IntPtr.Zero,"EARLY_REMOTE_THREAD_FAILED");
  try {uint code=0xffffffff;Need(WaitForSingleObject(thread,10000)==0 && GetExitCodeThread(thread,out code),"EARLY_REMOTE_UNKNOWN_RETAIN");return code;}
  finally{CloseHandle(thread);}
 }
 public void Start(string executable,string arguments,string runtime,bool native1c){
  Need(IntPtr.Size==4 && child.pid==0 && native1c,"GOLD_START_SCOPE");
  directory=Path.GetDirectoryName(Path.GetFullPath(runtime));
  Need(Regex.IsMatch(Path.GetFileName(directory),"^designer-v43-[a-f0-9]{32}$") &&
   String.Equals(Path.GetDirectoryName(directory),@"F:\Projects\AH_1C\build",StringComparison.OrdinalIgnoreCase) &&
   String.Equals(Path.GetFullPath(runtime),Path.Combine(directory,"runtime"),StringComparison.OrdinalIgnoreCase),"GOLD_RUNTIME_SCOPE");
  Need(String.Equals(executable,@"C:\Program Files (x86)\1cv8\8.3.18.1208\bin\1cv8.exe",StringComparison.OrdinalIgnoreCase) &&
   Regex.IsMatch(arguments,@"^DESIGNER /S ""d1(?::[0-9]+)?\\Gold"" /DisableStartupMessages /DisableStartupDialogs(?: |$)"),"GOLD_TARGET_SCOPE");
  string dll=Path.Combine(directory,"GoldBootstrap.dll");
  Need(File.Exists(executable) && File.Exists(dll),"EARLY_IMAGES_MISSING");
  Mark("local-dll");
  localDll=LoadLibrary(dll);Need(localDll!=IntPtr.Zero,"EARLY_LOCAL_DLL_LOAD_FAILED");
  IntPtr initialize=GetProcAddress(localDll,"_ahEarlyInitialize@4");Need(initialize!=IntPtr.Zero,"EARLY_EXPORT_MISSING");
  uint initializeRva=checked((uint)(initialize.ToInt64()-localDll.ToInt64()));
  SI si=new SI();si.cb=Marshal.SizeOf(typeof(SI));si.flags=1;si.show=0;
  Mark("create-original");
  Need(CreateProcess(executable,new StringBuilder("\""+executable+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,false,4|0x08000000,IntPtr.Zero,Path.Combine(directory,"runtime"),ref si,out child),"EARLY_CREATE_CHILD_FAILED");
  Stopped=false;long e,k,u;
  Need(GetProcessTimes(child.process,out born,out e,out k,out u),"EARLY_CHILD_BIRTH_UNKNOWN_RETAIN");
  // No credentials are written: receipt contains only the original kernel identity.
  File.WriteAllText(Path.Combine(directory,"owned-process-v43.json"),"{\"pid\":"+child.pid+",\"tid\":"+child.tid+",\"birth\":\""+Birth+"\"}",Encoding.ASCII);
  Mark("resume-original");
  Need(ResumeThread(child.thread)!=0xffffffff,"EARLY_RESUME_FAILED");
  IntPtr load=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryW"),owner=IntPtr.Zero;
  Need(load!=IntPtr.Zero && GetModuleHandleEx(6,load,out owner),"EARLY_LOAD_OWNER_FAILED");
  StringBuilder systemPath=new StringBuilder(32768);uint length=GetModuleFileName(owner,systemPath,systemPath.Capacity);
  Need(length>0 && length<systemPath.Capacity,"EARLY_LOAD_PATH_FAILED");
  uint loadRva=checked((uint)(load.ToInt64()-owner.ToInt64())),size;
  Mark("resolve-remote-system-module");
  IntPtr remoteOwner=IntPtr.Zero;Stopwatch watch=Stopwatch.StartNew();
  while(remoteOwner==IntPtr.Zero && watch.ElapsedMilliseconds<5000){remoteOwner=RemoteModule(systemPath.ToString(),out size);if(remoteOwner==IntPtr.Zero)Thread.Sleep(1);}
  remoteOwner=RemoteModule(systemPath.ToString(),out size);Need(remoteOwner!=IntPtr.Zero && loadRva<size,"EARLY_LOAD_REMOTE_OWNER_FAILED");
  Mark("load-owned-bootstrap");
  uint loaded=Call(new IntPtr(remoteOwner.ToInt64()+loadRva),PrivateBlock(Encoding.Unicode.GetBytes(dll+"\0")));
  IntPtr remoteDll=RemoteModule(dll,out size);Need(loaded!=0 && unchecked((uint)remoteDll.ToInt64())==loaded && initializeRva<size,"EARLY_REMOTE_DLL_BINDING_FAILED");
  Binding binding=new Binding();binding.pid=child.pid;
  binding.tid=child.tid;
  binding.birthLow=(uint)born;binding.birthHigh=(uint)((ulong)born>>32);binding.version=43;binding.fixture=0;
  IntPtr local=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Binding)));byte[] bytes=new byte[Marshal.SizeOf(typeof(Binding))];
  try {Marshal.StructureToPtr(binding,local,false);Marshal.Copy(local,bytes,0,bytes.Length);}finally{Marshal.FreeHGlobal(local);}
  IntPtr parameter=PrivateBlock(bytes),remoteInitialize=new IntPtr(remoteDll.ToInt64()+initializeRva);
  Mark("initialize-local-natural-cbt");
  InitializeResult=Call(remoteInitialize,parameter);ReplayResult=0xffffffff;
  if(InitializeResult==0)ReplayResult=Call(remoteInitialize,parameter);
  Mark("initialize-returned");
 }
 public void Dispose(){
  // Unknown or dirty state retains the original handles and running Gold.
  // Only the wrapper's freshly authenticated CLOSE_VERIFY authorizes this stop.
  if(child.process!=IntPtr.Zero){
   if(WaitForSingleObject(child.process,0)==258){
    Live();Need(cleanCloseAuthorized,"GOLD_UNKNOWN_RETAIN_HANDLES");bool requested=TerminateProcess(child.process,82);
    // The original can exit between Live and TerminateProcess. Only the
    // original held handle's terminal wait establishes completion.
    if(!requested)Need(WaitForSingleObject(child.process,5000)==0,"EARLY_OWN_FIXTURE_STOP_FAILED");
   }
   Stopped=WaitForSingleObject(child.process,5000)==0;Need(Stopped,"EARLY_OWN_FIXTURE_RETAIN");
   CloseHandle(child.thread);CloseHandle(child.process);child.thread=child.process=IntPtr.Zero;
  }
  if(localDll!=IntPtr.Zero){FreeLibrary(localDll);localDll=IntPtr.Zero;}
 }
}
