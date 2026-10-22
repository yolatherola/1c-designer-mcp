// The callback executes a fixed, compiled readonly payload on one owned thread.
// This adapter has no process launch/kill/memory write or desktop-wide hook API.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Text;
public sealed class OwnedSdkDiagnosisHook : IDisposable {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out long born,out long exit,out long k,out long u);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint timeout);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibrary(string path);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr library,string name);
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr library);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetModuleFileName(IntPtr library,StringBuilder path,int length);
 [DllImport("kernel32.dll")] static extern bool GetModuleHandleEx(uint flags,IntPtr address,out IntPtr module);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint rights,bool inherit,uint tid);
 [DllImport("kernel32.dll")] static extern uint GetProcessIdOfThread(IntPtr h);
 delegate bool EnumerateWindow(IntPtr window,IntPtr argument);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate IntPtr InstallNativeHook(uint tid,out uint error);
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumerateWindow callback,IntPtr arg);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window,StringBuilder name,int size);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SetWindowsHookEx(int kind,IntPtr callback,IntPtr library,uint tid);
 [DllImport("user32.dll",SetLastError=true)] static extern bool UnhookWindowsHookEx(IntPtr hook);
 [DllImport("user32.dll",SetLastError=true)] static extern bool PostThreadMessage(uint tid,uint message,IntPtr w,IntPtr l);
 IntPtr process,thread,library,hook;uint pid,tid;string birth;bool dispatched;OwnedSdkReadonlyAttach attachment;
 static void Require(bool b,string code){if(!b)throw new InvalidOperationException(code);}
 public uint ThreadId {get{return tid;}}
 public bool Dispatched {get{return dispatched;}}
 void Identity(){long b,e,k,u;Require(GetProcessTimes(process,out b,out e,out k,out u) && b.ToString("x16")==birth && WaitForSingleObject(process,0)==258,"SDK_ORIGINAL_IDENTITY_REJECTED");}
 public void Start(uint expectedPid,string expectedBirth,string fixedLibrary){
  Require(IntPtr.Size==4 && process==IntPtr.Zero && expectedPid>0 && expectedBirth.Length==16,"SDK_START_REJECTED");
  pid=expectedPid;birth=expectedBirth;process=OpenProcess(0x101010,false,pid);Require(process!=IntPtr.Zero,"SDK_OPEN_FAILED");Identity();
  var threads=new HashSet<uint>();var primary=new HashSet<uint>();
  EnumerateWindow enumerate=delegate(IntPtr window,IntPtr argument){uint owner;uint t=GetWindowThreadProcessId(window,out owner);if(owner==pid && t!=0){threads.Add(t);var name=new StringBuilder(256);GetClassName(window,name,name.Capacity);string cls=name.ToString();if(cls=="V8TopLevelFrame" || cls=="V8NewLocalFrameBaseWnd" || cls.StartsWith("WindowsForms10.Window.",StringComparison.Ordinal))primary.Add(t);}return true;};
  var ready=Stopwatch.StartNew();
  do{threads.Clear();primary.Clear();Identity();Require(EnumWindows(enumerate,IntPtr.Zero),"SDK_OWN_WINDOWS_ENUM_FAILED");if(primary.Count==1 || threads.Count==1)break;Thread.Sleep(20);}while(ready.ElapsedMilliseconds<3000);
  if(primary.Count==1)threads=primary;
  Require(threads.Count==1,"SDK_UNIQUE_OWN_GUI_THREAD_REQUIRED");GC.KeepAlive(enumerate);
  foreach(uint value in threads)tid=value;
  thread=OpenThread(0x100040,false,tid);Require(thread!=IntPtr.Zero && GetProcessIdOfThread(thread)==pid,"SDK_THREAD_IDENTITY_REJECTED");Identity();
  Require(Path.IsPathRooted(fixedLibrary) && File.Exists(fixedLibrary),"SDK_LIBRARY_REJECTED");
  library=LoadLibrary(fixedLibrary);Require(library!=IntPtr.Zero,"SDK_LIBRARY_LOAD_FAILED");
  IntPtr callback=GetProcAddress(library,"ahSdkHook");if(callback==IntPtr.Zero)callback=GetProcAddress(library,"ahSdkHook@12");
  if(callback==IntPtr.Zero)callback=GetProcAddress(library,"_ahSdkHook@12");
  Require(callback!=IntPtr.Zero,"SDK_HOOK_EXPORT_MISSING");Identity();
  IntPtr callbackModule;Require(GetModuleHandleEx(6,callback,out callbackModule) && callbackModule==library,"SDK_CALLBACK_MODULE_REJECTED");
  var loadedPath=new StringBuilder(32768);uint loadedLength=GetModuleFileName(library,loadedPath,loadedPath.Capacity);Require(loadedLength>0 && Path.GetFullPath(loadedPath.ToString()).Equals(Path.GetFullPath(fixedLibrary),StringComparison.OrdinalIgnoreCase),"SDK_LOADED_PATH_REJECTED");
  // Cross-process hook registration returned126 even for modern PE images.
  // Preload our immutable readonly DLL and arm its exact GUI-thread callback
  // from inside the same process. Loader workers never call metadata or AS.
  attachment=new OwnedSdkReadonlyAttach();string dllHash;
  using(var sha=System.Security.Cryptography.SHA256.Create())using(var file=File.OpenRead(fixedLibrary))dllHash=BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();
  attachment.BeginLoad(pid,birth,fixedLibrary,dllHash);
  while(!attachment.WaitLoad(10000))Thread.Sleep(10);
  attachment.BeginArm(tid);
  var armed=Stopwatch.StartNew();
  while(!attachment.ArmReady){if(attachment.ArmFinished || armed.ElapsedMilliseconds>10000)throw new InvalidOperationException("SDK_ARM_READY_UNKNOWN");Thread.Sleep(10);}
  Require(PostThreadMessage(tid,0x83d2,IntPtr.Zero,IntPtr.Zero),"SDK_PRIVATE_MESSAGE_FAILED");dispatched=true;
 }
 public int WaitReadonlyResult(string resultFile,int milliseconds){
  Require(dispatched && milliseconds>0 && milliseconds<=20000,"SDK_WAIT_REJECTED");var timer=Stopwatch.StartNew();
  while(timer.ElapsedMilliseconds<milliseconds){
   Identity();
   if(File.Exists(resultFile)){
    // CREATE_NEW becomes visible before the native writer flushes/closes its
    // nonshared handle. Retry only this read; never resend the SDK message.
    try{byte[] b=File.ReadAllBytes(resultFile);Require(b.Length==4,"SDK_RESULT_REJECTED");return BitConverter.ToInt32(b,0);}
    catch(IOException){ }
   }
   Thread.Sleep(10);
  }
  throw new InvalidOperationException("SDK_DIAGNOSIS_RESULT_UNKNOWN");
 }
 public void Dispose(){
  if(attachment!=null){
   if(attachment.LoadAttempted && !attachment.LoadFinished)while(!attachment.WaitLoad(10000))Thread.Sleep(10);
   if(attachment.ArmAttempted && !attachment.ArmFinished)while(!attachment.WaitArm(10000))Thread.Sleep(10);
   attachment.Dispose();attachment=null;
  }
  if(hook!=IntPtr.Zero){Require(UnhookWindowsHookEx(hook),"SDK_UNHOOK_FAILED");hook=IntPtr.Zero;}
  if(library!=IntPtr.Zero){FreeLibrary(library);library=IntPtr.Zero;}
  if(thread!=IntPtr.Zero){CloseHandle(thread);thread=IntPtr.Zero;}
  if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}
 }
}
