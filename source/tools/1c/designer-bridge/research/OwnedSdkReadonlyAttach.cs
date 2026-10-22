// Preload one fixed readonly SDK helper into the owned process. No executable
// memory allocation, existing-memory patch, process launch or termination API.
// Unknown loads keep original handles and the newly allocated path buffer.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
public sealed class OwnedSdkReadonlyAttach : IDisposable {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h,out long b,out long e,out long k,out long u);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint milliseconds);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr address,UIntPtr count,uint allocation,uint protect);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualFreeEx(IntPtr h,IntPtr address,UIntPtr count,uint operation);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h,IntPtr address,byte[] bytes,int count,out IntPtr written);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr attributes,UIntPtr stack,IntPtr entry,IntPtr argument,uint flags,out uint tid);
 [DllImport("kernel32.dll")] static extern bool GetExitCodeThread(IntPtr h,out uint code);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("kernel32.dll")] static extern bool GetModuleHandleEx(uint flags,IntPtr address,out IntPtr module);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetModuleFileName(IntPtr module,StringBuilder path,int size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr LoadLibrary(string path);
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
 [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr hook);
 IntPtr process,worker,scratch,localLibrary,remoteLibrary,remoteHook;uint pid;string birth,armFile;bool attempted,loadFinished,armAttempted,armFinished;
 static void Require(bool b,string code){if(!b)throw new InvalidOperationException(code);}
 static string Hash(string path){using(var h=SHA256.Create())using(var s=File.OpenRead(path))return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant();}
 void Identity(){long b,e,k,u;Require(process!=IntPtr.Zero && GetProcessTimes(process,out b,out e,out k,out u) && b.ToString("x16")==birth && WaitForSingleObject(process,0)==258,"SDK_ATTACH_ORIGINAL_REJECTED");}
 public bool LoadFinished {get{return loadFinished;}}
 public bool LoadAttempted {get{return attempted;}}
 public bool ArmFinished {get{return armFinished;}}
 public bool ArmAttempted {get{return armAttempted;}}
 public bool ArmReady {
  get{if(!armAttempted || !File.Exists(armFile))return false;byte[] d=File.ReadAllBytes(armFile);Require(d.Length==8,"SDK_ARM_READY_FILE_REJECTED");if(BitConverter.ToUInt32(d,0)!=0)throw new InvalidOperationException("SDK_ARM_READY_REJECTED_"+BitConverter.ToUInt32(d,0)+"_"+BitConverter.ToUInt32(d,4));return true;}
 }
 public uint RemoteLibrary {get{return unchecked((uint)remoteLibrary.ToInt32());}}
 public void BeginLoad(uint expectedPid,string expectedBirth,string libraryPath,string expectedSha256){
  Require(IntPtr.Size==4 && !attempted && Path.IsPathRooted(libraryPath) && expectedSha256.Length==64,"SDK_ATTACH_ARGUMENT_REJECTED");
  Require(Hash(libraryPath)==expectedSha256 && (File.GetAttributes(libraryPath)&FileAttributes.ReparsePoint)==0,"SDK_ATTACH_LIBRARY_REJECTED");
  pid=expectedPid;birth=expectedBirth;process=OpenProcess(0x10143a,false,pid);Require(process!=IntPtr.Zero,"SDK_ATTACH_OPEN_FAILED");Identity();
  armFile=Path.Combine(Path.GetDirectoryName(libraryPath),"arm-result.bin");
  IntPtr entry=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryW"),owner=IntPtr.Zero;
  Require(entry!=IntPtr.Zero && GetModuleHandleEx(6,entry,out owner),"SDK_OS_LOADER_MISSING");
  var path=new StringBuilder(32768);Require(GetModuleFileName(owner,path,path.Capacity)>0,"SDK_OS_LOADER_PATH_MISSING");
  string ownPath=Path.GetFullPath(path.ToString());long rva=entry.ToInt64()-owner.ToInt64();IntPtr remoteEntry=IntPtr.Zero;
  using(var target=Process.GetProcessById((int)pid))foreach(ProcessModule m in target.Modules){
   if(!Path.GetFullPath(m.FileName).Equals(ownPath,StringComparison.OrdinalIgnoreCase))continue;
   Require(rva>=0 && rva<m.ModuleMemorySize && Hash(m.FileName)==Hash(ownPath),"SDK_OS_LOADER_HASH_REJECTED");remoteEntry=new IntPtr(m.BaseAddress.ToInt64()+rva);
  }
  Require(remoteEntry!=IntPtr.Zero,"SDK_REMOTE_OS_LOADER_MISSING");Identity();
  byte[] bytes=Encoding.Unicode.GetBytes(libraryPath+"\0");Require(bytes.Length<=2048,"SDK_ATTACH_PATH_BOUND");
  scratch=VirtualAllocEx(process,IntPtr.Zero,(UIntPtr)bytes.Length,0x3000,0x04);Require(scratch!=IntPtr.Zero,"SDK_PATH_ALLOCATION_FAILED");
  IntPtr written;Require(WriteProcessMemory(process,scratch,bytes,bytes.Length,out written) && written.ToInt32()==bytes.Length,"SDK_OWN_PATH_WRITE_FAILED");Identity();
  // The intent is durable before this one attempt. Never repeat an unknown load.
  attempted=true;uint tid;worker=CreateRemoteThread(process,IntPtr.Zero,UIntPtr.Zero,remoteEntry,scratch,0,out tid);
  if(worker==IntPtr.Zero){loadFinished=true;throw new InvalidOperationException("SDK_READONLY_LOAD_THREAD_FAILED");}
  localLibrary=LoadLibrary(libraryPath);Require(localLibrary!=IntPtr.Zero,"SDK_LOCAL_COPY_LOAD_FAILED");
 }
 public bool WaitLoad(int milliseconds){
  Require(attempted && worker!=IntPtr.Zero && milliseconds>=0 && milliseconds<=10000,"SDK_ATTACH_WAIT_REJECTED");Identity();
  if(WaitForSingleObject(worker,(uint)milliseconds)!=0)return false;
  uint result;Require(GetExitCodeThread(worker,out result),"SDK_LOAD_RETURN_UNKNOWN");loadFinished=true;CloseHandle(worker);worker=IntPtr.Zero;
  Require(VirtualFreeEx(process,scratch,UIntPtr.Zero,0x8000),"SDK_OWN_PATH_RELEASE_FAILED");scratch=IntPtr.Zero;
  Require(result!=0 && result!=259,"SDK_READONLY_LIBRARY_NOT_LOADED");remoteLibrary=new IntPtr(unchecked((int)result));return true;
 }
 public void BeginArm(uint guiThread){
  Require(loadFinished && remoteLibrary!=IntPtr.Zero && !armAttempted,"SDK_ARM_STATE_REJECTED");Identity();
  IntPtr entry=GetProcAddress(localLibrary,"ahSdkArmOwnThread@4");if(entry==IntPtr.Zero)entry=GetProcAddress(localLibrary,"_ahSdkArmOwnThread@4");if(entry==IntPtr.Zero)entry=GetProcAddress(localLibrary,"ahSdkArmOwnThread");
  IntPtr owner;Require(entry!=IntPtr.Zero && GetModuleHandleEx(6,entry,out owner) && owner==localLibrary,"SDK_ARM_FIXED_EXPORT_REJECTED");
  long rva=entry.ToInt64()-localLibrary.ToInt64();Require(rva>0 && rva<1024*1024,"SDK_ARM_RVA_BOUND");
  armAttempted=true;uint tid;worker=CreateRemoteThread(process,IntPtr.Zero,UIntPtr.Zero,new IntPtr(remoteLibrary.ToInt64()+rva),new IntPtr(unchecked((int)guiThread)),0,out tid);
  if(worker==IntPtr.Zero){armFinished=true;throw new InvalidOperationException("SDK_ARM_THREAD_FAILED");}
 }
 public bool WaitArm(int milliseconds){
  Require(armAttempted && worker!=IntPtr.Zero && milliseconds>=0 && milliseconds<=10000,"SDK_ARM_WAIT_REJECTED");Identity();
  if(WaitForSingleObject(worker,(uint)milliseconds)!=0)return false;
  uint result;Require(GetExitCodeThread(worker,out result),"SDK_ARM_RETURN_UNKNOWN");armFinished=true;CloseHandle(worker);worker=IntPtr.Zero;
  if(result!=1){
   byte[] detail=File.Exists(armFile)?File.ReadAllBytes(armFile):new byte[0];
   string code=detail.Length==8?"SDK_SAME_PROCESS_HOOK_REJECTED_"+BitConverter.ToUInt32(detail,0)+"_"+BitConverter.ToUInt32(detail,4):"SDK_SAME_PROCESS_HOOK_REJECTED";
   throw new InvalidOperationException(code);
  }
  return true;
 }
 public void Dispose(){
  Require((!attempted || loadFinished) && (!armAttempted || armFinished),"SDK_UNKNOWN_ATTACH_RETAIN_HANDLES");
  if(scratch!=IntPtr.Zero){Identity();Require(VirtualFreeEx(process,scratch,UIntPtr.Zero,0x8000),"SDK_UNUSED_OWN_PATH_RELEASE_FAILED");scratch=IntPtr.Zero;}
  if(remoteHook!=IntPtr.Zero){Require(UnhookWindowsHookEx(remoteHook),"SDK_OWN_HOOK_RELEASE_FAILED");remoteHook=IntPtr.Zero;}
  if(localLibrary!=IntPtr.Zero){FreeLibrary(localLibrary);localLibrary=IntPtr.Zero;}
  if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}
 }
}
