// Local rejection checks only. Never starts 1C or any child process.
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class OwnedGoldGuardV43 {
 [StructLayout(LayoutKind.Sequential)] struct Binding {public uint pid,tid,low,high,version,fixture;}
 [DllImport("kernel32",CharSet=CharSet.Unicode)] static extern IntPtr LoadLibrary(string path);
 [DllImport("kernel32",CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("kernel32")] static extern uint GetCurrentThreadId();
 [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint Initialize(IntPtr value);
 public static int Main(){
  string folder=AppDomain.CurrentDomain.BaseDirectory;
  IntPtr dll=LoadLibrary(System.IO.Path.Combine(folder,"GoldBootstrap.dll"));
  if(dll==IntPtr.Zero)return 1;
  var initialize=(Initialize)Marshal.GetDelegateForFunctionPointer(GetProcAddress(dll,"_ahEarlyInitialize@4"),typeof(Initialize));
  long birth=Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc();
  Binding good=new Binding();good.pid=(uint)Process.GetCurrentProcess().Id;good.tid=GetCurrentThreadId();
  good.low=(uint)birth;good.high=(uint)((ulong)birth>>32);good.version=43;good.fixture=0;
  uint[] expected={89,88,90,91,93};uint[] actual=new uint[5];
  actual[0]=initialize(IntPtr.Zero);
  for(int n=1;n<5;n++){
   Binding value=good;if(n==1)value.fixture=1;if(n==2)value.pid++;if(n==3)value.low^=1;
   IntPtr p=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Binding)));
   try{Marshal.StructureToPtr(value,p,false);actual[n]=initialize(p);}finally{Marshal.FreeHGlobal(p);}
  }
  bool passed=true;for(int n=0;n<5;n++)passed &= actual[n]==expected[n];
  var loader=new OwnedGoldLoaderV43();int rejected=0;
  string[] targets={"other.exe",@"C:\Program Files (x86)\1cv8\8.3.18.1208\bin\1cv8.exe"};
  foreach(string image in targets){
   try{loader.Start(image,"ENTERPRISE /S \"d1\\Gold\"",System.IO.Path.Combine(folder,"runtime"),true);}
   catch(InvalidOperationException){if(loader.ProcessId==0)rejected++;}
  }
  loader.Dispose();passed &= rejected==2;
  Console.WriteLine("{\"passed\":"+(passed?"true":"false")+",\"nativeCodes\":["+String.Join(",",actual)+"],\"invalidStartsRejected\":"+rejected+",\"goldStarted\":false}");
  return passed?0:2;
 }
}
