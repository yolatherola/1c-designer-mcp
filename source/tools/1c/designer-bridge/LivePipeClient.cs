// Same-account local client. Source text is returned to the caller, never logged.
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

public sealed class LiveReadEvidence {
    public bool Passed, ActorAclVerified, ServerPidVerified, WrongPidRejected,
        WrongSessionRejected, WriteCommandRejected, OversizedRequestRejected,
        PersistentConnectionVerified;
    public int ReadCount, TextBytes;
    public string TextSha256;
    public List<double> RoundTripMs=new List<double>();
}
public static class LivePipeClient {
    public const string Root="218b5d00-7e10-486f-874c-73c2368ed5da";
    public const string Object="ca1bedb3-3d02-4924-a8a8-bc6b22b8eeb5";
    const int Maximum=2097152;
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    static void Require(bool ok,string code) { if(!ok) throw new InvalidOperationException(code); }
    static void ValidateAcl(PipeStream stream) {
        PipeSecurity acl=stream.GetAccessControl();
        SecurityIdentifier actor=WindowsIdentity.GetCurrent().User;
        SecurityIdentifier system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        AuthorizationRuleCollection rules=acl.GetAccessRules(true,true,typeof(SecurityIdentifier));
        bool a=false,s=false;
        foreach(PipeAccessRule rule in rules) {
            Require(rule.AccessControlType==AccessControlType.Allow,"PIPE_ACL_REJECTED");
            SecurityIdentifier sid=(SecurityIdentifier)rule.IdentityReference;
            if(sid.Equals(actor)) a=true; else if(sid.Equals(system)) s=true;
            else Require(false,"PIPE_ACL_REJECTED");
        }
        Require(acl.AreAccessRulesProtected&&rules.Count==2&&a&&s,"PIPE_ACL_REJECTED");
    }
    static byte[] Exchange(string name,uint expectedPid,string request) {
        Require(Regex.IsMatch(name,@"\AAH1C-[a-f0-9]{32}\z")&&expectedPid>0,"PIPE_TARGET_REJECTED");
        byte[] outgoing=Encoding.ASCII.GetBytes(request);
        Require(outgoing.Length<=128&&outgoing.Length==request.Length,"PIPE_REQUEST_REJECTED");
        string stage="PIPE_CONNECT";
        try {
        using(NamedPipeClientStream client=new NamedPipeClientStream(".",name,
            PipeAccessRights.ReadWrite|PipeAccessRights.ReadPermissions,PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification,HandleInheritability.None)) {
            client.Connect(2000);
            stage="PIPE_PID";
            uint actual;
            Require(GetNamedPipeServerProcessId(client.SafePipeHandle,out actual)&&actual==expectedPid,"PIPE_PID_REJECTED");
            stage="PIPE_ACL";ValidateAcl(client);
            stage="PIPE_READMODE";
            client.ReadMode=PipeTransmissionMode.Message;
            stage="PIPE_WRITE";client.Write(outgoing,0,outgoing.Length);
            stage="PIPE_READ";
            using(MemoryStream response=new MemoryStream()) {
                byte[] buffer=new byte[65536];
                do {
                    IAsyncResult pending=client.BeginRead(buffer,0,buffer.Length,null,null);
                    Require(pending.AsyncWaitHandle.WaitOne(2000),"PIPE_READ_TIMEOUT");
                    int count=client.EndRead(pending);pending.AsyncWaitHandle.Close();
                    Require(count>0&&response.Length+count<=Maximum,"PIPE_RESPONSE_REJECTED");
                    response.Write(buffer,0,count);
                } while(!client.IsMessageComplete);
                return response.ToArray();
            }
        }
        } catch(InvalidOperationException) {throw;}
        catch(Exception e) {
            // A stable stage/type/code is sufficient; never expose paths or a
            // framework exception message that might include source payload.
            throw new InvalidOperationException(stage+"_"+e.GetType().Name.ToUpperInvariant()+"_"+(Marshal.GetHRForException(e)&0xFFFF));
        }
    }
    static string Header(string session,string command) {
        Require(Regex.IsMatch(session,@"\A[a-f0-9]{32}\z"),"SESSION_REJECTED");
        return "AH1C1|"+session+"|"+Root+"|"+Object+"|"+command+"\n";
    }
    static byte[] Body(byte[] response,string expected) {
        byte[] header=Encoding.ASCII.GetBytes(expected);
        Require(response.Length>=header.Length,"PIPE_HEADER_REJECTED");
        for(int i=0;i<header.Length;i++) Require(response[i]==header[i],"PIPE_HEADER_REJECTED");
        byte[] body=new byte[response.Length-header.Length];
        Buffer.BlockCopy(response,header.Length,body,0,body.Length);
        return body;
    }
    public static string ReadModule(string name,uint expectedPid,string session) {
        string expected=Header(session,"READ");
        byte[] body=Body(Exchange(name,expectedPid,session+" READ"),expected);
        return new UTF8Encoding(false,true).GetString(body);
    }
    public sealed class Session : IDisposable {
        readonly NamedPipeClientStream client;
        readonly string session;
        internal Session(string name,uint expectedPid,string sessionId) {
            Header(sessionId,"READ");
            Require(name=="AH1C-"+sessionId&&expectedPid>0,"PIPE_TARGET_REJECTED");
            session=sessionId;
            client=new NamedPipeClientStream(".",name,
                PipeAccessRights.ReadWrite|PipeAccessRights.ReadPermissions,PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification,HandleInheritability.None);
            try {
                client.Connect(2000);
                uint actual;
                Require(GetNamedPipeServerProcessId(client.SafePipeHandle,out actual)&&actual==expectedPid,"PIPE_PID_REJECTED");
                ValidateAcl(client);
                client.ReadMode=PipeTransmissionMode.Message;
            } catch {client.Dispose();throw;}
        }
        internal byte[] ReadBytes() {
            byte[] request=Encoding.ASCII.GetBytes(session+" READ");
            client.Write(request,0,request.Length);
            using(MemoryStream response=new MemoryStream()) {
                byte[] buffer=new byte[65536];
                do {
                    IAsyncResult pending=client.BeginRead(buffer,0,buffer.Length,null,null);
                    Require(pending.AsyncWaitHandle.WaitOne(2000),"PIPE_READ_TIMEOUT");
                    int count=client.EndRead(pending);pending.AsyncWaitHandle.Close();
                    Require(count>0&&response.Length+count<=Maximum,"PIPE_RESPONSE_REJECTED");
                    response.Write(buffer,0,count);
                } while(!client.IsMessageComplete);
                return Body(response.ToArray(),Header(session,"READ"));
            }
        }
        // One connection, strictly sequential read-only calls. Not thread-safe.
        public string ReadModule() {
            return new UTF8Encoding(false,true).GetString(ReadBytes());
        }
        public void Dispose() {client.Dispose();}
    }
    public static Session OpenSession(string name,uint expectedPid,string session) {
        return new Session(name,expectedPid,session);
    }
    static bool Rejected(Action action,string code) {
        try {action();return false;} catch(InvalidOperationException e) {return e.Message==code;}
    }
    public static LiveReadEvidence Probe(string name,uint pid,string session) {
        LiveReadEvidence result=new LiveReadEvidence();
        Require(Body(Exchange(name,pid,session+" PING"),Header(session,"PING")).Length==0,"PING_REJECTED");
        result.ActorAclVerified=result.ServerPidVerified=true;
        result.WrongPidRejected=Rejected(delegate{Exchange(name,pid+1,session+" READ");},"PIPE_PID_REJECTED");
        byte[] wrong=Body(Exchange(name,pid,new string('0',32)+" READ"),Header(session,"ERROR"));
        result.WrongSessionRejected=Encoding.ASCII.GetString(wrong)=="REQUEST_REJECTED";
        byte[] write=Body(Exchange(name,pid,session+" CAPTURE"),Header(session,"ERROR"));
        result.WriteCommandRejected=Encoding.ASCII.GetString(write)=="REQUEST_REJECTED";
        result.OversizedRequestRejected=Rejected(delegate{Exchange(name,pid,new string('X',129));},"PIPE_REQUEST_REJECTED");
        string hash=null;
        using(Session connection=OpenSession(name,pid,session)) {
        for(int i=0;i<20;i++) {
            Stopwatch timer=Stopwatch.StartNew();
            byte[] body=connection.ReadBytes();
            result.RoundTripMs.Add(timer.Elapsed.TotalMilliseconds);
            new UTF8Encoding(false,true).GetString(body);
            Require(body.Length>0,"EMPTY_MODULE");
            using(System.Security.Cryptography.SHA256 sha=System.Security.Cryptography.SHA256.Create()) {
                string current=BitConverter.ToString(sha.ComputeHash(body)).Replace("-","");
                if(hash==null) hash=current; else Require(hash==current,"MODULE_CHANGED");
            }
            result.ReadCount++;result.TextBytes=body.Length;
        }
        result.PersistentConnectionVerified=result.ReadCount==20;
        }
        result.TextSha256=hash;
        result.Passed=result.WrongPidRejected&&result.WrongSessionRejected&&result.WriteCommandRejected&&result.OversizedRequestRejected&&result.PersistentConnectionVerified;
        Require(result.Passed,"NEGATIVE_CASE_FAILED");return result;
    }
}
