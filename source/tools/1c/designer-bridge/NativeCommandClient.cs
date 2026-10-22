// Local native command client. Exact PID+birth, protected actor/System pipe,
// fixed scope, sequential exchanges and explicit replay. Never logs source.
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

public sealed class NativeCommandEvidence {
    public bool Passed, ActorAclVerified, ServerPidBirthVerified, WrongPidRejected,
        WrongBirthRejected, WrongSessionRejected, WrongScopeRejected, UnknownCommandRejected,
        ChangedCommandReplayRejected, ConsumedOperationRejected, ExactReplayVerified,
        SourceSecondOperationBlocked, OwnSecondOperationBlocked, SameConnectionVerified, NonAsciiRejected,
        OwnBufferGuardVerified, OwnBufferGuardSecondOperationBlocked, OwnBufferGuardReplayVerified, SelectedBufferGuardVerified;
    public int ReadCount, SourceMetadataRpcCount, SourceModuleRpcCount;
    public string LiveTextSha256;
    public List<double> ReadRoundTripMs=new List<double>();
    public List<double> StatusRoundTripMs=new List<double>();
}
public sealed class NativeCommandReply {
    public string Kind, Body;
    public bool Replayed;
}
public static class NativeCommandClient {
    public const string Root="218b5d00-7e10-486f-874c-73c2368ed5da";
    public const string Object="88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d";
    const int Maximum=2097152;
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
    static void Require(bool ok,string code) {if(!ok) throw new InvalidOperationException(code);}
    static bool Hex(string value,int length) {return value!=null&&Regex.IsMatch(value,"\\A[a-f0-9]{"+length+"}\\z");}
    static string Operation() {return Guid.NewGuid().ToString("N");}
    static string Hash(byte[] data) {using(SHA256 s=SHA256.Create()) return BitConverter.ToString(s.ComputeHash(data)).Replace("-","").ToLowerInvariant();}
    static Dictionary<string,object> Json(string value) {
        JavaScriptSerializer serializer=new JavaScriptSerializer();serializer.MaxJsonLength=Maximum;serializer.RecursionLimit=128;
        return serializer.Deserialize<Dictionary<string,object>>(value);
    }
    static int Number(Dictionary<string,object> data,string key) {
        object value;Require(data.TryGetValue(key,out value)&&(value is int||value is long),"COMMAND_FIELD_REJECTED");
        return checked(Convert.ToInt32(value));
    }
    static bool True(Dictionary<string,object> data,string key) {object v;return data.TryGetValue(key,out v)&&v is bool&&(bool)v;}
    static void ValidateAcl(PipeStream stream) {
        PipeSecurity acl=stream.GetAccessControl();
        SecurityIdentifier actor=WindowsIdentity.GetCurrent().User;
        SecurityIdentifier system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        AuthorizationRuleCollection rules=acl.GetAccessRules(true,true,typeof(SecurityIdentifier));
        bool a=false,s=false;
        foreach(PipeAccessRule rule in rules) {
            Require(rule.AccessControlType==AccessControlType.Allow,"PIPE_ACL_REJECTED");
            SecurityIdentifier sid=(SecurityIdentifier)rule.IdentityReference;
            if(sid.Equals(actor)) a=true;else if(sid.Equals(system)) s=true;else Require(false,"PIPE_ACL_REJECTED");
        }
        Require(acl.AreAccessRulesProtected&&rules.Count==2&&a&&s
            &&acl.GetOwner(typeof(SecurityIdentifier)).Equals(actor),"PIPE_ACL_REJECTED");
    }
    public sealed class Session : IDisposable {
        readonly NamedPipeClientStream client;
        readonly Process server;
        readonly string session,birth;
        readonly uint pid;
        readonly object exchangeGate=new object();
        bool failed;
        internal Session(string name,uint expectedPid,string expectedBirth,string sessionId) {
            Require(Hex(sessionId,32)&&name=="AH1C-"+sessionId&&expectedPid>0&&expectedPid<=Int32.MaxValue&&Hex(expectedBirth,16),"PIPE_TARGET_REJECTED");
            pid=expectedPid;birth=expectedBirth;session=sessionId;
            server=Process.GetProcessById((int)pid);
            try {
                // Keep the original query handle for this connection; PID reuse
                // cannot change which process is checked before each request.
                IntPtr handle=server.Handle;
                VerifyProcess();
                client=new NamedPipeClientStream(".",name,PipeAccessRights.ReadWrite|PipeAccessRights.ReadPermissions,
                    PipeOptions.Asynchronous,TokenImpersonationLevel.Identification,HandleInheritability.None);
                client.Connect(2000);
                uint actual;
                Require(GetNamedPipeServerProcessId(client.SafePipeHandle,out actual)&&actual==pid,"PIPE_PID_REJECTED");
                ValidateAcl(client);
                VerifyProcess();
                client.ReadMode=PipeTransmissionMode.Message;
            } catch {if(client!=null) client.Dispose();server.Dispose();throw;}
        }
        void VerifyProcess() {
            long created,exited,kernel,user;
            Require(!server.HasExited&&GetProcessTimes(server.Handle,out created,out exited,out kernel,out user)
                &&created.ToString("x16")==birth,"PIPE_BIRTH_REJECTED");
        }
        public NativeCommandReply Send(string operation,string command) {return SendEnvelope(operation,command,session,Root,Object);}
        // Diagnostic read only: reproduce a peer disappearing after sending a
        // request. Never accepts a mutation command or waits for its response.
        public void SendReadAndDisconnect(string operation) {
            lock(exchangeGate) {
                Require(!failed&&Hex(operation,32),"COMMAND_OPERATION_REJECTED");
                VerifyProcess();
                byte[] bytes=Encoding.ASCII.GetBytes(session+" "+operation+" "+Root+" "+Object+" READLIVE");
                try {client.Write(bytes,0,bytes.Length);}
                finally {failed=true;client.Dispose();}
            }
        }
        public NativeCommandReply SendOwnedPilot(string operation,string command) {
            Require(command=="PILOT_PREPARE"||command=="PILOT_STATUS"||command=="PILOT_CREATE"||command=="PILOT_SAVE"
                ||command=="PILOT_CONFIRM_SAVE"||command=="PILOT_DELETE"||command=="PILOT_DELETE_SAVE"
                ||command=="PILOT_SAVED_CREATED"||command=="PILOT_SAVED_DELETED","PILOT_COMMAND_REJECTED");
            lock(exchangeGate) {return Exchange(operation,command,session,Root,Object,45000);}
        }
        static int ResultBudgetMilliseconds(string command) {
            // Native own-object cycles can finish after five seconds. Waiting
            // longer grants no write authority; the protected host checks it.
            return command=="GOLD_OWN_OBJECT_MODULE_V82"||command=="GOLD_OWNED_CONSTANT_V99"||command=="GOLD_OWNED_MANAGED_FORM_V107"||command=="GOLD_OWNED_EMPTY_OBJECTS_V130"||command=="GOLD_OWNED_DOCUMENT_STRUCTURE_V139"||command=="MANAGED_INPUT_RECORD_V145"||command=="GOLD_OWNED_FULL_OBJECT_MODULE_V150"?30000:5000;
        }
        internal NativeCommandReply SendEnvelope(string operation,string command,string requestSession,string root,string objectId) {
            lock(exchangeGate) {
                int budget=ResultBudgetMilliseconds(command);
                return Exchange(operation,command,requestSession,root,objectId,budget,budget==30000);
            }
        }
        NativeCommandReply Exchange(string operation,string command,string requestSession,string root,string objectId,int timeout=5000,bool totalBudget=false) {
            Require(!failed&&Hex(operation,32),"COMMAND_OPERATION_REJECTED");
            string request=requestSession+" "+operation+" "+root+" "+objectId+" "+command;
            Require(Array.TrueForAll(request.ToCharArray(),delegate(char c){return c>=32&&c<=126;}),"COMMAND_ENVELOPE_REJECTED");
            byte[] bytes=Encoding.ASCII.GetBytes(request);
            Require(bytes.Length<=256&&bytes.Length==request.Length&&Array.TrueForAll(bytes,delegate(byte c){return c>=32&&c<=126;}),"COMMAND_ENVELOPE_REJECTED");
            try {
                VerifyProcess();
                Stopwatch resultWatch=totalBudget?Stopwatch.StartNew():null;
                client.Write(bytes,0,bytes.Length);
                using(MemoryStream response=new MemoryStream()) {
                    byte[] buffer=new byte[65536];
                    do {
                        // One bounded result budget, including any partial
                        // message reads; fragments cannot reset these cycles.
                        int remaining=timeout;
                        if(resultWatch!=null) {
                            long left=timeout-resultWatch.ElapsedMilliseconds;
                            if(left<=0)throw new InvalidOperationException("COMMAND_RESULT_TIMEOUT");
                            remaining=(int)left;
                        }
                        IAsyncResult pending=client.BeginRead(buffer,0,buffer.Length,null,null);
                        bool completed=pending.AsyncWaitHandle.WaitOne(remaining);
                        // A pending IO completion still signals its event after
                        // Dispose cancels the pipe. Closing it here races that
                        // callback; retain it until completion and GC instead.
                        if(!completed)throw new InvalidOperationException("COMMAND_RESULT_TIMEOUT");
                        int count=client.EndRead(pending);pending.AsyncWaitHandle.Close();
                        Require(count>0&&response.Length+count<=Maximum,"COMMAND_RESPONSE_REJECTED");
                        response.Write(buffer,0,count);
                    }while(!client.IsMessageComplete);
                    VerifyProcess();
                    string raw=new UTF8Encoding(false,true).GetString(response.ToArray());
                    int newline=raw.IndexOf('\n');Require(newline>0&&newline<256,"COMMAND_HEADER_REJECTED");
                    string[] header=raw.Substring(0,newline).Split('|');
                    Require(header.Length==7&&header[0]=="AH1C2"&&header[1]==session&&header[2]==operation
                        &&header[3]==Root&&header[4]==Object&&(header[5]==command||header[5]=="ERROR")
                        &&(header[6]=="RESULT"||header[6]=="REPLAY"),"COMMAND_HEADER_REJECTED");
                    return new NativeCommandReply {Kind=header[5],Body=raw.Substring(newline+1),Replayed=header[6]=="REPLAY"};
                }
            }catch{failed=true;client.Dispose();throw;}
        }
        public void Dispose() {lock(exchangeGate) {failed=true;client.Dispose();server.Dispose();}}
    }
    public static Session OpenSession(string name,uint pid,string birth,string session) {return new Session(name,pid,birth,session);}
    static bool Rejected(Action action,string code) {try{action();return false;}catch(InvalidOperationException e){return e.Message==code;}}
    static bool Error(NativeCommandReply value,string code) {return value.Kind=="ERROR"&&value.Body==code&&!value.Replayed;}
    public static NativeCommandEvidence Probe(string name,uint pid,string birth,string session,string ownedDirectory) {
        NativeCommandEvidence result=new NativeCommandEvidence();
        result.WrongBirthRejected=Rejected(delegate{using(Session x=OpenSession(name,pid,new string('0',16),session)){}},"PIPE_BIRTH_REJECTED");
        // The PID test uses the real calling process (different from Gold), so
        // creation time is valid and the actual pipe-owner check is exercised.
        using(Process self=Process.GetCurrentProcess()) {
            long c,e,k,u;Require(GetProcessTimes(self.Handle,out c,out e,out k,out u),"PROBE_SELF_IDENTITY_UNKNOWN");
            result.WrongPidRejected=Rejected(delegate{using(Session x=OpenSession(name,(uint)self.Id,c.ToString("x16"),session)){}},"PIPE_PID_REJECTED");
        }
        using(Session connection=OpenSession(name,pid,birth,session)) {
            result.ActorAclVerified=result.ServerPidBirthVerified=true;
            NativeCommandReply ping=connection.Send(Operation(),"PING");Require(ping.Kind=="PING"&&ping.Body==""&&!ping.Replayed,"PING_REJECTED");
            result.NonAsciiRejected=Rejected(delegate{connection.Send(Operation(),"ST\u0410TUS");},"COMMAND_ENVELOPE_REJECTED");
            result.WrongSessionRejected=Error(connection.SendEnvelope(Operation(),"STATUS",new string('0',32),Root,Object),"REQUEST_REJECTED");
            result.WrongScopeRejected=Error(connection.SendEnvelope(Operation(),"OWN_CYCLE",session,Root,"0ed914fb-2a1a-4b58-9fad-eaa103b47c9e"),"SCOPE_REJECTED");
            result.UnknownCommandRejected=Error(connection.Send(Operation(),"CAPTURE"),"COMMAND_REJECTED");
            string op=Operation();NativeCommandReply status=connection.Send(op,"STATUS");
            NativeCommandReply replay=connection.Send(op,"STATUS");
            result.ExactReplayVerified=replay.Replayed&&status.Body==replay.Body;
            result.ChangedCommandReplayRejected=Error(connection.Send(op,"OWN_CYCLE"),"OPERATION_REUSED");
            connection.Send(Operation(),"PING");
            result.ConsumedOperationRejected=Error(connection.Send(op,"STATUS"),"OPERATION_CONSUMED");
            Dictionary<string,object> initialStatus=Json(status.Body);
            Dictionary<string,object> bufferStatus=initialStatus["selectedBufferGuard"] as Dictionary<string,object>;
            result.SelectedBufferGuardVerified=bufferStatus!=null&&True(bufferStatus,"initialTextKnown")&&True(bufferStatus,"scopeUnchanged")&&True(bufferStatus,"matchesInitialText");
            Require(result.SelectedBufferGuardVerified,"SELECTED_BUFFER_STATUS_REJECTED");
            string bufferOp=Operation();NativeCommandReply bufferReply=connection.Send(bufferOp,"OWN_BUFFER_GUARD");
            Require(bufferReply.Kind=="OWN_BUFFER_GUARD"&&!bufferReply.Replayed,"OWN_BUFFER_REPLY_REJECTED");
            Dictionary<string,object> bufferProof=Json(bufferReply.Body);
            result.OwnBufferGuardVerified=True(bufferProof,"sharedNativeComparatorUsed")&&True(bufferProof,"initialComparisonAccepted")
                &&True(bufferProof,"unknownBaselineRejected")&&True(bufferProof,"changedTextComparisonRejected")&&True(bufferProof,"exactTextRestored")
                &&True(bufferProof,"restoredComparisonAccepted")&&True(bufferProof,"selectedGoldBufferUnchanged");
            Require(result.OwnBufferGuardVerified,"OWN_BUFFER_GUARD_REJECTED");
            File.WriteAllText(Path.Combine(ownedDirectory,"command-buffer-guard.json"),bufferReply.Body,new UTF8Encoding(false));
            NativeCommandReply bufferReplay=connection.Send(bufferOp,"OWN_BUFFER_GUARD");
            result.OwnBufferGuardReplayVerified=bufferReplay.Replayed&&bufferReplay.Body==bufferReply.Body;
            result.OwnBufferGuardSecondOperationBlocked=Error(connection.Send(Operation(),"OWN_BUFFER_GUARD"),"OWN_BUFFER_ALREADY_ATTEMPTED");
            NativeCommandReply sourceReply=connection.Send(Operation(),"SOURCE_ONCE");
            Require(sourceReply.Kind=="SOURCE_ONCE"&&!sourceReply.Replayed,"SOURCE_RESULT_REJECTED");
            string source=sourceReply.Body;
            File.WriteAllText(Path.Combine(ownedDirectory,"command-source.json"),source,new UTF8Encoding(false));
            result.SourceSecondOperationBlocked=Error(connection.Send(Operation(),"SOURCE_ONCE"),"SOURCE_ALREADY_FETCHED");
            NativeCommandReply ownReply=connection.Send(Operation(),"OWN_CYCLE");
            Require(ownReply.Kind=="OWN_CYCLE"&&!ownReply.Replayed,"OWN_RESULT_REJECTED");
            string own=ownReply.Body;
            File.WriteAllText(Path.Combine(ownedDirectory,"command-owned.json"),own,new UTF8Encoding(false));
            result.OwnSecondOperationBlocked=Error(connection.Send(Operation(),"OWN_CYCLE"),"OWN_ALREADY_ATTEMPTED");
            string hash=null;
            for(int i=0;i<20;i++) {
                Stopwatch timer=Stopwatch.StartNew();NativeCommandReply read=connection.Send(Operation(),"READLIVE");
                result.ReadRoundTripMs.Add(timer.Elapsed.TotalMilliseconds);
                Require(read.Kind=="READLIVE"&&!read.Replayed&&read.Body.Length>0,"LIVE_READ_REJECTED");
                string current=Hash(new UTF8Encoding(false,true).GetBytes(read.Body));
                if(hash==null) hash=current;else Require(hash==current,"LIVE_MODULE_CHANGED");result.ReadCount++;
            }
            result.LiveTextSha256=hash;
            for(int i=0;i<5;i++) {
                Stopwatch timer=Stopwatch.StartNew();NativeCommandReply current=connection.Send(Operation(),"STATUS");
                result.StatusRoundTripMs.Add(timer.Elapsed.TotalMilliseconds);
                Dictionary<string,object> data=Json(current.Body);
                Require(True(data,"scopeAlive")&&True(data,"selectionVerified")&&True(data,"repositoryBoundVerified")
                    &&True(data,"ownerVerified")&&True(data,"generationVerified"),"NATIVE_SCOPE_REJECTED");
                Dictionary<string,object> dirty=(Dictionary<string,object>)data["dirty"];
                Require(True(dirty,"verified")&&True(dirty,"refreshAllowed"),"NATIVE_DIRTY_REJECTED");
                result.SourceMetadataRpcCount=Number(data,"sourceMetadataRpcCount");result.SourceModuleRpcCount=Number(data,"sourceModuleRpcCount");
                File.WriteAllText(Path.Combine(ownedDirectory,"command-status-"+i+".json"),current.Body,new UTF8Encoding(false));
            }
            result.SameConnectionVerified=result.ReadCount==20;
        }
        result.Passed=result.WrongPidRejected&&result.WrongBirthRejected&&result.WrongSessionRejected&&result.WrongScopeRejected
            &&result.UnknownCommandRejected&&result.ChangedCommandReplayRejected&&result.ConsumedOperationRejected
            &&result.ExactReplayVerified&&result.SourceSecondOperationBlocked&&result.OwnSecondOperationBlocked
            &&result.OwnBufferGuardVerified&&result.OwnBufferGuardReplayVerified&&result.OwnBufferGuardSecondOperationBlocked
            &&result.SelectedBufferGuardVerified&&result.SameConnectionVerified&&result.NonAsciiRejected&&result.SourceMetadataRpcCount==1&&result.SourceModuleRpcCount==1;
        Require(result.Passed,"COMMAND_PROBE_REJECTED");return result;
    }
}
