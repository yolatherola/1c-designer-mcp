"""Pure bounded own full-text proof. No I/O/native/process/SDK/BSL authority."""
import hashlib
import json
import re

ROOT_ID='218b5d00-7e10-486f-874c-73c2368ed5da'
OWN_ID='be276787-4261-50e8-9524-d748a29a81ad'
CLASS_ID='bf845118-327b-4682-b5c6-285d2a0eb296'
PROPERTY_ID='a637f77f-3840-441d-a1c3-699c8c5cb7e0'
OWN_NAME='АгентПолныйObjectModuleV150'
INPUT_SHA='0320a444334420e1cecf3a0bc462add6365e014fd39b144a38889b04ce228aa7'
NORMALIZED_SHA='6721e3aa7511fa11e4f66cc7df3470ebfbe53a6edf1f7905908745b727b431ee'
INPUT_BYTES=74501;UTF16_UNITS=44744;END=(885,1)
RESULT_FILENAME='gold-owned-full-object-module-v150.json'
REGISTRY_FILENAME='gold-owned-full-object-module-v150-registry.json'
STAGES=('Baseline','Factory','Id','Attach','Name','Helper','OpenModule','ActionBegin','Insertion','ActionClose','FullReadback','Undo','EmptyReadback','Delete','ScopeExit','FinalSourceControl')
PHASES=tuple(part+stage for stage in STAGES for part in ('before','after'))
WRITERS=('Factory','Id','Attach','Name','ActionBegin','Insertion','ActionClose','Undo','Delete')
FALSE_CLAIMS=('endCoordinates1CVerified','wholeModuleRuntimeVerified','nativePermit','writerAuthorized','persistedGoldVerified','databaseConfigurationVerified','formVerified','captureLatestVerified','bslExecuted','foreignPropertyContentHashed','typePropertiesVerified','stringTypeVerified','qualifierVerified')
ZERO=('foreignSourceWrites','goldSaves','databaseUpdates','repositoryWrites','businessCalls','dirtyFlagWrites')
FLAGS=('fullReadback','restored','helperEmpty','selectionRestored','ownDeleted','ownAbsent','baselineClean','rootIdentityPreserved','goldSourcePreserved','foreignGraphPreserved','terminalObserved','completeObservation','returnUnknown','nativeException')
KEYS=('status','operationId','ownId','inputSha256','inputBytes','utf16Units','endLine','endColumn','writeAttempts','writerCounts','baselineGuardCount','processingCountBefore','processingCountAfter','phases')+FLAGS+FALSE_CLAIMS+ZERO


def need(ok,code):
    if not ok:raise ValueError('GFM150_'+code)


def parse(raw,limit=32768):
    need(type(raw) is bytes and 0<len(raw)<=limit,'JSON_BOUND')
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'DUPLICATE_KEY');result[key]=value
        return result
    try:return json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE'))
    except (UnicodeError,json.JSONDecodeError):raise ValueError('GFM150_JSON_REJECTED') from None


def marker_filename(phase):
    need(phase in PHASES,'PHASE');return 'gold-owned-full-object-module-v150-'+phase+'.json'


def verify_observation(raw,markers,registry,readbacks):
    """Require physical full-text witnesses before Undo plus known clean deletion.

    A valid observation still grants no live writer/close/process/DB permission.
    Known pre-write refusal is distinct from a full text observation.
    """
    info=parse(raw);need(type(info) is dict and set(info)==set(KEYS),'SHAPE')
    need(info['status']=='V150_TEXT_CYCLE_OBSERVATION' and type(info['operationId']) is str and re.fullmatch('[a-f0-9]{32}',info['operationId']) is not None,'OPERATION')
    need(info['ownId']==OWN_ID and info['inputSha256']==INPUT_SHA,'OWN_INPUT_PIN')
    for key,value in (('inputBytes',INPUT_BYTES),('utf16Units',UTF16_UNITS),('endLine',END[0]),('endColumn',END[1])):
        need(type(info[key]) is int and info[key]==value,'PAYLOAD_COORDINATE')
    for key in FALSE_CLAIMS:need(info[key] is False,'CAPABILITY')
    for key in ZERO:need(type(info[key]) is int and info[key]==0,'FOREIGN_EFFECT')
    for key in FLAGS:need(type(info[key]) is bool,'FLAG_TYPE')
    need(not info['returnUnknown'] and not info['nativeException'],'UNKNOWN_RETAIN')
    calls=info['writerCounts'];need(type(calls) is list and len(calls)==9 and all(type(v) is int and v in (0,1) for v in calls),'WRITER_COUNTS')
    need(type(info['writeAttempts']) is int and info['writeAttempts']==sum(calls)<=9,'BUDGET')
    need(type(info['baselineGuardCount']) is int and sum(calls)+2<=info['baselineGuardCount']<=128,'BASELINE_GUARDS')
    for key in ('processingCountBefore','processingCountAfter'):need(type(info[key]) is int and 0<=info[key]<=100000,'COUNT_TYPE')
    need(info['processingCountBefore']==info['processingCountAfter'],'ROOT_COUNT')
    need(all(info[k] is True for k in ('ownDeleted','ownAbsent','baselineClean','rootIdentityPreserved','goldSourcePreserved','foreignGraphPreserved','terminalObserved')),'TERMINAL')
    phases=info['phases'];need(type(phases) is list and len(phases)==32 and all(type(v) is bool for v in phases),'PHASE_TYPES')
    full=all(v==1 for v in calls)
    need(info['completeObservation'] is full,'FULL_CLAIM')
    if full:need(all(phases) and info['baselineGuardCount']==12,'FULL_PHASES')
    else:need(calls[:4]==[1]*4 and calls[4:8]==[0]*4 and calls[8]==1,'KNOWN_REFUSAL_ONLY')
    need(type(markers) is dict and set(markers)=={marker_filename(p) for p,v in zip(PHASES,phases) if v},'PHYSICAL_SET')
    previous_sequence=previous_attempt=previous_guards=0
    for phase,measured in zip(PHASES,phases):
        if not measured:continue
        mark=parse(markers[marker_filename(phase)],1024)
        need(type(mark) is dict and set(mark)=={'phase','operationId','sequence','writeAttempts','baselineGuardCount'},'MARKER_SHAPE')
        need(mark['phase']==phase and mark['operationId']==info['operationId'],'MARKER_BINDING')
        for key in ('sequence','writeAttempts','baselineGuardCount'):need(type(mark[key]) is int,'MARKER_TYPE')
        need(mark['sequence']==previous_sequence+1 and previous_attempt<=mark['writeAttempts']<=info['writeAttempts'] and previous_guards<=mark['baselineGuardCount']<=info['baselineGuardCount'],'MARKER_ORDER')
        previous_sequence=mark['sequence'];previous_attempt=mark['writeAttempts'];previous_guards=mark['baselineGuardCount']
    for index,(stage,count) in enumerate(zip(WRITERS,calls)):
        if count:
            before=parse(markers[marker_filename('before'+stage)],1024);after=parse(markers[marker_filename('after'+stage)],1024)
            need(after['sequence']==before['sequence']+1 and after['writeAttempts']==before['writeAttempts']+1 and after['baselineGuardCount']==before['baselineGuardCount']+1,'WRITER_PAIR')
    need(phases[0] and phases[1] and all(phases[-6:]),'TERMINAL_PHASES')
    registered=parse(registry,1024)
    expected=dict(createdOnly=True,rootId=ROOT_ID,inputSha256=INPUT_SHA,operationId=info['operationId'],ownId=OWN_ID,classId=CLASS_ID,propertyId=PROPERTY_ID,factoryCalls=1,idSetterCalls=1,attachCalls=0)
    need(type(registered) is dict and set(registered)==set(expected),'REGISTRY_SHAPE')
    for key,value in expected.items():need(type(registered[key]) is type(value) and registered[key]==value,'REGISTRY_BINDING')
    need(type(readbacks) is dict,'READBACK_SHAPE')
    if full:
        need(set(readbacks)=={'editor','helper','empty-editor','empty-helper'},'FULL_READBACK_FILES')
        for key in ('editor','helper'):
            body=readbacks[key];need(type(body) is bytes and len(body)==75385 and hashlib.sha256(body).hexdigest()==NORMALIZED_SHA,'FULL_TEXT_HASH')
            value=body.decode('utf-8',errors='strict');need(len(value.encode('utf-16-le'))//2==UTF16_UNITS and value.count('\r\n')==884 and value.endswith('\r\n'),'FULL_TEXT_POSITION')
        need(readbacks['empty-editor']==readbacks['empty-helper']==b'','EMPTY_RESTORE')
        need(all(info[k] for k in ('fullReadback','restored','helperEmpty','selectionRestored')),'RESTORE_FLAGS')
    else:need(not readbacks and not any(info[k] for k in ('fullReadback','restored','helperEmpty','selectionRestored')),'PARTIAL_TEXT_FALSE')
    return dict(textCycleObservationVerified=full,knownCleanTerminalObserved=True,physicalPhaseCount=len(markers),nominalWriters=sum(calls),endCoordinates1CVerified=False,wholeModuleRuntimeVerified=False,nativePermit=False,writerAuthorized=False,savePermitted=False,processStopPermitted=False)
