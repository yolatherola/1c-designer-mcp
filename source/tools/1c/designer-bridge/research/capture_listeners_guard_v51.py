"""Validate bounded interface observations; grant no notification/write capability."""
MODULES=frozenset(('devtool.dll','config.dll','configshell.dll','frntend.dll','basicui.dll',
    'backend.dll','crcore.dll','frame.dll','core83.dll','txtedui.dll','txtedt.dll',
    'mngbase.dll','mngcore.dll','mngdsgn.dll','rclient.dll','basic.dll','1cv8.exe'))

def need(condition,code):
    if not condition:raise ValueError(code)

def integer(value):return type(value) is int and value>=0

def api(value,slots):
    need(isinstance(value,dict) and isinstance(value.get('slots'),list)
        and len(value['slots'])==slots,'V51_LISTENER_ADDRESS_REJECTED')
    for location in (value.get('table'),*value['slots']):
        need(isinstance(location,dict) and location.get('module') in MODULES
            and integer(location.get('rva')) and location['rva']<0x10000000,'V51_LISTENER_ADDRESS_REJECTED')

def verify(proof,version):
    need(type(version) is int and version>=0 and type(proof.get('version')) is int
        and proof['version']==version,'V51_LISTENER_VERSION_REJECTED')
    need(proof.get('status')=='LISTENERS_OBSERVED' and proof.get('registryUnchanged') is True
        and proof.get('bindingAndVersionUnchanged') is True,'V51_LISTENER_STATE_REJECTED')
    count=proof.get('registryCount');supported=proof.get('supportedCount');rows=proof.get('listeners')
    need(integer(count) and 0<count<=16 and integer(supported) and 0<supported<=count
        and isinstance(rows,list) and len(rows)==count,'V51_LISTENER_SCOPE_REJECTED')
    actual=0;queried=0
    for index,row in enumerate(rows):
        need(type(row.get('index')) is int and row['index']==index and row.get('interfaceVerified') is True,
            'V51_LISTENER_SCOPE_REJECTED')
        if row.get('present') is False:
            need(row.get('supportsNotification') is False and not any(k in row for k in
                ('unknown','notification','queryHresult','ownedQueryReferenceReleased','releaseReturn')),
                'V51_LISTENER_REFERENCE_REJECTED')
            continue
        need(row.get('present') is True and row.get('outputCanariesUnchanged') is True,
            'V51_LISTENER_SCOPE_REJECTED');queried+=1
        api(row.get('unknown'),3)
        if row.get('supportsNotification') is True:
            need(type(row.get('queryHresult')) is int and row['queryHresult']==0
                and row.get('ownedQueryReferenceReleased') is True and integer(row.get('releaseReturn')),
                'V51_LISTENER_REFERENCE_REJECTED')
            api(row.get('notification'),5);actual+=1
        else:
            need(row.get('supportsNotification') is False and type(row.get('queryHresult')) is int
                and row['queryHresult']==-2147467262 and row.get('notification') is None
                and row.get('ownedQueryReferenceReleased') is False and row.get('releaseReturn')==0,
                'V51_LISTENER_REFERENCE_REJECTED')
    need(actual==supported and type(proof.get('queryCalls')) is int and proof['queryCalls']==queried
        and type(proof.get('releaseCalls')) is int and proof['releaseCalls']==supported,
        'V51_LISTENER_REFERENCE_REJECTED')
    need(all(type(proof.get(k)) is int and proof[k]==0 for k in ('notificationHandlerInvocations',
        'selectedHandlerInvocations','sourceWrites','repositoryWrites','goldSaves','readonlySetterCalls')),
        'V51_LISTENER_MUTATION_REJECTED')
    return dict(passed=True,version=version,listenerCount=count,supportedCount=supported,
        ownedQueryReferencesReleased=True,queriedCount=queried,nullHoles=count-queried,
        notificationHandlerInvocations=0,writerAuthorized=False,
        notificationApis=[row['notification'] for row in rows if row['supportsNotification']])
