"""Validate actual stock notification of the exact FREE object, no write grant."""
from statistic_packet_guard_v54 import OBJECT,need

def verify(p,version):
    need(type(version) is int and version>=0 and type(p.get('version')) is int and p['version']==version,
        'V55_NOTIFY_VERSION_REJECTED')
    need(p.get('status')=='NOTIFICATION_OBSERVED' and p.get('objectId')==OBJECT
        and all(p.get(k) is True for k in ('canonicalSameAsGoldUi','exactStatisticGuidVerified','statisticLockFieldsEqual',
            'attachmentAndRegistryUnchanged','bindingAndVersionUnchanged')),'V55_NOTIFY_SCOPE_REJECTED')
    need(type(p.get('notificationHandlerInvocations')) is int and p['notificationHandlerInvocations']==1
        and p.get('callbackException') is False and p.get('ownedQueryReferenceReleased') is True
        and p.get('ownedOutputsReleased') is True,'V55_NOTIFY_CALLBACK_REJECTED')
    for name in ('before','after'):
        part=p.get(name)
        need(type(part) is dict and part.get('verified') is True and part.get('bufferReadOnly') is True
            and part.get('bufferDirty') is False and type(part.get('cachedGetterVerified')) is bool
            and type(part.get('cached')) is dict,'V55_NOTIFY_PERMISSION_REJECTED')
        if part['cachedGetterVerified']:
            need(type(part['cached'].get('documentReadOnly')) is bool and part['cached'].get('exactGoldObjectBound') is True
                and part['cached'].get('singleCacheEntryVerified') is True,'V55_NOTIFY_PERMISSION_REJECTED')
    need(p.get('captureDispatched') is False and all(type(p.get(k)) is int and p[k]==0
        for k in ('sourceWrites','repositoryWrites','goldSaves','readonlySetterCalls')),'V55_NOTIFY_MUTATION_REJECTED')
    return dict(passed=True,version=version,notificationHandlerInvocations=1,actualBufferGettersVerified=True,
        cachedGetterBeforeVerified=p['before']['cachedGetterVerified'],cachedGetterAfterVerified=p['after']['cachedGetterVerified'],
        freeBufferStayedReadOnly=True,ownedQueryReferenceReleased=True,writerAuthorized=False)
