"""Verify readonly attachment/canonical identity observations; no write grant."""
from capture_listeners_guard_v51 import api,integer

def need(condition,code):
    if not condition:raise ValueError(code)

def verify(proof,version):
    need(type(version) is int and version>=0 and type(proof.get('version')) is int
        and proof['version']==version,'V52_STATE_VERSION_REJECTED')
    need(proof.get('status')=='STATE_OBSERVED' and proof.get('attachmentAndRegistryUnchanged') is True
        and proof.get('bindingAndVersionUnchanged') is True,'V52_STATE_BINDING_REJECTED')
    need(type(proof.get('listenerMatches')) is int and proof['listenerMatches']==1
        and integer(proof.get('listenerRegistryCount')) and 0<proof['listenerRegistryCount']<=16
        and proof.get('listenerAttachmentOffsets')==[16,20]
        and proof.get('editorInterfaceIid')=='1051f428-77fb-4228-8e87-bb3999417ef1','V52_STATE_SCOPE_REJECTED')
    for name,slots in (('editorInterface',15),('attachedCanonical',3),('uiCanonical',3),('managerCanonical',3)):
        part=proof.get(name)
        need(isinstance(part,dict) and part.get('verified') is True and type(part.get('queryHresult')) is int
            and part['queryHresult']==0 and part.get('outputCanariesUnchanged') is True
            and part.get('ownedQueryReferenceReleased') is True and integer(part.get('releaseReturn')),
            'V52_STATE_REFERENCE_REJECTED')
        try:api(part.get('api'),slots)
        except ValueError:raise ValueError('V52_STATE_API_REJECTED') from None
    need(all(type(proof.get(k)) is int and proof[k]==4 for k in ('queryCalls','releaseCalls')),
        'V52_STATE_REFERENCE_REJECTED')
    need(all(type(proof.get(k)) is bool for k in ('canonicalSameAsGoldUi','canonicalSameAsGoldManager')),
        'V52_STATE_BINDING_REJECTED')
    need(all(type(proof.get(k)) is int and proof[k]==0 for k in ('notificationHandlerInvocations',
        'permissionCallbackInvocations','sourceWrites','repositoryWrites','goldSaves','readonlySetterCalls')),
        'V52_STATE_MUTATION_REJECTED')
    table=proof['editorInterface']['api']
    return dict(passed=True,version=version,editorInterface=table,
        canonicalSameAsGoldUi=proof['canonicalSameAsGoldUi'],canonicalSameAsGoldManager=proof['canonicalSameAsGoldManager'],
        canonicalBindingProved=proof['canonicalSameAsGoldUi'] or proof['canonicalSameAsGoldManager'],
        permissionCallbackAddress=table['slots'][7],batchNotificationAddress=table['slots'][14],
        ownedQueryReferencesReleased=4,permissionCallbackInvocations=0,writerAuthorized=False)
