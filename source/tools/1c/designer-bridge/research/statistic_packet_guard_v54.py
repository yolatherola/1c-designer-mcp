"""Verify an exact, independently observed statistic packet; never grant writes."""
import uuid

OBJECT='88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
ZERO='00000000-0000-0000-0000-000000000000'
def need(condition,code):
    if not condition:raise ValueError(code)

def verify(p,version):
    need(type(version) is int and version>=0 and type(p.get('version')) is int and p['version']==version
        and type(p.get('statisticVersion')) is int and p['statisticVersion']==version,'V54_PACKET_VERSION_REJECTED')
    need(p.get('status')=='PACKET_OBSERVED' and p.get('objectId')==OBJECT and p.get('exactStatisticGuidVerified') is True
        and type(p.get('statisticCount')) is int and p['statisticCount']==1,'V54_PACKET_SCOPE_REJECTED')
    need(p.get('bindingAndVersionUnchanged') is True and p.get('independentStatisticUnchanged') is True
        and p.get('statisticFieldsEqual') is True and type(p.get('wholeStatisticBytesEqual')) is bool
        and type(p.get('meaningfulStatisticBytes')) is int and p['meaningfulStatisticBytes']==21
        and type(p.get('reviseDateEqual')) is bool,'V54_PACKET_STATISTIC_REJECTED')
    try:owner=str(uuid.UUID(p['revisorId'].strip('{}')))
    except (ValueError,TypeError,KeyError,AttributeError):raise ValueError('V54_PACKET_STATISTIC_REJECTED') from None
    need(type(p.get('revised')) is bool and p['revised']==(owner!=ZERO),'V54_PACKET_STATISTIC_REJECTED')
    need(p.get('auxiliaryCollectionsBounded') is True
        and all(type(p.get(k)) is int and 0<=p[k]<=16 for k in ('userCount','bindingCount'))
        and p.get('outputCanariesUnchanged') is True and p.get('inputVectorUnchanged') is True,'V54_PACKET_OUTPUT_REJECTED')
    differences=p.get('differingStatisticOffsets')
    need(type(differences) is list and all(type(n) is int and (n in (5,6,7) or 24<=n<32) for n in differences)
        and len(set(differences))==len(differences) and p['wholeStatisticBytesEqual']==(len(differences)==0)
        and p['reviseDateEqual']==(not any(n>=24 for n in differences)),
        'V54_PACKET_STATISTIC_REJECTED')
    need(p.get('ownedOutputsReleased') is True and all(type(p.get(k)) is int and p[k]==2
        for k in ('nativeMapsConstructed','nativeMapsDestructed')),'V54_PACKET_OWNERSHIP_REJECTED')
    need(type(p.get('packetReadCalls')) is int and p['packetReadCalls']==1 and type(p.get('elapsedMs')) is int
        and p['elapsedMs']>=0,'V54_PACKET_CALL_REJECTED')
    need(all(type(p.get(k)) is int and p[k]==0 for k in ('notificationHandlerInvocations','sourceWrites',
        'repositoryWrites','goldSaves','readonlySetterCalls')),'V54_PACKET_MUTATION_REJECTED')
    return dict(passed=True,version=version,exactStatisticGuidVerified=True,meaningfulStatisticBytes=21,
        reviseDateEqual=p['reviseDateEqual'],dateDiscrepancyExplained=False,lockGenerationVerified=False,
        wholeStatisticBytesEqual=p['wholeStatisticBytesEqual'],nativeMapsDestructed=2,ownedOutputsReleased=True,
        packetReadCalls=1,elapsedMs=p['elapsedMs'],notificationHandlerInvocations=0,writerAuthorized=False)
