"""Compare complete Opros metadata descriptors without printing source values.

External resources (modules/forms/templates) need their own body comparison.
Descriptor equality must never be advertised as a full configuration backup.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'tests'))
from saved_pilot_codec import parse,decode_packet

OBJECT='88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
REFERENCES=frozenset(('fb880e93-47d7-4127-9357-a20e69c17545','3daea016-69b7-4ed4-9453-127911372fe6'))
KINDS=REFERENCES|{'21c53e09-8950-4b5e-a6a0-1054f1bbc274','45e46cbc-3e24-4165-8b7b-cc98a6f80211','b544fc6a-2ba3-4885-8fb2-cb289fb6d65e'}
GUID=re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
# Observed on all 34 templates and 15 forms in the actual pinned Gold stream.
# These are primary identity fields, not a search for any matching UUID value.
REFERENCE_ID_PATHS={'3daea016-69b7-4ed4-9453-127911372fe6':(0,2,1,2),
                    'fb880e93-47d7-4127-9357-a20e69c17545':(0,1,1,1,2)}

def external_child_id(kind,child):
    if not isinstance(child,list) or len(child)!=2 or type(child[1]) is not int or child[1]!=0:
        raise ValueError('V47_REFERENCE_PROFILE_REJECTED')
    value=child
    for index in REFERENCE_ID_PATHS[kind]:
        if not isinstance(value,list) or len(value)<=index:raise ValueError('V47_REFERENCE_ID_PATH_REJECTED')
        value=value[index]
    return value

def summary(tree):
    nodes=0;depth=0;object_ids=0
    def visit(value,level):
        nonlocal nodes,depth,object_ids
        nodes+=1;depth=max(depth,level)
        if isinstance(value,list):
            for item in value:visit(item,level+1)
        elif isinstance(value,str) and value.lower()==OBJECT:object_ids+=1
    visit(tree,0)
    canonical=json.dumps(tree,ensure_ascii=False,separators=(',',':')).encode('utf-8')
    return dict(rootItems=len(tree),nodes=nodes,maxDepth=depth,objectIdOccurrences=object_ids,
                canonicalSha256=hashlib.sha256(canonical).hexdigest())

def compare(live:bytes,repository_packet:bytes):
    if not 0<len(live)<=4*1024**2:raise ValueError('V47_DESCRIPTOR_SIZE_REJECTED')
    try:current=parse(live.decode('utf-8-sig'))
    except UnicodeError as error:raise ValueError('V47_DESCRIPTOR_ENCODING_REJECTED') from error
    repository=decode_packet(repository_packet)
    left,right=summary(current),summary(repository)
    if left['objectIdOccurrences']!=1 or right['objectIdOccurrences']!=1:raise ValueError('V47_DESCRIPTOR_OBJECT_SCOPE_REJECTED')
    return dict(verified=True,descriptorEqual=current==repository,live=left,repository=right,
                liveBytes=len(live),repositoryPacketBytes=len(repository_packet),
                liveSha256=hashlib.sha256(live).hexdigest(),repositoryPacketSha256=hashlib.sha256(repository_packet).hexdigest(),
                comparison='all-parsed-values-order-and-strings-preserved',externalResourceBodiesCompared=False,
                persistedGoldReadbackVerified=False)

def document_profile(tree,*,repository):
    """Project only known separate repository children; retain all inline values."""
    if repository:
        if len(tree)!=8 or type(tree[0]) is not int or tree[0]!=1:raise ValueError('V47_REPOSITORY_PROFILE_REJECTED')
        tree=tree[1:]
    if len(tree)!=7 or not isinstance(tree[0],list) or type(tree[1]) is not int or tree[1]!=5:
        raise ValueError('V47_LIVE_PROFILE_REJECTED')
    kinds=set();child_ids=set();result=[tree[0],tree[1]];references=0
    for group in tree[2:]:
        if not isinstance(group,list) or len(group)<2 or group[0] not in KINDS or group[0] in kinds:
            raise ValueError('V47_CHILD_KIND_REJECTED')
        kind,count=group[:2];kinds.add(kind)
        if type(count) is not int or not 0<=count<=1024 or len(group)!=count+2:raise ValueError('V47_CHILD_COUNT_REJECTED')
        projected=[kind,count]
        for child in group[2:]:
            if kind in REFERENCES:
                if repository:
                    if not isinstance(child,str):raise ValueError('V47_REFERENCE_PROFILE_REJECTED')
                    uid=child
                else:
                    uid=external_child_id(kind,child)
                projected.append(uid);references+=1
            else:
                if not isinstance(child,list) or len(child)<2:raise ValueError('V47_INLINE_CHILD_REJECTED')
                # Inline native descriptors have their own nested identity
                # layout. Preserve the whole record; never interpret its first
                # field as the UUID-only separate-resource record layout.
                projected.append(child)
                continue
            if not isinstance(uid,str) or not GUID.fullmatch(uid) or uid in (OBJECT,'00000000-0000-0000-0000-000000000000') or uid in child_ids:raise ValueError('V47_CHILD_ID_REJECTED')
            child_ids.add(uid)
        result.append(projected)
    if kinds!=KINDS:raise ValueError('V47_CHILD_KINDS_INCOMPLETE')
    return result,references

def compare_document_profiles(live:bytes,repository_packet:bytes):
    result=compare(live,repository_packet)
    current=parse(live.decode('utf-8-sig'));repository=decode_packet(repository_packet)
    left,left_refs=document_profile(current,repository=False);right,right_refs=document_profile(repository,repository=True)
    result.update(rawDescriptorEqual=result['descriptorEqual'],descriptorEqual=left==right,
                  liveProjected=summary(left),repositoryProjected=summary(right),serializationProfilesCompatible=True,
                  liveExternalChildReferences=left_refs,repositoryExternalChildReferences=right_refs,
                  externalChildDescriptionsCompared=False,
                  comparison='repository-prefix-1-and-only-form-template-uuid-reference-projection',
                  repositoryObjectCaptureScopeVerified=left==right)
    return result
