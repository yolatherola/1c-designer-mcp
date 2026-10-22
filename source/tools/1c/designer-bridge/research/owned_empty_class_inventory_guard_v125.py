"""Pure class-definition observations, never empty-object CRUD or a writer."""
import json
import re

LIMIT=8192
KINDS=(('Document','061d872a-5787-460e-95ac-ed74ea3a3e84'),
       ('Catalog','cf4abea6-37b2-11d4-940f-008048da11f9'))
SLOTS=('queryInterface','addRef','release','getId','getName','getClassName','factory')
ROW=('requestedKind','requestedClassId','actualClassId','lookupReturned','idRead','idMatches',
     'pointerPageVerified','tablePageVerified','table','slots')
FLAGS=('scopeBeforeVerified','scopeAfterVerified','bindingAndVersionUnchanged','selectedSourcePreserved',
       'classHandlesScoped','classHandlesDistinct','scopeExited','nativeException','returnUnknown','mdServiceReturned')
ZERO=('classNameReads','objectFactoryCalls','queryInterfaceCalls','rawAdoptions','metadataSetters','ownedDeletes',
      'configurationWrites','configurationSaves','configurationExports','configurationImports',
      'repositoryMutations','databaseUpdates','businessCalls')
FALSE=('catalogFactoryAbiVerified','emptyCrudVerified','attributeCrudVerified','typePropertiesVerified',
       'nativePermit','writerAuthorized')
KEYS=('status','version','mdServiceRequests','classLookupCalls','classIdReads','rows')+FLAGS+ZERO+FALSE


def need(ok,code):
    if not ok:raise ValueError('V125_'+code)


def parse_result(raw):
    def pairs(items):
        out={}
        for key,value in items:
            need(key not in out,'JSON_REJECTED');out[key]=value
        return out
    def invalid(_):raise ValueError('V125_JSON_REJECTED')
    need(type(raw) is bytes and 0<len(raw)<=LIMIT,'JSON_REJECTED')
    try:result=json.loads(raw.decode('utf8'),object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
    except (ValueError,UnicodeError,RecursionError):raise ValueError('V125_JSON_REJECTED') from None
    need(type(result) is dict,'JSON_REJECTED');return result


def _address(value):
    if value is None:return
    need(type(value) is dict and set(value)=={'module','rva'}
         and type(value['module']) is str and re.fullmatch('[a-z0-9_.-]{1,64}\\.(dll|exe)',value['module'])
         and type(value['rva']) is int and 0<=value['rva']<=0x7fffffff,'ADDRESS_REJECTED')


def verify(info,version):
    """Accept bounded SDK class lookup only; caller proves source/lease/PID.

    A mapped factory slot is data, not verified ABI or authorization to call it.
    No class name is read: requestedKind is the fixed request's label.
    """
    need(type(info) is dict and set(info)==set(KEYS),'SHAPE_REJECTED')
    need(type(version) is int and 0<=version<=0x7fffffff and type(info['version']) is int
         and info['version']==version,'VERSION_REJECTED')
    need(info['status']=='EMPTY_CLASS_INVENTORY_OBSERVED_V125','STATUS_REJECTED')
    need(all(type(info[k]) is bool for k in FLAGS),'FLAG_TYPE_REJECTED')
    need(info['nativeException'] is False and info['returnUnknown'] is False,'UNKNOWN_REJECTED')
    need(all(info[k] is True for k in FLAGS if k not in
         ('nativeException','returnUnknown','classHandlesDistinct','mdServiceReturned')),'SCOPE_REJECTED')
    need(all(type(info[k]) is int and info[k]==0 for k in ZERO),'WRITES_REJECTED')
    need(all(info[k] is False for k in FALSE),'CLAIM_REJECTED')
    need(type(info['mdServiceRequests']) is int and info['mdServiceRequests']==1
         and type(info['classLookupCalls']) is int and info['classLookupCalls']==(2 if info['mdServiceReturned'] else 0)
         and type(info['classIdReads']) is int and 0<=info['classIdReads']<=2,'CALL_COUNT_REJECTED')
    rows=info['rows'];need(type(rows) is list and len(rows)==2,'ROWS_REJECTED')
    present=0;complete=True
    for row,(kind,guid) in zip(rows,KINDS):
        need(type(row) is dict and set(row)==set(ROW)
             and row['requestedKind']==kind and row['requestedClassId']==guid,'ROW_SCOPE_REJECTED')
        need(all(type(row[k]) is bool for k in ('lookupReturned','idRead','idMatches','pointerPageVerified','tablePageVerified')),
             'ROW_TYPE_REJECTED')
        need(type(row['slots']) is dict and set(row['slots'])==set(SLOTS),'SLOTS_REJECTED')
        _address(row['table'])
        for value in row['slots'].values():_address(value)
        if row['lookupReturned']:
            present+=1
            need(info['mdServiceReturned'] is True and row['idRead'] is True and type(row['actualClassId']) is str
                 and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',row['actualClassId']),
                 'CLASS_RETURN_REJECTED')
            need(row['idMatches'] is (row['actualClassId']==guid),'CLASS_ID_REJECTED')
            need(not row['tablePageVerified'] or row['pointerPageVerified'],'PAGE_ORDER_REJECTED')
            if not row['tablePageVerified']:
                need(row['table'] is None and all(v is None for v in row['slots'].values()),'UNREADABLE_REJECTED')
            complete=complete and row['idMatches'] and row['pointerPageVerified'] and row['tablePageVerified']
        else:
            need(row['actualClassId'] is None and all(row[k] is False for k in
                 ('idRead','idMatches','pointerPageVerified','tablePageVerified'))
                 and row['table'] is None and all(v is None for v in row['slots'].values()),'NULL_RETURN_REJECTED')
            complete=False
    need(info['classIdReads']==present and info['classHandlesDistinct'] is (present==2),'LIFETIME_COUNT_REJECTED')
    return dict(verified=bool(complete),classInventoryObserved=True,catalogFactoryAbiVerified=False,
                classNamesObserved=False,emptyCrudVerified=False,nativePermit=False,writerAuthorized=False,
                requiredBeforeFactory=('exact-class-table-and-whole-factory','counted-output-ABI',
                                      'independent-empty-MemoryFile','created-only-registry','own-only-delete'))
