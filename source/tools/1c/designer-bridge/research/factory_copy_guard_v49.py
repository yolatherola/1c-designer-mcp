"""Validate bounded native factory evidence; this cannot authorize a writer."""
DOC='88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'

def require(value,code):
    if not value:raise ValueError(code)

def integer(value):return type(value) is int

def verify_start(proof,expected_version):
    require(integer(expected_version) and expected_version>=0 and proof.get('version')==expected_version
        and integer(proof.get('version')),'V49_FACTORY_VERSION_REJECTED')
    require(proof.get('status')=='FACTORY_COPIES_HELD'
        and all(proof.get(k) is True for k in ('bindingAndVersionUnchanged','recordFieldsAndIndependenceVerified')),
        'V49_FACTORY_COPY_UNVERIFIED')
    require(all(integer(proof.get(k)) and proof[k]==0 for k in
        ('selectedHandlerInvocations','sourceWrites','repositoryWrites','goldSaves')),'V49_FACTORY_MUTATION_REJECTED')
    maps=[];present=0;absent=0
    for phase,operation in (('capturePlan',1),('cancelPlan',3)):
        plan=proof.get(phase,{})
        require(plan.get('operation')==operation and integer(plan.get('operation'))
            and plan.get('allMapsBoundedToRequested') is True,'V49_FACTORY_PLAN_REJECTED')
        for name in ('selected','filtered','application'):
            part=plan.get(name,{})
            require(part.get('verified') is True and integer(part.get('count')) and 0<=part['count']<=1,
                'V49_FACTORY_MAP_REJECTED')
            if part.get('present') is False:
                require(part['count']==0 and not part.get('records'),'V49_FACTORY_MAP_REJECTED');absent+=1
            else:
                require(part.get('exactRequestedOnly') is True,'V49_FACTORY_SCOPE_REJECTED');present+=1
                rows=part.get('records')
                require(isinstance(rows,list) and len(rows)==part['count'],'V49_FACTORY_MAP_REJECTED')
                for row in rows:
                    require(isinstance(row,dict) and isinstance(row.get('key'),str) and isinstance(row.get('id'),str)
                        and row['key'].strip('{}').lower()==DOC and row['id']==row['key'],
                        'V49_FACTORY_SCOPE_REJECTED')
                    require(integer(row.get('versionNumber')) and row['versionNumber'] in (-1,expected_version),
                        'V49_FACTORY_RECORD_VERSION_REJECTED')
            maps.append(dict(phase=phase,map=name,count=part['count'],present=part.get('present') is not False))
    require(present>0 and all(integer(proof.get(k)) for k in ('heldCopies','absentInputs','factoryCalls','releases','releaseZeroWitnesses'))
        and proof['heldCopies']==present and proof['absentInputs']==absent and proof['factoryCalls']==2*present
        and proof['releases']==present and proof['releaseZeroWitnesses']==present,'V49_FACTORY_OWNERSHIP_REJECTED')
    return dict(version=expected_version,heldCopies=present,factoryCalls=proof['factoryCalls'],maps=maps,
        nativeOwnedMapsAndRecordFieldsVerified=True,selectedHandlerInputsEligibilityProved=False,writerAuthorized=False)

def verify_finish(start,proof):
    require(proof.get('status')=='FACTORY_LIFETIME_VERIFIED'
        and all(proof.get(k) is True for k in ('crossCallbackCopiesSurvived','originalRecordFieldsUnchanged',
            'allOwnCopiesReleased','bindingAndVersionUnchanged')),'V49_FACTORY_LIFETIME_UNVERIFIED')
    require(integer(proof.get('version')) and proof['version']==start['version'],'V49_FACTORY_VERSION_REJECTED')
    require(all(integer(proof.get(k)) and proof[k]==0 for k in
        ('selectedHandlerInvocations','sourceWrites','repositoryWrites','goldSaves')),'V49_FACTORY_MUTATION_REJECTED')
    require(all(integer(proof.get(k)) and proof[k]==start['factoryCalls'] for k in
        ('factoryCalls','releases','releaseZeroWitnesses')),'V49_FACTORY_OWNERSHIP_REJECTED')
    require(proof.get('unlimitedLifetimeProved') is False,'V49_FACTORY_UNBOUNDED_CLAIM_REJECTED')
    return dict(start,passed=True,crossCallbackLifetimeVerified=True,allOwnCopiesReleased=True,
        releases=proof['releases'],releaseZeroWitnesses=proof['releaseZeroWitnesses'],unlimitedLifetimeProved=False)
