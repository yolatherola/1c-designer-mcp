"""The real detached IDocument restoration is distinct from a readonly host."""
CLASS='5c84acf4-db1c-11d4-b008-004095e12de6'
def verify(observed,version):
    if observed.get('status')!='DETACHED_UNDO_VERIFIED' or observed.get('version')!=version or observed.get('factoryClassId')!=CLASS:raise ValueError('V63_SCOPE_REJECTED')
    for key in ['independentTextAndManagerAndDocument','nativeDocumentGettersKnown','initialEmpty','initialDocumentClean','initialWritable','actionBeginAccepted','insertionExact','documentModifiedAfterInsertion','actionClosed','undoAccepted','originalTextRestored','documentCleanAfterUndo','externalObjectNull','goldControlPreserved']:
        if observed.get(key) is not True:raise ValueError('V63_DOCUMENT_STATE_REJECTED')
    for key in ['exception','goldSourceApplyVerified','persistedGoldReadbackVerified']:
        if observed.get(key) is not False:raise ValueError('V63_UNBOUNDED_CLAIM_REJECTED')
    for key in ['localTextWrites','actionBeginCalls','actionCloseCalls','undoCalls']:
        if type(observed.get(key)) is not int or observed[key]!=1:raise ValueError('V63_DISPATCH_REJECTED')
    for key in ['goldSourceWrites','repositoryWrites','saveCalls','dirtyFlagWrites','databaseUpdates','businessCalls']:
        if type(observed.get(key)) is not int or observed[key]!=0:raise ValueError('V63_GOLD_MUTATION_REJECTED')
    if observed.get('markerCharacters')!=29:raise ValueError('V63_MARKER_REJECTED')
    return dict(verified=True,actualIndependentDocumentCleanRestored=True,localTextWrites=1,goldSourceWrites=0,goldSourceApplyVerified=False,persistedGoldReadbackVerified=False)
