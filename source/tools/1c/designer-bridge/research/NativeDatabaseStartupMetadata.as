// Applied DB metadata only: startup property URL shapes and two CM flag sets.
// Never reads module text/storage, creates a session, or invokes application code.
void ahDatabaseStartupMetadata() {
    bool smAdmitted=__STARTUP_METADATA_SCOPE_ADMITTED__,smVerified=false,smBefore=false,smAfter=false,smClean=false,smIntent=false,smPrefix=false,smException=false;
    string smOperation="__OPERATION_ID__",smScope="__SCOPE_SHA256__",smReason="SCOPE";
    string smProofPath="__PROOF_PATH__",smIntentPath="__NATIVE_STARTUP_METADATA_INTENT_PATH__";
    uint smBeforeCount=0,smAfterCount=0,smBindings=0,smStartupReads=0,smFlagReads=0,smUrlCalls=0,smCmResolutions=0;
    uint smPersistentBefore=0,smPersistentAfter=0,smSingleBefore=0,smSingleAfter=0;
    IConfigMngrUI@ smUi;IMDContainer@ smMain,smDb;IInfoBase@ smIb;IConfigMngr@ smManager;
    Designer@ smDesigner;IDispatch@ smDispatch;ITopLevelFrame@ smShell,smCore;
    array<IMDObject@> smTargets(3),smCmObjects(2);
    array<string> smTargetIds={"8daef957-4ae2-48a1-bf6c-b88163a076f5","176e2552-fd8b-4823-afc0-d17431f2fb7b","28ecdfc7-083e-4082-b272-efbf7152de5c"};
    array<string> smStartupIds={"9b7bbbae-9771-46f2-9e4d-2489e0ffc702","a4a9c1e2-1e54-4c7f-af06-4ca341198fac"};
    array<string> smFlagIds={"d12660a6-7298-4ae2-a332-b95a6459a280","6275a02e-96f0-4347-975a-2d661e6a0675","7dbb2bc7-6bae-4b81-91cb-681317272a0b","c474bab9-d13a-4fbd-bfb0-9214d6dc2fde","334033a1-6bda-4dba-bc6d-0095d1b66f0b","07ddee68-6fc0-4b88-9616-7792446d12b8"};
    array<string> smCategory(2,"UNOBSERVED"),smKeys(2,""),smHashes(2,"");
    array<int> smKinds(2,-1),smPropertyCodes(4,0);array<uint> smUrlCodes(4,0),smCharacters(2,0),smUtf8Bytes(2,0);
    array<bool> smNulls(2,true),smTypePresent(2,false),smExternal(2,false),smSupported(2,false),smHashKnown(2,false),smFlags(12,false);
    array<int> smFlagCodes(24,0),smReuseKinds(2,-1);array<IValue@> smReuseValues(2);
    array<string> smReuseCategories(2,"UNOBSERVED"),smReuseTypes(2,""),smReuseHashes(2,"");array<uint> smReuseBytes(2,0);
    array<bool> smReuseNulls(2,true),smReuseStable(2,false),smReuseEqualityAvailable(2,false);ExceptionCatcher smCatcher;
    {CppCatch smCaught("class core::Exception",ExceptionHandler(smCatcher.handle));
        do {
            if(!smAdmitted || smOperation.length!=32 || smScope.length!=64 || sizeof_ptr!=4 || ahStatusUi is null || !ahPipeScopeAlive()
                || ahGetCurrentProcessId()!=48936 || ahGetCurrentThreadId()!=8292 || ahFrameOwnerPidV211!=48936 || ahFrameOwnerTidV211!=8292)break;
            if(smProofPath!="F:/Projects/AH_1C/build/designer-hot-v233-"+smOperation+"/database-startup-metadata-proof.json"
                || smIntentPath!="F:/Projects/AH_1C/build/designer-hot-v233-"+smOperation+"/database-startup-metadata-intent.json")break;
            bool smHex=true;for(uint smN=0;smN<smOperation.length;smN++){uint ch=smOperation[smN];if(!((ch>=48 && ch<=57)||(ch>=97 && ch<=102)))smHex=false;}
            for(uint smN=0;smN<smScope.length;smN++){uint ch=smScope[smN];if(!((ch>=48 && ch<=57)||(ch>=97 && ch<=102)))smHex=false;}
            if(!smHex)break;
            // Intent precedes all published metadata getters; failure does not retry.
            smReason="INTENT";smIntent=ahWriteSample(smIntentPath,"{\"kind\":\"DATABASE_STARTUP_METADATA_INTENT\",\"operationId\":\""+smOperation+"\",\"scopeSha256\":\""+smScope+"\",\"maximumStartupPropertyReads\":4,\"maximumFlagPropertyReads\":24,\"maximumUrlGetterCalls\":4,\"moduleTextReads\":0,\"storageOpens\":0,\"newSessions\":0,\"nativeCommands\":0,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"patientReads\":0,\"businessCalls\":0}");
            if(!smIntent)break;
            @smUi=ahStatusUi;@smMain=smUi.getMDCont();smReason="MAIN_ROOT";
            if(!ahCatalogEditableV218(smMain) || smMain.id!=Guid("{218b5d00-7e10-486f-874c-73c2368ed5da}") || smMain.isModified() || smUi.isModified())break;
            for(uint smN=0;smN<3;smN++){
                @smTargets[smN]=smMain.objById(Guid("{"+smTargetIds[smN]+"}"));
                if(smTargets[smN] is null || smTargets[smN].isModified())break;smBeforeCount++;
            }
            if(smBeforeCount!=3)break;smBefore=true;smReason="DESIGNER_PREFIX";
            if(oneDesigner is null || oneAddinMgr !is null || dspWindows is null || mainFrame is null || coreMainFrame is null
                || oneDesigner._windows !is null || oneDesigner._metadata !is null || oneDesigner._develop !is null)break;
            @smDesigner=oneDesigner;@smDispatch=dspWindows;@smShell=mainFrame;@smCore=coreMainFrame;
            smPersistentBefore=idleHandlers.length;smSingleBefore=idleHandlersSingle.length;if(smPersistentBefore!=0 || smSingleBefore!=0)break;
            @smIb=getDefaultInfoBase();smReason="DATABASE_MANAGER";if(smIb is null)break;
            @smManager=smIb.getConfigMgr();if(smManager is null || uint(mem::addressOf(smManager))!=100051712
                || !ahCompactTableV108(mem::addressOf(smManager),"backend.dll",15589540,86))break;
            @smDb=smManager.getMDCont(0);smReason="DATABASE_ROOT";
            if(smDb is null || uint(mem::addressOf(smDb))!=1383504556 || smDb.id!=smMain.id || smDb.isModified()
                || !ahCompactTableV108(mem::addressOf(smDb),"backend.dll",15815188,60))break;
            for(uint smPass=0;smPass<2;smPass++){
                smReason="DATABASE_BINDING";IInfoBase@ smFreshIb=getDefaultInfoBase();if(smFreshIb is null)break;
                IConfigMngr@ smFreshManager=smFreshIb.getConfigMgr();if(smFreshManager is null)break;
                IMDContainer@ smFresh=smFreshManager.getMDCont(0);IConfigMngr@ smRound=smDb.getConfigMngr();
                if(smFresh is null || smRound is null || !ahCatalogSameV218(smFreshIb.unk,smIb.unk)
                    || !ahCatalogSameV218(smFreshManager.unk,smManager.unk) || !ahCatalogSameV218(smFresh.unk,smDb.unk)
                    || !ahCatalogSameV218(smRound.unk,smManager.unk) || uint(mem::addressOf(smFresh))!=1383504556
                    || smDb.isModified() || smMain.isModified() || smUi.isModified())break;
                uint smMapped=0;
                for(uint smIndex=0;smIndex<2;smIndex++){
                    smReason="STARTUP_PROPERTY";Value smValue;smStartupReads++;
                    int smCode=smDb.mdPropVal(Guid("{"+smStartupIds[smIndex]+"}"),smValue);
                    smPropertyCodes[smPass*2+smIndex]=smCode;
                    bool smNull=smValue.pValue is null,smHasType=false,smHasExternal=false,smUrlSupported=false,smHasHash=false;
                    int smKind=-1;uint smChars=0,smBytes=0,smUrlCode=0;string smType="NULL_VALUE",smKey="",smHash="";
                    if(!smNull){
                        // Special metadata values may provide IMDExtObj without
                        // IType. Record that shape instead of inventing a type.
                        IType@ smTypeValue=smValue.pValue.getType();smHasType=smTypeValue !is null;
                        if(smHasType)smKind=smTypeValue.getTypeKind();smType=smHasType?"NON_EXTERNAL_VALUE":"NON_EXTERNAL_NO_TYPE";
                        IMDExtObj@ smExt=smValue.pValue.unk;
                        if(smExt !is null){
                            smHasExternal=true;URL smUrl;smUrlCalls++;smUrlCode=smExt.url(smUrl);string smObserved=smUrl.url;
                            smChars=smObserved.length;smReason="URL_BOUND";if(smChars>4096)break;
                            utf8string smEncoded=smObserved.toUtf8();smBytes=smEncoded.length;if(smBytes>4096)break;
                            if(smBytes>0){MemoryBuffer smHashInput(smBytes);mem::memcpy(smHashInput.bytes,smEncoded.ptr,smBytes);smHash=ahTemplateRamShaV202(smHashInput,smBytes);if(smHash.length!=64)break;smHasHash=true;}
                            // Never expose a path, connection, or unknown URL spelling.
                            smUrlSupported=smChars==38 && smObserved.substr(36)==".0" && ahModuleUuidV225(smObserved.substr(0,36));
                            if(smUrlSupported){smKey=smObserved;smType="INTERNAL_UUID_ZERO";}else smType="UNSUPPORTED_URL";
                        }
                    }
                    smUrlCodes[smPass*2+smIndex]=smUrlCode;
                    if(smPass==0){smNulls[smIndex]=smNull;smTypePresent[smIndex]=smHasType;smExternal[smIndex]=smHasExternal;smKinds[smIndex]=smKind;smCategory[smIndex]=smType;
                        smKeys[smIndex]=smKey;smHashes[smIndex]=smHash;smCharacters[smIndex]=smChars;smUtf8Bytes[smIndex]=smBytes;smSupported[smIndex]=smUrlSupported;smHashKnown[smIndex]=smHasHash;}
                    else if(smPropertyCodes[smIndex]!=smCode || smUrlCodes[smIndex]!=smUrlCode || smNulls[smIndex]!=smNull || smTypePresent[smIndex]!=smHasType || smExternal[smIndex]!=smHasExternal
                        || smKinds[smIndex]!=smKind || smCategory[smIndex]!=smType || smKeys[smIndex]!=smKey || smHashes[smIndex]!=smHash
                        || smCharacters[smIndex]!=smChars || smUtf8Bytes[smIndex]!=smBytes || smSupported[smIndex]!=smUrlSupported || smHashKnown[smIndex]!=smHasHash)break;
                    smMapped++;
                }
                if(smMapped!=2)break;
                uint smFlagsSeen=0;
                for(uint smModule=0;smModule<2;smModule++){
                    smReason="COMMON_MODULE";IMDObject@ smCm=smDb.objById(Guid("{"+smTargetIds[smModule+1]+"}"));smCmResolutions++;
                    if(smCm is null || smCm.id!=Guid("{"+smTargetIds[smModule+1]+"}") || smCm.mdClass is null
                        || smCm.mdClass.id!=Guid("{0fe48980-252d-11d6-a3c7-0050bae0a776}") || smCm.mdParentLink is null || smCm.isModified())break;
                    IMDObject@ smParent=smCm.mdParentLink.getMDObject();if(smParent is null || !ahCatalogSameV218(smParent.unk,smDb.unk) || !ahCatalogLinkV218(smCm,smParent,smDb))break;
                    if(smPass==0)@smCmObjects[smModule]=smCm;else if(!ahCatalogSameV218(smCm.unk,smCmObjects[smModule].unk))break;
                    for(uint smFlag=0;smFlag<6;smFlag++){
                        uint smIndex=smModule*6+smFlag;Value smFlagValue;smReason="FLAG_PROPERTY";smFlagReads++;
                        smFlagCodes[smPass*12+smIndex]=smCm.mdPropVal(Guid("{"+smFlagIds[smFlag]+"}"),smFlagValue);
                        if(smFlag<5){
                            if(smFlagValue.pValue is null)break;IType@ smFlagType=smFlagValue.pValue.getType();bool smEnabled=false;
                            smReason="FLAG_TYPE";if(smFlagType is null || smFlagType.getTypeKind()!=tkBoolean || !smFlagValue.pValue.getBool(smEnabled))break;
                            if(smPass==0)smFlags[smIndex]=smEnabled;
                            else if(smFlags[smIndex]!=smEnabled || smFlagCodes[smIndex]!=smFlagCodes[12+smIndex])break;
                        }else{
                            // Return-value reuse is an enum in some configurations,
                            // not a sixth Boolean. Observe its type without guessing ordinal.
                            bool smReuseNull=smFlagValue.pValue is null;int smReuseKind=-1;string smReuseCategory="NULL_VALUE",smReuseType="",smReuseHash="";uint smReuseLength=0;
                            if(!smReuseNull){
                                IType@ smReuseValueType=smFlagValue.pValue.getType();smReason="REUSE_TYPE";if(smReuseValueType is null)break;
                                smReuseKind=smReuseValueType.getTypeKind();smReuseType=string(smReuseValueType.getClsid()).lowered();smReuseCategory="OTHER_VALUE";
                                if(smReuseKind==tkObject)smReuseCategory="OBJECT_OR_ENUM";
                                else if(smReuseKind==tkBoolean)smReuseCategory="BOOLEAN_VALUE";
                                else if(smReuseKind==tkNumeric)smReuseCategory="NUMERIC_VALUE";
                                else if(smReuseKind==tkUndefined)smReuseCategory="UNDEFINED_VALUE";
                                else if(smReuseKind==tkNull)smReuseCategory="NULL_KIND";
                                else if(smReuseKind==tkString){
                                    smReuseCategory="STRING_VALUE";v8string smReuseText;if(!smFlagValue.pValue.getString(smReuseText) || smReuseText.str.length>256)break;
                                    utf8string smReuseEncoded=smReuseText.str.toUtf8();smReuseLength=smReuseEncoded.length;if(smReuseLength>256)break;
                                    if(smReuseLength>0){MemoryBuffer smReuseHashInput(smReuseLength);mem::memcpy(smReuseHashInput.bytes,smReuseEncoded.ptr,smReuseLength);smReuseHash=ahTemplateRamShaV202(smReuseHashInput,smReuseLength);if(smReuseHash.length!=64)break;}
                                }
                            }
                            if(smPass==0){smReuseNulls[smModule]=smReuseNull;smReuseKinds[smModule]=smReuseKind;smReuseCategories[smModule]=smReuseCategory;
                                smReuseTypes[smModule]=smReuseType;smReuseHashes[smModule]=smReuseHash;smReuseBytes[smModule]=smReuseLength;@smReuseValues[smModule]=smFlagValue.pValue;}
                            else{
                                smReason="REUSE_CHANGED";
                                if(smReuseNulls[smModule]!=smReuseNull || smReuseKinds[smModule]!=smReuseKind || smReuseCategories[smModule]!=smReuseCategory
                                    || smReuseTypes[smModule]!=smReuseType || smReuseHashes[smModule]!=smReuseHash || smReuseBytes[smModule]!=smReuseLength
                                    || smFlagCodes[smIndex]!=smFlagCodes[12+smIndex])break;
                                if(smReuseNull)smReuseStable[smModule]=true;
                                else{
                                    IValueEqualityV231@ smEquality=smReuseValues[smModule].unk;smReuseEqualityAvailable[smModule]=smEquality !is null;
                                    if(smEquality !is null){if(!smEquality.isEqual(smFlagValue.pValue))break;smReuseStable[smModule]=true;}
                                    else if(smReuseKind==tkString)smReuseStable[smModule]=true;
                                }
                            }
                        }
                        smFlagsSeen++;
                    }
                    if(smFlagsSeen!=(smModule+1)*6)break;
                }
                if(smFlagsSeen!=12 || smDb.isModified() || smMain.isModified() || smUi.isModified())break;
                smBindings++;
            }
            if(smBindings!=2 || smStartupReads!=4 || smFlagReads!=24 || smCmResolutions!=4)break;smReason="NONE";
        }while(false);
    }
    if(smCatcher.hasException){smException=true;smReason="NATIVE_EXCEPTION";}
    {ExceptionCatcher smFinalCatcher;CppCatch smFinalCaught("class core::Exception",ExceptionHandler(smFinalCatcher.handle));
        smPersistentAfter=idleHandlers.length;smSingleAfter=idleHandlersSingle.length;
        smPrefix=smDesigner !is null && oneDesigner is smDesigner && dspWindows is smDispatch && mainFrame is smShell && coreMainFrame is smCore && oneAddinMgr is null
            && smDesigner._windows is null && smDesigner._metadata is null && smDesigner._develop is null;
        if(smBefore && smUi !is null && smMain !is null && ahStatusUi is smUi && ahPipeScopeAlive() && !smUi.isModified() && !smMain.isModified()
            && ahGetCurrentProcessId()==48936 && ahGetCurrentThreadId()==8292){
            IMDContainer@ smMainAfter=smUi.getMDCont();IConfigMngr@ smManagerAfter;IMDContainer@ smDbAfter;
            if(smIb !is null)@smManagerAfter=smIb.getConfigMgr();if(smManagerAfter !is null)@smDbAfter=smManagerAfter.getMDCont(0);
            if(smMainAfter !is null && smDbAfter !is null && smManagerAfter !is null && smDb !is null
                && ahCatalogSameV218(smMainAfter.unk,smMain.unk) && ahCatalogSameV218(smDbAfter.unk,smDb.unk)
                && ahCatalogSameV218(smManagerAfter.unk,smManager.unk) && !smDb.isModified()){
                for(uint smN=0;smN<3;smN++){IMDObject@ smTarget=smMainAfter.objById(Guid("{"+smTargetIds[smN]+"}"));
                    if(smTarget is null || smTargets[smN] is null || smTarget.isModified() || smTargets[smN].isModified() || !ahCatalogSameV218(smTarget.unk,smTargets[smN].unk))break;smAfterCount++;}
                smAfter=smAfterCount==3;
                for(uint smN=0;smN<2;smN++)if(smCmObjects[smN] is null || smCmObjects[smN].isModified())smAfter=false;
            }
        }
        if(smFinalCatcher.hasException){smException=true;smAfter=false;}
    }
    @smDb=null;@smManager=null;@smIb=null;@smMain=null;@smUi=null;@smDesigner=null;@smDispatch=null;@smShell=null;@smCore=null;
    for(uint smN=0;smN<3;smN++)@smTargets[smN]=null;for(uint smN=0;smN<2;smN++)@smCmObjects[smN]=null;
    for(uint smN=0;smN<2;smN++)@smReuseValues[smN]=null;
    smClean=smDb is null && smManager is null && smIb is null && smMain is null && smUi is null && smDesigner is null && smDispatch is null && smShell is null && smCore is null;
    for(uint smN=0;smN<3;smN++)if(smTargets[smN] !is null)smClean=false;for(uint smN=0;smN<2;smN++)if(smCmObjects[smN] !is null)smClean=false;
    for(uint smN=0;smN<2;smN++)if(smReuseValues[smN] !is null)smClean=false;
    smVerified=smAdmitted && smReason=="NONE" && smIntent && smBefore && smAfter && smPrefix && smClean && !smException && smBindings==2
        && smPersistentBefore==0 && smPersistentAfter==0 && smSingleBefore==0 && smSingleAfter==0;
    string smStartup="[",smFlagRows="[",smReuseRows="[";
    for(uint smN=0;smN<2;smN++)smStartup+=(smN==0?"":",")+"{\"propertyId\":\""+smStartupIds[smN]+"\",\"typeCategory\":\""+smCategory[smN]+"\",\"typeKind\":"+smKinds[smN]+",\"typePresent\":"+smTypePresent[smN]+",\"valueNull\":"+smNulls[smN]
        +",\"externalObjectPresent\":"+smExternal[smN]+",\"propertyReturnCodes\":["+smPropertyCodes[smN]+","+smPropertyCodes[2+smN]+"],\"urlReturnCodes\":["+smUrlCodes[smN]+","+smUrlCodes[2+smN]+"]"
        +",\"canonicalInternalUrl\":\""+smKeys[smN]+"\",\"urlCharacters\":"+smCharacters[smN]+",\"urlUtf8Bytes\":"+smUtf8Bytes[smN]+",\"urlSha256\":\""+smHashes[smN]+"\",\"urlHashKnown\":"+smHashKnown[smN]+",\"urlSupported\":"+smSupported[smN]+"}";
    for(uint smModule=0;smModule<2;smModule++)for(uint smFlag=0;smFlag<5;smFlag++){uint smN=smModule*6+smFlag;smFlagRows+=(smModule==0 && smFlag==0?"":",")+"{\"objectId\":\""+smTargetIds[smModule+1]+"\",\"propertyId\":\""+smFlagIds[smFlag]+"\",\"value\":"+smFlags[smN]+",\"propertyReturnCodes\":["+smFlagCodes[smN]+","+smFlagCodes[12+smN]+"]}";}
    for(uint smN=0;smN<2;smN++)smReuseRows+=(smN==0?"":",")+"{\"objectId\":\""+smTargetIds[smN+1]+"\",\"propertyId\":\""+smFlagIds[5]+"\",\"typeCategory\":\""+smReuseCategories[smN]+"\",\"typeKind\":"+smReuseKinds[smN]+",\"typeId\":\""+smReuseTypes[smN]+"\",\"valueNull\":"+smReuseNulls[smN]+",\"stringUtf8Bytes\":"+smReuseBytes[smN]+",\"stringSha256\":\""+smReuseHashes[smN]+"\",\"valueStabilityVerified\":"+smReuseStable[smN]+",\"equalityInterfaceAvailable\":"+smReuseEqualityAvailable[smN]+",\"propertyReturnCodes\":["+smFlagCodes[smN*6+5]+","+smFlagCodes[12+smN*6+5]+"]}";
    smStartup+="]";smFlagRows+="]";smReuseRows+="]";
    string smProof="{\"kind\":\"DATABASE_STARTUP_METADATA_NATIVE\",\"operationId\":\""+smOperation+"\",\"scopeSha256\":\""+smScope+"\",\"phase\":\"METADATA_ONLY\",\"status\":\""+(smVerified?"DATABASE_STARTUP_METADATA_OBSERVED":"REFUSED")+"\",\"verified\":"+smVerified+",\"reason\":\""+smReason+"\",\"nativeIntentWritten\":"+smIntent
        +",\"beforeRootAndTargetsClean\":"+smBefore+",\"afterRootAndTargetsClean\":"+smAfter+",\"beforeTargetsClean\":"+smBeforeCount+",\"afterTargetsClean\":"+smAfterCount+",\"designerPrefixPreserved\":"+smPrefix+",\"typedHandlesCleared\":"+smClean+",\"exceptionObserved\":"+smException
        +",\"configurationSourceDomain\":\"DATABASE\",\"databaseManager\":100051712,\"databaseSource\":1383504556,\"bindingPasses\":"+smBindings+",\"startupPropertyReads\":"+smStartupReads+",\"flagPropertyReads\":"+smFlagReads+",\"urlGetterCalls\":"+smUrlCalls+",\"commonModuleResolutions\":"+smCmResolutions+",\"startupProperties\":"+smStartup+",\"commonModuleFlags\":"+smFlagRows+",\"commonModuleReuse\":"+smReuseRows
        +",\"persistentBefore\":"+smPersistentBefore+",\"persistentAfter\":"+smPersistentAfter+",\"singleBefore\":"+smSingleBefore+",\"singleAfter\":"+smSingleAfter+",\"startupReviewed\":false,\"sourceKindBranchRuntimeVerified\":false,\"moduleTextReads\":0,\"storageOpens\":0,\"newSessions\":0,\"nativeCommands\":0,\"sourceWrites\":0,\"configurationSaves\":0,\"databaseUpdates\":0,\"repositoryMutations\":0,\"patientReads\":0,\"businessCalls\":0,\"queryExecutions\":0,\"editorHelperCalls\":0}";
    ExceptionCatcher smProofCatcher;{CppCatch smProofCaught("class core::Exception",ExceptionHandler(smProofCatcher.handle));if(smProof.toUtf8().length<=16384)ahWriteSample(smProofPath,smProof);}
}
