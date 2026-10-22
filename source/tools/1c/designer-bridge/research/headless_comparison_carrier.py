"""New derivative: pinned core/adapter + typed CPP epoch, pure C generation."""
from pathlib import Path
import hashlib
import comparison_cpp_exception_type_epoch as epoch
import comparison_headless_factory_primary as factory
import comparison_headless_execute_primary as headless
import comparison_result_creation_primary as creation
import comparison_update_other_managers_read as update

HERE=Path(__file__).resolve().parent
CORE_SHA='b39a89fc04a4c3dd456dee9be531bff789a33550b7dff7f13dcc8e0622e2a45a'
TREE_SHA='983c56d1876630fa4e3cc60733bbe0fc437423ada60b4042bbfc4056dfc42640'
EPOCH_SHA='e39d7fe335be118d3491317187654b884101fc1cfc7e0b743ab4dc76cec893c4'


def need(ok,code):
 if not ok:raise ValueError('HEADLESS_CARRIER_'+code)


def render():
 need(hashlib.sha256(Path(epoch.__file__).read_bytes()).hexdigest()==EPOCH_SHA,'EPOCH_PIN')
 tree=(HERE/'native_comparison_tree_projection.h').read_bytes();core=(HERE/'native_headless_comparison_core.h').read_bytes()
 need(hashlib.sha256(tree).hexdigest()==TREE_SHA and hashlib.sha256(core).hexdigest()==CORE_SHA,'CORE_TREE_PIN')
 # All inputs are fixed installed DLL units, not app source or a runtime patch.
 units={}
 _,factory_units=factory.verify_primary()
 for name,(module,rva,size,pin) in factory.SPANS.items():units[module,rva]=factory_units[name]
 _,headless_units=headless.verify_primary()
 for name,(module,rva,size,pin) in headless.SPANS.items():units[module,rva]=headless_units[name]
 _,creation_units,malloc_wrapper=creation.verify_primary()
 for name,(rva,size,pin) in creation.SPANS.items():units['frntend.dll',rva]=creation_units[name]
 units['nuke83.dll',0x1080]=malloc_wrapper
 update.verify_primary();image=creation.PE('config.dll')
 for name,(rva,size,pin) in update.SPANS.items():
  at=image.offset(image.base+rva);units['config.dll',rva]=image.data[at:at+size]
 checks=[];declarations=[]
 for index,((module,rva),raw) in enumerate(sorted(units.items())):
  need(0<len(raw)<=4096,'CODE_UNIT_BOUND')
  declarations.append('static const uint8_t hpcPin%d[]={%s};'%(index,','.join(str(b) for b in raw)))
  checks.append('hpc_match(L"%s",0x%x,hpcPin%d,sizeof(hpcPin%d))'%(module,rva,index,index))
 code=epoch.render().decode()
 code=code.replace('if(GetCurrentThreadId()!=sdkGuiThread)rc=110;',
                   'if(GetCurrentThreadId()!=sdkGuiThread || sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD)rc=110;')
 code=code.replace('if(!valid && diagnostic[0]==0)',
                   'if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;\n if(!valid && diagnostic[0]==0)')
 need(code.count('sdkGuiThread!=AH_SDK_EXPECTED_GUI_THREAD')==1 and code.count('if(thread!=AH_SDK_EXPECTED_GUI_THREAD)valid=FALSE;')==1,'GUI_GUARDS')
 core_text=core.decode().replace('#include "native_comparison_tree_projection.h"','')
 adapter=(HERE/'NativeHeadlessComparisonAdapter.c.inc').read_text('utf-8')
 return (code+'\n'+tree.decode()+'\n'+core_text+'\n'+adapter+'\n'+'\n'.join(declarations)
         +'\nstatic int hpc_verify_code(void){return '+' &&\n '.join(checks)+';}\n').encode()
