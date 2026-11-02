// 3.3b: guarded private BODY descriptor + native owned-model rebuild. See README.
// Included after the unchanged 2.9c logging helpers and before its impact hook.
namespace BodyProbe {
struct MBI { void* base; void* allocationBase; DWORD allocationProtect;
    SIZE_T size; DWORD state; DWORD protect; DWORD type; };
using QueryFn=SIZE_T(WINAPI*)(const void*,MBI*,SIZE_T);
static QueryFn query=nullptr;
static uptr rangeBegin=0,rangeEnd=0;static u32 queryCount=0;
static void resetReadCache(){rangeBegin=rangeEnd=0;queryCount=0;}

static bool readable(uptr p,u32 n){
    if(!query||p<0x10000u||!n||p+n<p)return false;
    uptr end=p+n;
    if(p>=rangeBegin&&end<=rangeEnd)return true;
    while(p<end){
        MBI m={};++queryCount;if(query((void*)p,&m,sizeof(m))!=sizeof(m))return false;
        u32 prot=m.protect&255u;
        if(m.state!=MEM_COMMIT||(m.protect&0x100u)||
           !(prot==2||prot==4||prot==8||prot==0x20||prot==0x40||prot==0x80))return false;
        uptr next=(uptr)m.base+m.size;
        if(next<=p)return false;rangeBegin=(uptr)m.base;rangeEnd=next;p=next<end?next:end;
    }return true;
}
template<class T> static bool read(uptr p,T& v){
    if(!readable(p,sizeof(T)))return false;
    const volatile u8* s=(const volatile u8*)p;u8* d=(u8*)&v;
    for(u32 i=0;i<sizeof(T);++i)d[i]=s[i];return true;
}
static void val(const char* key,u32 x){LB l;I(l);S(l,"BODY_AUDIT ");S(l,key);S(l,"=");HX(l,x);S(l,"\r\n");LogRaw(l.b);}
static void end(const char* why){LB l;I(l);S(l,"BODY_AUDIT_END result=");S(l,why);S(l," virtualCalls=0\r\n");LogRaw(l.b);}
static u32 hash(const char* s,u32 h=0xffffffffu){while(*s)h=h*33u+(u8)*s++;return h;}
static bool stringHash(uptr p,u32& h){for(u32 i=0;i<128;++i){u8 c;if(!read(p+i,c))return false;if(!c)return true;h=h*33u+c;}return false;}
static bool signature(uptr p,const u8* s,u32 n){if(!readable(p,n))return false;for(u32 i=0;i<n;++i)if(((volatile u8*)p)[i]!=s[i])return false;return true;}
// Exact relocation-free function body from the user's NFSMWUnlimiter.asi RVA 4DAC0.
// Recognize one direct E9 only. Never execute it or follow an unknown chain.
static const u8 unlimiterOwnerBody[]={0x8b,0x41,0x08,0x85,0xc0,0x74,0x17,0x8b,0x10,0x85,0xd2,0x74,0x11,0x56,0x8b,0x74,0x24,0x08,0x56,0x51,0x8b,0xc8,0x3e,0xff,0x52,0x04,0x5e,0xc2,0x04,0x00,0x32,0xc0,0xc2,0x04,0x00};
static bool knownOwnerCode(){
    const u8 native[]={0x8b,0x41,0x08,0x85,0xc0};
    if(signature(0x6e9e40,native,sizeof(native))){
        LogRaw("BODY_AUDIT_OWNER implementation=VANILLA recognized=YES called=NO\r\n");return true;}
    u8 op=0;u32 displacement=0;
    if(!read(0x6e9e40,op)||op!=0xe9||!read(0x6e9e41,displacement))return false;
    uptr target=0x6e9e45u+displacement;
    val("ownerHookTarget_NOT_CALLED",target);
    bool match=signature(target,unlimiterOwnerBody,sizeof(unlimiterOwnerBody));
    LogRaw(match?"BODY_AUDIT_OWNER implementation=VERIFIED_UNLIMITER_35_BYTES recognized=YES called=NO\r\n":
                 "BODY_AUDIT_OWNER implementation=UNKNOWN_E9_TARGET recognized=NO called=NO\r\n");
    return match;
}
static void codeLog(uptr address,const u8* expected,u32 count){
    LB l;I(l);S(l,"BODY_AUDIT_GUARD_CODE address=");HX(l,address);
    S(l," actual=");
    for(u32 i=0;i<count;++i){u8 b=0;if(i)C(l,',');if(read(address+i,b))HX(l,b);else S(l,"UNREADABLE");}
    S(l," expected=");for(u32 i=0;i<count;++i){if(i)C(l,',');HX(l,expected[i]);}
    S(l,"\r\n");LogRaw(l.b);
}
#pragma pack(push,1)
struct Part { u32 name;u8 slot,group,selector,carIndex;u16 nameOffset,attributes,modelIndex; };
#pragma pack(pop)
static_assert(sizeof(Part)==14,"CarPart ABI");
static bool modelHash(uptr db,u32 carHash,u32 modelIndex,u32 lod,u32& out){
    uptr models,strings,suffix;u32 count;u8 isString;u16 prefix;
    if(!read(db+0x2c,models)||!read(db+0x30,count)||count>65535||modelIndex>=count||
       !read(db+0x0c,strings))return false;
    uptr rec=models+24*modelIndex;
    if(!read(rec,isString)||!read(rec+2,prefix)||!read(rec+4+lod*4,suffix))return false;
    if(suffix==0xffffffffu){out=0;return true;}
    if(!isString){out=suffix;return true;}
    out=carHash;
    if(prefix!=0xffffu&&!stringHash(strings+4u*prefix,out))return false;
    if(!stringHash(suffix,out))return false;
    out=out*33u+'_';out=out*33u+'A'+lod;return true;
}
// Read the same resident-solid tables searched by native 0x5018f0.
// Unlike the native lookup this does NOT reorder the pack linked list.
static bool solidLookup(u32 key,uptr& result){
    result=0;uptr pack;if(!read(0x91a0d0,pack))return false;
    for(u32 seen=0;pack!=0x91a0d0&&seen<4096;++seen){
        u32 count;uptr table,next;
        if(!read(pack,next)||!read(pack+0x0c,count)||!read(pack+0x74,table)||count>1000000)return false;
        u32 lo=0,hi=count;
        while(lo<hi){u32 mid=lo+(hi-lo)/2,h;
            if(table>0xffffffffu-mid*8u||!read(table+mid*8u,h))return false;
            if(h<key)lo=mid+1;else hi=mid;
        }
        if(lo<count){u32 h;uptr s;if(!read(table+lo*8,h)||!read(table+lo*8+4,s))return false;
            if(h==key&&s){if(!readable(s,16))return false;result=s;return true;}}
        if(next==pack)return false;pack=next;
    }return pack==0x91a0d0;
}
static void partLog(uptr ride,u32 slot){
    uptr p;Part cp={};LB l;I(l);S(l,"BODY_AUDIT_PART slot=");U(l,slot);
    if(!read(ride+0x48+slot*4,p)){S(l," status=UNREADABLE\r\n");LogRaw(l.b);return;}
    S(l," ptr=");HX(l,p);
    if(p&&read(p,cp)){S(l," PartID=");U(l,cp.slot);S(l," partHash=");HX(l,cp.name);
        S(l," modelIndex=");U(l,cp.modelIndex);S(l," carHashIndex=");U(l,cp.carIndex);
        S(l," selector=");U(l,cp.selector);S(l," attributes=");U(l,cp.attributes);}
    u8 flags;if(read(ride+0x274+slot,flags)){S(l," enabledFlags=");HX(l,flags);}
    S(l,"\r\n");LogRaw(l.b);
}
static void modelsLog(uptr cri,u32 slot){
    for(u32 lod=0;lod<5;++lod){uptr tagged,solid=0;u32 key=0;
        if(!read(cri+0xb84+20*slot+4*lod,tagged))return;
        uptr model=tagged&~3u;
        bool ok=model&&read(model+8,key)&&read(model+12,solid);
        LB l;I(l);S(l,"BODY_AUDIT_EMODEL slot=");U(l,slot);S(l," lod=");C(l,'A'+lod);
        S(l," tagged=");HX(l,tagged);S(l," hash=");HX(l,key);S(l," solid=");HX(l,solid);
        S(l," readable=");S(l,ok?"YES":"NO");S(l,"\r\n");LogRaw(l.b);
    }
}
struct Pending { void* damage;void* vehicle;void* sim;uptr render,handle,world;DWORD tick;bool active; };
static Pending pending[8]={};
static void phaseLog(const char* phase){LB l;I(l);S(l,"BODY_AUDIT_BEGIN version=3.3b phase=");S(l,phase);
    S(l," gate=HARD_EXTERNAL_TRAILERA_ONESHOT mode=GUARDED_BODY_REBUILD tick=");U(l,KGetTickCount());S(l,"\r\n");LogRaw(l.b);}
#include "NativeRebuildSignatures.h"
// Persistent storage: never reused or freed while a RideInfo might retain it.
// Capacity exhaustion skips the visual change; gameplay remains active.
static Part privateBodies[64];static u32 privateCount=0;
struct DamagedInstance {uptr world,conn,render,handle,damage,sim,cri,ride,original,db;Part body;bool active;};
static DamagedInstance damagedInstances[64]={};

static bool writable(uptr p,u32 n){
    if(p<0x10000u||!n||p+n<p)return false;
    uptr end=p+n;while(p<end){MBI m={};++queryCount;
        if(query((void*)p,&m,sizeof(m))!=sizeof(m))return false;
        u32 prot=m.protect&255u;
        if(m.state!=MEM_COMMIT||(m.protect&0x100u)||!(prot==4||prot==8||prot==0x40||prot==0x80))return false;
        uptr next=(uptr)m.base+m.size;if(next<=p)return false;p=next<end?next:end;
    }return true;
}
static bool bodyModelsMatch(uptr cri){
    for(u32 lod=0;lod<5;++lod){u32 tag=0,key=0,solid=0;
        if(!read(cri+0xb84+23*20+lod*4,tag)||!(tag&~3u)||(tag&1u)||
           !read((tag&~3u)+8,key)||key!=0x51b22595u+lod||
           !read((tag&~3u)+12,solid)||!solid)return false;}
    return true;
}
static void nativeRebuild(uptr cri){
#ifdef BODY_PROBE_FIXTURE
    fixtureRebuild(cri);
#else
    using Fn=void(__thiscall*)(void*);((Fn)0x755800u)((void*)cri);
#endif
}
static bool rebuildInputsReadable(uptr cri,uptr ride){
    // Validate readable Part descriptors and owned eModel headers used by native rebuild.
    for(u32 slot=0;slot<76;++slot){uptr part=0;
        if(!read(ride+0x48+slot*4,part)||(part&&!readable(part,sizeof(Part)))){return false;}
        for(u32 lod=0;lod<5;++lod){u32 tag=0;
            if(!read(cri+0xb84+slot*20+lod*4,tag)||((tag&~3u)&&!writable(tag&~3u,0x18))){return false;}}}
    return true;
}
static bool apply(uptr cri,uptr ride,uptr original,const Part& body,u32 model){
    if(privateCount>=64){end("PRIVATE_PART_CAPACITY_NO_WRITE");return false;}
    if(!writable(cri,0x17e0)||!writable(ride+0xa4,4)){end("NONWRITABLE_INSTANCE_NO_WRITE");return false;}
    // Whole native function + switch data and descriptor/hash consumers.
    if(!nativeCodeMatches()){end("NATIVE_CODE_CHANGED_NO_WRITE");return false;}
    uptr current=0;if(!read(ride+0xa4,current)||current!=original){end("BODY_CHANGED_NO_WRITE");return false;}
    u8 enabled=0;if(!read(ride+0x274+23,enabled)||!(enabled&1)){end("BODY_DISABLED_NO_WRITE");return false;}
    if(!rebuildInputsReadable(cri,ride)){end("REBUILD_INPUTS_INVALID_NO_WRITE");return false;}
    Part& replacement=privateBodies[privateCount++];replacement=body;replacement.modelIndex=(u16)model;
    val("privateBodyPart",(uptr)&replacement);val("originalBodyPart",original);
    val("nativeRebuildTarget",0x755800);val("VirtualQuery_count_before_apply",queryCount);
    LogRaw("BODY_SWAP_BEFORE instanceSlot=23 directEMODELWrites=0 globalDBWrites=0 nativeSetPartCalled=NO\r\n");
    u32 started=KGetTickCount();
    // Proven native single-part store: 7571C0 / Unlimiter RVA4BEA3.
    // Do not call BODY SetPart: it also changes ten unrelated slots.
    *(volatile uptr*)(ride+0xa4)=(uptr)&replacement;
    nativeRebuild(cri);
    resetReadCache();
    uptr installed=0;
    if(!read(ride+0xa4,installed)||installed!=(uptr)&replacement){end("BODY_SLOT_CHANGED_DURING_REBUILD");return false;}
    *(volatile uptr*)(ride+0xa4)=original;
    LogRaw("BODY_TEMPLATE_RESTORED timing=IMMEDIATELY_AFTER_REBUILD cachedModels=DAMAGE0\r\n");
    modelsLog(cri,23);
    val("nativeRebuild_elapsed_ms",KGetTickCount()-started);
    if(bodyModelsMatch(cri)){end("DAMAGE0_BODY_MODELS_BUILT_VISUAL_CONFIRMATION_PENDING");return true;}
    LogRaw("BODY_SWAP_ROLLBACK reason=MODEL_POSTCHECK_FAILED restore=ORIGINAL_PART_AND_NATIVE_REBUILD\r\n");
    *(volatile uptr*)(ride+0xa4)=original;nativeRebuild(cri);
    resetReadCache();modelsLog(cri,23);end("MODEL_POSTCHECK_FAILED_ORIGINAL_REBUILD_REQUESTED");return false;
}
static void run(void* damage,void* vehicle,void* expectedSim,const char* phase){
    resetReadCache();phaseLog(phase);
    val("DamageCopCar",(uptr)damage);val("IVehicle",(uptr)vehicle);val("expectedSim",(uptr)expectedSim);
    if(!query)query=(QueryFn)KGetProcAddress(KLoadLibraryA("kernel32.dll"),"VirtualQuery");
    if(!query){end("NO_VIRTUALQUERY");return;}
    uptr sim,registry,begin,finish,render=0,cached=0,vt=0;u32 zones=0;
    if(!read((uptr)damage+0x34,sim)||sim!=(uptr)expectedSim||!read(sim+4,registry)||
       !read(registry+4,begin)||!read(registry+8,finish)||finish<begin||
       (finish-begin)%8||(finish-begin)>128*8){end("INVALID_COM_REGISTRY");return;}
    val("COM",registry);val("interfaces",(finish-begin)/8);
    for(uptr e=begin;e<finish;e+=8){uptr key,p;
        if(!read(e,key)||!read(e+4,p)){end("UNREADABLE_COM_PAIR");return;}
        if(key==0x404ff0){if(render){end("DUPLICATE_RENDERABLE");return;}render=p;}
    }
    val("IRenderable_COM",render);
    if(read((uptr)damage+0x94,cached))val("IRenderable_cached94",cached);
    if(read((uptr)damage+0x98,zones))val("damageZones",zones);
    uptr back,getter,handle;
    if(!render||!read(render+4,back)||back!=registry||!read(render,vt)||!read(vt+12,getter)){
        end("INVALID_RENDERABLE");return;}
    val("IRenderable_vtable",vt);val("GetModelHandle_target_NOT_CALLED",getter);
    const u8 getSig[]={0x8b,0x41,0x10,0xc3};
    if(getter!=0x6b90c0||!signature(getter,getSig,sizeof(getSig))){end("UNSUPPORTED_RENDERABLE_IMPLEMENTATION");return;}
    // Exactly reproduces the proven getter's one load; never calls the vtable.
    if(!read(render+0x10,handle)){end("UNREADABLE_HANDLE");return;}val("modelHandle",handle);
    // Constructor 6bbe70 proves this exact class: IRenderable = full object +4c.
    // 693b77 compares callback world against full+84; 6e9e40 reads world+8 owner.
    uptr conn=render-0x4c,connVt=0,connSim=0,world=0,worldVt=0,owner=0,key30=0;
    const u8 ownerSig[]={0x8b,0x41,0x08,0x85,0xc0};
    const u8 callbackSig[]={0x3b,0x86,0x84,0,0,0,0x75,0x26};
    // Evaluate each preflight condition separately; do not short-circuit the evidence.
    // Only conn header/+34 are read here, never the bound world before class checks.
    bool connVtReadable=read(conn,connVt),connSimReadable=read(conn+0x34,connSim);
    bool ownerVanilla=signature(0x6e9e40,ownerSig,sizeof(ownerSig));
    bool ownerCodeOK=knownOwnerCode();
    bool callbackCodeOK=signature(0x693b77,callbackSig,sizeof(callbackSig));
    val("guard_RenderConn",conn);val("guard_connVtableReadable",connVtReadable);
    val("guard_connVtableActual",connVt);val("guard_connVtableExpected",0x8ad92c);
    val("guard_connSimReadable",connSimReadable);val("guard_connSimActual",connSim);
    val("guard_connSimExpected",sim);val("guard_ownerVanillaBytesMatch",ownerVanilla);val("guard_ownerImplementationRecognized",ownerCodeOK);
    val("guard_callbackCodeMatches",callbackCodeOK);
    codeLog(0x6e9e40,ownerSig,sizeof(ownerSig));
    codeLog(0x693b77,callbackSig,sizeof(callbackSig));
    if(vt!=0x8ad908){end("GUARD_RENDERABLE_CLASS");return;}
    if(!connVtReadable){end("GUARD_CONN_VTABLE_UNREADABLE");return;}
    if(connVt!=0x8ad92c){end("GUARD_CONN_VTABLE_MISMATCH");return;}
    if(!ownerCodeOK){end("GUARD_OWNER_CODE_MISMATCH");return;}
    if(!callbackCodeOK){end("GUARD_CALLBACK_CODE_MISMATCH");return;}
    if(!connSimReadable){end("GUARD_CONN_SIM_UNREADABLE");return;}
    if(connSim!=sim){end("GUARD_CONN_SIM_MISMATCH");return;}
    if(!read(conn+0x84,world)){end("GUARD_BOUND_WORLD_UNREADABLE");return;}
    val("RenderConn",conn);val("WorldModel_direct84",world);
    if(!world){end("NO_BOUND_WORLD");return;}
    if(!read(world,worldVt)||!read(world+8,owner)){end("WORLD_HEADER_UNREADABLE");return;}
    val("WorldModel_vtable",worldVt);val("WorldModel_owner",owner);
    if(owner!=conn||(worldVt!=0x8b5254&&worldVt!=0x8b5274)){
        end("WORLD_CLASS_OR_OWNER_MISMATCH");return;}
    if(read(world+0x30,key30))val("WorldModel_key30_NOT_IModelHandle",key30);
    uptr list;u32 count,matches=0;
    if(!read(0x9b37cc,list)||!read(0x9b37d4,count)||count>4096){end("INVALID_WORLD_LIST");return;}
    val("worldListCount",count);
    for(u32 i=0;i<count;++i){uptr w;if(!read(list+i*4,w)){end("UNREADABLE_WORLD_LIST");return;}
        if(w==world)++matches;}
    val("directWorldListMatches",matches);
    if(matches!=1){end("BOUND_WORLD_NOT_UNIQUE_IN_LIST");return;}
    if(phase[0]=='P'&&phase[1]=='R'){
        u32 slot=8;for(u32 i=0;i<8;++i)if(!pending[i].active){slot=i;break;}
        if(slot<8){Pending& p=pending[slot];p.damage=damage;p.vehicle=vehicle;p.sim=expectedSim;
            p.render=render;p.handle=handle;p.world=world;p.tick=KGetTickCount();p.active=true;}
        else LogRaw("BODY_AUDIT_NEXT_ENDSCENE skipped=QUEUE_FULL\r\n");
        end("QUEUED_NO_GAME_WRITES");return;
    }
    uptr cri=0,ride=0,worldRide=0,dm=0;u32 state=0,type=0,lo=0,hi=0;
    if(!read(world+0x28,state)||!read(world+0x44,cri)||!read(world+0x40,worldRide)){
        end("WORLD_FIELDS_UNREADABLE");return;}
    val("WorldModel_state",state);val("CarRenderInfo",cri);val("WorldModel_RideInfo",worldRide);
    if(state<2||!cri||!worldRide){end("WORLD_NOT_READY");return;}
    if(!read(cri+0x84,ride)||ride!=worldRide||!read(ride,type)||!read(cri+0x40,dm)||
       !read(cri+0x1628,lo)||!read(cri+0x162c,hi)){end("INVALID_RENDER_CHAIN");return;}
    val("RideInfo",ride);val("DamageModel",dm);val("CarType",type);
    if(dm){uptr dvt=0,downer=0;if(read(dm,dvt))val("DamageModel_vtable",dvt);
        if(read(dm+4,downer))val("DamageModel_owner",downer);}
    u32 cachedZones=0;if(read(cri+0x17a0,cachedZones))val("CRI_cachedDamageZones",cachedZones);
    val("lodMin",lo);val("lodMax",hi);
    // TRAILERA is enum value 13 decimal = 0x0D, NOT 0x13.
    if(type!=13u){end("NOT_VANILLA_TRAILERA_TYPE");return;}
    u32 shared=0;
    for(u32 i=0;i<count;++i){uptr w,r,c;if(!read(list+i*4,w)||!read(w+0x40,r)||!read(w+0x44,c)){
            end("SHARING_CHECK_UNREADABLE");return;}
        if(w!=world&&(r==ride||c==cri))++shared;}
    val("otherWorldsSharingRideOrCRI",shared);
    partLog(ride,23);partLog(ride,2);modelsLog(cri,23);modelsLog(cri,2);
    uptr db,parts,hashes;u32 numParts,numCars;Part body;uptr bodyPtr;
    if(!read(ride+0xa4,bodyPtr)||!read(bodyPtr,body)||!read(0x9b09d4,db)||
       !read(db+0x34,parts)||!read(db+0x38,numParts)||numParts>100000||
       !read(0x9b09c4,hashes)||!read(0x9b09c8,numCars)||numCars>256){end("INVALID_PART_DATABASE");return;}
    u32 carHash;if(body.carIndex>=numCars||!read(hashes+body.carIndex*4,carHash)||carHash!=hash("TRAILERA")){
        end("BODY_CAR_HASH_MISMATCH");return;}
    val("TRAILERA_carHash",carHash);val("partRecordCount",numParts);
    // Exact LZC candidate 3 first, original BUN candidate 316 second.
    // Both are hints only; all five live hashes must match before use.
    u32 chosen=0xffffffffu;
    const u32 candidates[]={3,316};
    for(u32 c=0;c<2;++c){bool match=true;
        for(u32 lod=0;lod<5;++lod){u32 computed=0;
            if(!modelHash(db,carHash,candidates[c],lod,computed)||computed!=0x51b22595u+lod)match=false;}
        if(match){chosen=candidates[c];break;}}
    val("verifiedDamage0ModelIndex",chosen);
    if(chosen==0xffffffffu){end("NO_VERIFIED_DAMAGE0_TEMPLATE_NO_WRITE");return;}
    bool allResident=true;
    for(u32 lod=0;lod<5;++lod){uptr solid=0;bool ok=solidLookup(0x51b22595u+lod,solid)&&solid;
        allResident&=ok;val("DAMAGE0_residentSolid",solid);}
    if(!allResident){end("DAMAGE0_NOT_RESIDENT_NO_WRITE");return;}
    if(shared||dm||lo!=0||hi!=4){end("UNSUPPORTED_RENDER_STATE_NO_WRITE");return;}
    if(body.slot!=23||body.selector!=1||body.name!=0x0ac38b60u){end("BODY_DESCRIPTOR_MISMATCH_NO_WRITE");return;}
    // Original descriptor must still belong to the live database; never alter it.
    if(bodyPtr<parts||bodyPtr-parts>=numParts*14u||(bodyPtr-parts)%14u){end("BODY_NOT_DATABASE_OWNED_NO_WRITE");return;}
    for(u32 lod=0;lod<5;++lod){u32 hash=0,tag=0,actual=0;uptr solid=0;
        if(!modelHash(db,carHash,body.modelIndex,lod,hash)||hash!=0x0bcb3d27u+lod||
           !read(cri+0xb84+23*20+lod*4,tag)||!(tag&~3u)||(tag&1u)||
           !read((tag&~3u)+8,actual)||actual!=hash||!read((tag&~3u)+12,solid)||!solid){
            end("ORIGINAL_BODY_MODEL_MISMATCH_NO_WRITE");return;}}
    if(!zones){end("NO_POST_DAMAGE_STATE_NO_WRITE");return;}
    if(apply(cri,ride,bodyPtr,body,chosen)){
        DamagedInstance& t=damagedInstances[privateCount-1];
        t={world,conn,render,handle,(uptr)damage,sim,cri,ride,bodyPtr,db,body,true};
        LogRaw("BODY_LIFECYCLE armed=YES resetCondition=DAMAGE_ZONES_ZERO identity=OWNER_HANDLE_SIM_CRI_RIDE\r\n");
    }

}
// Only previously swapped objects are monitored. No searches for new vehicles.
static bool samePart(const Part& a,const Part& b){const u8* x=(const u8*)&a;const u8* y=(const u8*)&b;for(u32 i=0;i<sizeof(Part);++i)if(x[i]!=y[i])return false;return true;}
static bool normalBodyModels(uptr cri){
    for(u32 lod=0;lod<5;++lod){u32 tag=0,key=0,solid=0;
        if(!read(cri+0xb84+23*20+lod*4,tag)||!(tag&~3u)||(tag&1)||
           !read((tag&~3u)+8,key)||key!=0x0bcb3d27u+lod||!read((tag&~3u)+12,solid)||!solid)return false;}
    return true;
}
static void maintainDamagedInstances(){
    bool any=false;for(u32 k=0;k<64;++k)any|=damagedInstances[k].active;if(!any)return;
    uptr list=0;u32 count=0;if(!read(0x9b37cc,list)||!read(0x9b37d4,count)||count>4096)return;
    for(u32 k=0;k<64;++k){DamagedInstance& t=damagedInstances[k];if(!t.active)continue;
        u32 matches=0;for(u32 i=0;i<count;++i){uptr w=0;if(!read(list+i*4,w))return;if(w==t.world)++matches;}
        if(!matches)continue; // No stale-object reads while absent; allow same pool object to return.
        uptr wvt=0,owner=0,vt=0,rv=0,bound=0,h=0,sim=0,ds=0,cri=0,ride=0,cride=0;
        if(matches!=1||!read(t.world,wvt)||(wvt!=0x8b5254&&wvt!=0x8b5274)||
           !read(t.world+8,owner)||owner!=t.conn||!read(t.conn,vt)||vt!=0x8ad92c||
           !read(t.render,rv)||rv!=0x8ad908||!read(t.conn+0x84,bound)||bound!=t.world||
           !read(t.render+0x10,h)||h!=t.handle||!read(t.conn+0x34,sim)||sim!=t.sim||
           !read(t.damage+0x34,ds)||ds!=t.sim||!read(t.world+0x44,cri)||cri!=t.cri||
           !read(t.world+0x40,ride)||ride!=t.ride||!read(cri+0x84,cride)||cride!=ride){
            t.active=false;LogRaw("BODY_LIFECYCLE detached=IDENTITY_CHANGED gameWrites=0\r\n");continue;}
        u32 zones=0;if(!read(t.damage+0x98,zones)||zones)continue;
        // This zero transition is observed in the uploaded pooled-respawn log.
        u32 state=0,type=0,dm=0,lo=0,hi=0;uptr part=0,db=0;
        if(!read(t.world+0x28,state)||state<2)continue;
        t.active=false; // One reset attempt; unknown states never cause per-frame retries.
        Part original={};
        if(!read(ride,type)||type!=13||!read(cri+0x40,dm)||dm||
           !read(cri+0x1628,lo)||lo!=0||!read(cri+0x162c,hi)||hi!=4||
           !read(ride+0xa4,part)||part!=t.original||!read(part,original)||!samePart(original,t.body)||
           !read(0x9b09d4,db)||db!=t.db){end("RESPAWN_STATE_CHANGED_NO_WRITE");continue;}
        bool shared=false;for(u32 i=0;i<count;++i){uptr w=0,r=0,c=0;
            if(!read(list+i*4,w)||!read(w+0x40,r)||!read(w+0x44,c)){shared=true;break;}
            if(w!=t.world&&(r==ride||c==cri)){shared=true;break;}}
        if(shared){end("RESPAWN_SHARED_STATE_NO_WRITE");continue;}
        if(normalBodyModels(cri)){LogRaw("BODY_RESPAWN_RESET result=ALREADY_NORMAL gameWrites=0\r\n");continue;}
        if(!bodyModelsMatch(cri)){end("RESPAWN_UNKNOWN_MODELS_NO_WRITE");continue;}
        bool resident=true;for(u32 lod=0;lod<5;++lod){uptr solid=0;if(!solidLookup(0x0bcb3d27u+lod,solid)||!solid)resident=false;}
        if(!resident||!writable(cri,0x17e0)||!rebuildInputsReadable(cri,ride)||!nativeCodeMatches()){
            end("RESPAWN_REBUILD_GUARD_FAILED_NO_WRITE");continue;}
        val("respawnWorld",t.world);val("respawnCRI",cri);val("respawnRide",ride);
        LogRaw("BODY_RESPAWN_RESET_BEFORE reason=DAMAGE_ZONES_RESET_TO_ZERO part=ORIGINAL nativeRebuild=YES\r\n");
        nativeRebuild(cri);resetReadCache();modelsLog(cri,23);
        LogRaw(normalBodyModels(cri)?"BODY_RESPAWN_RESET result=NORMAL_BODY_VERIFIED\r\n":"BODY_RESPAWN_RESET result=MODEL_POSTCHECK_FAILED\r\n");
    }
}
// Reuse the pre-existing EndScene hook. No additional hook. Native rebuild is deferred here.
// Never follow saved damage/sim pointers until world membership, owner, class and
// monotonically allocated IModel handle still identify the captured instance.
static void frame(){
    if(g_inImpact)return;
    resetReadCache();
    maintainDamagedInstances();
    for(u32 k=0;k<8;++k){Pending p=pending[k];if(!p.active)continue;pending[k].active=false;
        uptr list=0;u32 count=0,matches=0;
        if(KGetTickCount()-p.tick>5000||!read(0x9b37cc,list)||!read(0x9b37d4,count)||count>4096){
            phaseLog("NEXT_ENDSCENE");end("DEFERRED_EXPIRED_OR_LIST_INVALID");continue;}
        for(u32 i=0;i<count;++i){uptr w;if(!read(list+i*4,w)){matches=0;break;}if(w==p.world)++matches;}
        uptr conn=p.render-0x4c,owner=0,vt=0,bound=0,h=0,sim=0,renderVt=0,damageSim=0;
        if(matches!=1||!read(p.world+8,owner)||owner!=conn||!read(conn,vt)||vt!=0x8ad92c||
           !read(p.render,renderVt)||renderVt!=0x8ad908||!read(conn+0x84,bound)||bound!=p.world||
           !read(p.render+0x10,h)||h!=p.handle||!read(conn+0x34,sim)||sim!=(uptr)p.sim||
           !read((uptr)p.damage+0x34,damageSim)||damageSim!=sim){
            phaseLog("NEXT_ENDSCENE");end("DEFERRED_INSTANCE_CHANGED_OR_REMOVED");continue;}
        run(p.damage,p.vehicle,p.sim,"NEXT_ENDSCENE");
    }
}

}
