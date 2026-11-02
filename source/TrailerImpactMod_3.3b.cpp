// NFSMW 2005 TrailerImpactMod 2.9 - NATIVE GAS-STATION FX + SAFE TRACTOR HOLD
// Target: supplied retail/Redux 32-bit speed.exe, image base 0x00400000.
//
// Functional release attempt:
//  * exact TRAILERA DamageCopCar::OnImpact trigger
//  * only external vehicle vs trailer; own SEMIA excluded
//  * hard-impact gate + one-shot per trailer
//  * stop SEMIA tractor
//  * native NFSMW fxex_gasstation particle emitter through the game ParticleSystem
//  * standalone sibling WAV sound with near/mid/far attenuation tiers
//  * 50m cop kill during active pursuit
//  * destroy TRAILERA only; tractor remains stopped
//  * detailed stage-by-stage TrailerImpactMod.log diagnostics

extern "C" int _fltused = 0;
extern "C" void* memset(void* dst, int c, unsigned int n){ unsigned char* d=(unsigned char*)dst; for(unsigned int i=0;i<n;i++) d[i]=(unsigned char)c; return dst; }
extern "C" void* memcpy(void* dst, const void* src, unsigned int n){ unsigned char* d=(unsigned char*)dst; const unsigned char* s=(const unsigned char*)src; for(unsigned int i=0;i<n;i++) d[i]=s[i]; return dst; }

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using s32 = int;
using uptr = unsigned int;
using BOOL = int;
using DWORD = unsigned long;
using SIZE_T = unsigned int;
using HANDLE = void*;
using HMODULE = void*;
using LPVOID = void*;
using LPCVOID = const void*;
using LPCSTR = const char*;
using FARPROC = void*;
using HRESULT = long;

#define WINAPI __stdcall
#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define PAGE_EXECUTE_READWRITE 0x40
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 0x00000001u
#define CREATE_ALWAYS 2u
#define INVALID_HANDLE_VALUE ((HANDLE)(-1))

// PlaySound flags.
#define SND_ASYNC     0x0001u
#define SND_NODEFAULT 0x0002u
#define SND_FILENAME  0x00020000u

// Minimal D3D9 constants.
#define D3DFMT_A8R8G8B8 21u
#define D3DPOOL_MANAGED 1u
#define D3DPT_TRIANGLESTRIP 5u
#define D3DFVF_XYZ 0x002u
#define D3DFVF_XYZRHW 0x004u
#define D3DFVF_DIFFUSE 0x040u
#define D3DFVF_TEX1 0x100u
#define D3DTS_VIEW 2u
#define D3DTS_PROJECTION 3u
#define D3DTS_WORLD 256u
#define D3DRS_ZENABLE 7u
#define D3DRS_ZWRITEENABLE 14u
#define D3DRS_ALPHATESTENABLE 15u
#define D3DRS_SRCBLEND 19u
#define D3DRS_DESTBLEND 20u
#define D3DRS_CULLMODE 22u
#define D3DRS_ALPHABLENDENABLE 27u
#define D3DRS_FOGENABLE 28u
#define D3DRS_LIGHTING 137u
#define D3DRS_COLORWRITEENABLE 168u
#define D3DRS_SCISSORTESTENABLE 174u
#define D3DRS_SRGBWRITEENABLE 194u
#define D3DRS_SEPARATEALPHABLENDENABLE 206u
#define D3DRS_BLENDOP 171u
#define D3DBLEND_ONE 2u
#define D3DBLEND_SRCALPHA 5u
#define D3DBLEND_INVSRCALPHA 6u
#define D3DBLENDOP_ADD 1u
#define D3DCULL_NONE 1u
#define D3DTSS_COLOROP 1u
#define D3DTSS_COLORARG1 2u
#define D3DTSS_COLORARG2 3u
#define D3DTSS_ALPHAOP 4u
#define D3DTSS_ALPHAARG1 5u
#define D3DTSS_ALPHAARG2 6u
#define D3DTSS_TEXCOORDINDEX 11u
#define D3DTSS_TEXTURETRANSFORMFLAGS 24u
#define D3DTOP_DISABLE 1u
#define D3DTOP_MODULATE 4u
#define D3DTA_DIFFUSE 0u
#define D3DTA_TEXTURE 2u
#define D3DSAMP_MAGFILTER 5u
#define D3DSAMP_MINFILTER 6u
#define D3DTEXF_LINEAR 2u

struct Vec3 { float x,y,z; };
struct D3DMatrix { float m[4][4]; };
struct D3DLockedRect { s32 Pitch; void* pBits; };
struct ParticleVertex { float x,y,z; u32 color; float u,v; };
struct ParticleScreenVertex { float x,y,z,rhw; u32 color; float u,v; };
struct D3DViewport { u32 X,Y,Width,Height; float MinZ,MaxZ; };

// speed.exe KERNEL32 IAT slots, verified on supplied executable.
static const uptr IAT_CloseHandle       = 0x00890078u;
static const uptr IAT_GetProcAddress    = 0x00890094u;
static const uptr IAT_LoadLibraryA      = 0x00890098u;
static const uptr IAT_GetTickCount      = 0x008900A4u;
static const uptr IAT_GetModuleFileNameA= 0x008901D4u;
static const uptr IAT_WriteFile         = 0x00890228u;
static const uptr IAT_VirtualAlloc      = 0x00890240u;
static const uptr IAT_VirtualProtect    = 0x00890294u;
static const uptr IAT_CreateFileA       = 0x008902ACu;

template<class Fn> static Fn IatFn(uptr slot){ return (Fn)(*(void**)slot); }
static DWORD KGetTickCount(){using Fn=DWORD(WINAPI*)();return IatFn<Fn>(IAT_GetTickCount)();}
static HMODULE KLoadLibraryA(LPCSTR s){using Fn=HMODULE(WINAPI*)(LPCSTR);return IatFn<Fn>(IAT_LoadLibraryA)(s);}
static FARPROC KGetProcAddress(HMODULE m,LPCSTR s){using Fn=FARPROC(WINAPI*)(HMODULE,LPCSTR);return IatFn<Fn>(IAT_GetProcAddress)(m,s);}
static DWORD KGetModuleFileNameA(HMODULE m,char*b,DWORD n){using Fn=DWORD(WINAPI*)(HMODULE,char*,DWORD);return IatFn<Fn>(IAT_GetModuleFileNameA)(m,b,n);}
static LPVOID KVirtualAlloc(LPVOID a,SIZE_T n,DWORD t,DWORD p){using Fn=LPVOID(WINAPI*)(LPVOID,SIZE_T,DWORD,DWORD);return IatFn<Fn>(IAT_VirtualAlloc)(a,n,t,p);}
static BOOL KVirtualProtect(LPVOID a,SIZE_T n,DWORD p,DWORD*o){using Fn=BOOL(WINAPI*)(LPVOID,SIZE_T,DWORD,DWORD*);return IatFn<Fn>(IAT_VirtualProtect)(a,n,p,o);}
static HANDLE KCreateFileA(LPCSTR a,DWORD b,DWORD c,LPVOID d,DWORD e,DWORD f,HANDLE g){using Fn=HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE);return IatFn<Fn>(IAT_CreateFileA)(a,b,c,d,e,f,g);}
static BOOL KWriteFile(HANDLE a,LPCVOID b,DWORD c,DWORD*d,LPVOID e){using Fn=BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,DWORD*,LPVOID);return IatFn<Fn>(IAT_WriteFile)(a,b,c,d,e);}
static BOOL KCloseHandle(HANDLE a){using Fn=BOOL(WINAPI*)(HANDLE);return IatFn<Fn>(IAT_CloseHandle)(a);}

static const uptr PREFERRED_BASE = 0x00400000u;
static const uptr RVA_DAMAGE_COP_ON_IMPACT = 0x0069CA30u - PREFERRED_BASE;
static const uptr RVA_VEHICLE_LIST_DATA    = 0x0092CD1Cu - PREFERRED_BASE;
static const uptr RVA_VEHICLE_LIST_COUNT   = 0x0092CD24u - PREFERRED_BASE;
static const uptr RVA_D3D_DEVICE_PTR       = 0x00982BDCu - PREFERRED_BASE;
// Engine player view stack, byte-anchored retail v1.3 (MWSDK camera layer).
static const uptr RVA_PLAYER_VIEW           = 0x00919650u - PREFERRED_BASE;
static const uptr RVA_PLAYER_CAMERA_PTR     = 0x00919690u - PREFERRED_BASE;
static const u32 OFF_EVIEW_PLATINFO         = 0x00u;
static const u32 OFF_EVIEW_FOCAL_LENGTH     = 0x0Cu;
static const u32 OFF_VIEW_VIEW              = 0x00u;
static const u32 OFF_VIEW_PROJECTION        = 0x40u;
static const u32 OFF_VIEW_VIEWPROJECTION    = 0x80u;
static const u32 OFF_VIEW_NONJITTERED_VP    = 0x100u;
static const u32 OFF_CAMERA_POSITION        = 0x40u;

static const float COP_RADIUS_SQ = 2500.0f;    // 50 m
static const float SOUND_MID_SQ  = 3600.0f;    // 60 m
static const float SOUND_FAR_SQ  = 16900.0f;   // 130 m
static const float SOUND_MAX_SQ  = 48400.0f;   // 220 m
static const DWORD FX_LIFETIME_MS = 5600u;
static const float FX_VISUAL_SCALE = 1.00f;
static const float TRIGGER_REUSE_RESET_SQ = 10000.0f; // 100 m spatial reset for recycled vehicle pointers

static uptr g_base = 0;
static HMODULE g_selfModule = nullptr;
static HANDLE g_log = INVALID_HANDLE_VALUE;
static bool g_inImpact = false;
static bool g_inRender = false;
struct TriggerEntry { void* trailer; Vec3 anchor; DWORD tick; };
static TriggerEntry g_triggered[256] = {};
static u32 g_triggeredCount = 0;

using ImpactFn=void(__thiscall*)(void*,void*,void*,float,float,void*,void*);
static ImpactFn g_origImpact=nullptr;
using EndSceneFn=HRESULT(__stdcall*)(void*);
static EndSceneFn g_origEndScene=nullptr;
static void** g_hookedD3DVtable=nullptr;
static bool g_renderHookInstalled=false;
static void* g_particleTexture=nullptr;
static bool g_textureAttempted=false;
static bool g_textureReady=false;

struct Vec4f { float x,y,z,w; };
static D3DMatrix g_engineView={};
static D3DMatrix g_engineProj={};
static D3DMatrix g_engineVP={};
static Vec3 g_engineEye={};
static float g_engineFocal=0.0f;
static bool g_engineCameraValid=false;
static bool g_engineCameraLogged=false;
static bool g_engineCameraFailLogged=false;
static bool g_engineUsesNonJittered=false;
static u8 g_matrixConvention=0; // 1=row-vector, 2=column-vector
static float g_frontWSign=1.0f;
static bool g_fixedAxisLogged=false;

using PlaySoundAFn=BOOL(WINAPI*)(LPCSTR,HMODULE,DWORD);
static HMODULE g_winmm=nullptr;
static PlaySoundAFn g_playSoundA=nullptr;
static char g_soundNear[320]={};
static char g_soundMid[320]={};
static char g_soundFar[320]={};

struct ExplosionInstance {
    bool active;
    bool firstFrameLogged;
    bool completeLogged;
    bool firstDrawLogged;
    bool fallbackLogged;
    DWORD startTick;
    Vec3 origin;
    void* trailer;
};
static ExplosionInstance g_fx[4]={};

struct FrozenTractor { void* vehicle; void* sim; Vec3 anchor; bool logged; };
static FrozenTractor g_frozen[32]={};
static u32 g_frozenCount=0;

static u32 StrLen(const char* s){if(!s)return 0;u32 n=0;while(s[n])++n;return n;}
static char Lower(char c){return(c>='A'&&c<='Z')?(char)(c+32):c;}
static bool EqI(const char*a,const char*b){if(!a||!b)return false;while(*a&&*b){if(Lower(*a++)!=Lower(*b++))return false;}return *a==0&&*b==0;}
static void CopyStr(char*d,u32 cap,const char*s){if(!d||!cap)return;u32 n=0;if(s){while(s[n]&&n+1<cap){d[n]=s[n];++n;}}d[n]=0;}
static void AppendStr(char*d,u32 cap,const char*s){u32 n=StrLen(d);if(n>=cap)return;if(s){u32 i=0;while(s[i]&&n+1<cap)d[n++]=s[i++];}d[n]=0;}

static bool InitLog(){g_log=KCreateFileA("TrailerImpactMod.log",GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,0,nullptr);return g_log&&g_log!=INVALID_HANDLE_VALUE;}
static void LogRaw(const char*s){if(!s||!g_log||g_log==INVALID_HANDLE_VALUE)return;DWORD w=0;KWriteFile(g_log,s,StrLen(s),&w,nullptr);}
struct LB{char b[768];u32 n;};
static void I(LB&l){l.n=0;l.b[0]=0;} static void C(LB&l,char c){if(l.n+1>=sizeof(l.b))return;l.b[l.n++]=c;l.b[l.n]=0;}
static void S(LB&l,const char*s){if(!s)s="<null>";while(*s&&l.n+1<sizeof(l.b))l.b[l.n++]=*s++;l.b[l.n]=0;}
static void U(LB&l,u32 v){char t[16];u32 n=0;if(!v){C(l,'0');return;}while(v&&n<16){t[n++]=(char)('0'+v%10);v/=10;}while(n)C(l,t[--n]);}
static void SI(LB&l,s32 v){if(v<0){C(l,'-');U(l,(u32)(-v));}else U(l,(u32)v);} static char HD(u32 v){v&=15;return v<10?(char)('0'+v):(char)('A'+v-10);}
static void HX(LB&l,u32 v){S(l,"0x");for(s32 sh=28;sh>=0;sh-=4)C(l,HD(v>>sh));} static void P(LB&l,const void*p){HX(l,(u32)(uptr)p);}
static void F1(LB&l,float v){if(v<0){C(l,'-');v=-v;}u32 x=(u32)(v*10.0f+0.5f);U(l,x/10);C(l,'.');C(l,(char)('0'+x%10));}

static float FAbs(float v){return v<0?-v:v;}
static float FSq(float v){return v*v;}
static float DistSq(const Vec3&a,const Vec3&b){return FSq(a.x-b.x)+FSq(a.y-b.y)+FSq(a.z-b.z);}
static u32 AlphaColor(u32 rgb,u32 a){if(a>255)a=255;return (a<<24)|(rgb&0x00FFFFFFu);}

template<class R> static R V0(void*o,u32 slot){void**vt=*(void***)o;using Fn=R(__thiscall*)(void*);return ((Fn)vt[slot])(o);}
template<class R,class A> static R V1(void*o,u32 slot,A a){void**vt=*(void***)o;using Fn=R(__thiscall*)(void*,A);return ((Fn)vt[slot])(o,a);}
static u32 VehicleCount(){if(!g_base)return 0;u32 n=*(volatile u32*)(g_base+RVA_VEHICLE_LIST_COUNT);return n<=512?n:0;}
static void** VehicleData(){return g_base?*(void***)(g_base+RVA_VEHICLE_LIST_DATA):nullptr;}
static void* VSim(void*v){return v?V0<void*>(v,1):nullptr;}
static const Vec3* VPos(void*v){return v?V0<const Vec3*>(v,3):nullptr;}
static const char* VName(void*v){return v?V0<const char*>(v,19):nullptr;}
static int VDriver(void*v){return v?V0<int>(v,22):-1;}
static bool VDestroyed(void*v){return v?V0<bool>(v,31):true;}
static void* FindVehicleBySim(void*s){if(!s)return nullptr;void**d=VehicleData();u32 n=VehicleCount();if(!d)return nullptr;for(u32 i=0;i<n;i++){void*v=d[i];if(v&&VSim(v)==s)return v;}return nullptr;}
static void* FindPlayer(){void**d=VehicleData();u32 n=VehicleCount();if(!d)return nullptr;for(u32 i=0;i<n;i++){void*v=d[i];if(v&&VDriver(v)==0)return v;}return nullptr;}
static void* GetTrailer(void*tractor){if(!tractor)return nullptr;void*a=*(void**)((u8*)tractor+0x58);return a?V0<void*>(a,1):nullptr;}
static void* FindTractor(void*trailer){if(!trailer)return nullptr;void**d=VehicleData();u32 n=VehicleCount();if(!d)return nullptr;for(u32 i=0;i<n;i++){void*v=d[i];if(!v)continue;const char*n=VName(v);if(n&&EqI(n,"semia")&&GetTrailer(v)==trailer)return v;}return nullptr;}
static s32 TriggerEntryIndex(void*t){if(!t)return -1;for(u32 i=0;i<g_triggeredCount;i++)if(g_triggered[i].trailer==t)return (s32)i;return -1;}
static bool AlreadyTriggeredAt(void*t,const Vec3&pos){s32 idx=TriggerEntryIndex(t);if(idx<0)return false;return DistSq(g_triggered[(u32)idx].anchor,pos)<=TRIGGER_REUSE_RESET_SQ;}
static void MarkTriggeredAt(void*t,const Vec3&pos){if(!t)return;DWORD now=KGetTickCount();s32 idx=TriggerEntryIndex(t);if(idx>=0){TriggerEntry&e=g_triggered[(u32)idx];e.anchor=pos;e.tick=now;return;}if(g_triggeredCount<256){g_triggered[g_triggeredCount].trailer=t;g_triggered[g_triggeredCount].anchor=pos;g_triggered[g_triggeredCount].tick=now;++g_triggeredCount;return;}u32 oldest=0;DWORD age=0;for(u32 i=0;i<g_triggeredCount;i++){DWORD a=now-g_triggered[i].tick;if(a>age){age=a;oldest=i;}}g_triggered[oldest].trailer=t;g_triggered[oldest].anchor=pos;g_triggered[oldest].tick=now;}
static bool HoldTractorSpeed(void*t){if(!t)return false;V1<void,float>(t,37,0.0f);return true;}
static bool VehicleStillPresent(void*v,void*sim){if(!v||!sim)return false;void**d=VehicleData();u32 n=VehicleCount();if(!d)return false;for(u32 i=0;i<n;i++)if(d[i]==v)return VSim(v)==sim;return false;}
static void FreezeTractor(void*t,const Vec3&anchor){if(!t)return;void*s=VSim(t);if(!s)return;for(u32 i=0;i<g_frozenCount;i++)if(g_frozen[i].vehicle==t&&g_frozen[i].sim==s){g_frozen[i].anchor=anchor;HoldTractorSpeed(t);return;}if(g_frozenCount<32){g_frozen[g_frozenCount].vehicle=t;g_frozen[g_frozenCount].sim=s;g_frozen[g_frozenCount].anchor=anchor;g_frozen[g_frozenCount].logged=false;++g_frozenCount;}HoldTractorSpeed(t);}
static void MaintainFrozenTractors(){u32 w=0;for(u32 i=0;i<g_frozenCount;i++){FrozenTractor f=g_frozen[i];if(!VehicleStillPresent(f.vehicle,f.sim))continue;const char*n=VName(f.vehicle);if(!n||!EqI(n,"semia"))continue;const Vec3*p=VPos(f.vehicle);if(!p)continue;float jump=DistSq(*p,f.anchor);if(jump>625.0f){LB l;I(l);S(l,"TRACTOR_HOLD release=YES tractor=");P(l,f.vehicle);S(l," reason=POSITION_JUMP distSq=");F1(l,jump);S(l,"\r\n");LogRaw(l.b);continue;}HoldTractorSpeed(f.vehicle);if(!f.logged){LB l;I(l);S(l,"TRACTOR_HOLD active=YES tractor=");P(l,f.vehicle);S(l," sim=");P(l,f.sim);S(l," anchor=(");F1(l,f.anchor.x);C(l,',');F1(l,f.anchor.y);C(l,',');F1(l,f.anchor.z);S(l,") mode=SPEED_ZERO_ONLY releaseOn25mJump=YES\r\n");LogRaw(l.b);f.logged=true;}g_frozen[w++]=f;}g_frozenCount=w;}
static bool DestroyVehicle(void*v){if(!v)return false;void*d=*(void**)((u8*)v+0x4C);if(!d)return false;V0<void>(d,7);return true;}
static bool PursuitActive(void*player){if(!player)return false;void*ai=V0<void*>(player,43);if(!ai)return false;return V0<void*>(ai,39)!=nullptr;}
struct CopStats{u32 total,alive,inRadius,calls,confirmed;};
static CopStats KillCops50(const Vec3&origin){CopStats s={};void**d=VehicleData();u32 n=VehicleCount();if(!d)return s;for(u32 i=0;i<n;i++){void*v=d[i];if(!v||VDriver(v)!=2)continue;++s.total;if(VDestroyed(v))continue;++s.alive;const Vec3*p=VPos(v);if(!p)continue;if(DistSq(*p,origin)<=COP_RADIUS_SQ){++s.inRadius;if(DestroyVehicle(v))++s.calls;if(VDestroyed(v))++s.confirmed;}}return s;}

static void BuildSiblingPath(char*out,u32 cap,const char*file){char tmp[320]={};DWORD n=KGetModuleFileNameA(g_selfModule,tmp,(DWORD)sizeof(tmp));if(!n||n>=sizeof(tmp)){CopyStr(out,cap,file);return;}s32 cut=(s32)n-1;while(cut>=0&&tmp[cut]!='\\'&&tmp[cut]!='/')--cut;u32 base=(cut>=0)?(u32)(cut+1):0u;u32 i=0;for(;i<base&&i+1<cap;i++)out[i]=tmp[i];out[i]=0;AppendStr(out,cap,file);}
static bool InitSound(){if(g_playSoundA)return true;g_winmm=KLoadLibraryA("winmm.dll");if(!g_winmm)return false;g_playSoundA=(PlaySoundAFn)KGetProcAddress(g_winmm,"PlaySoundA");return g_playSoundA!=nullptr;}
struct SoundResult{bool api;bool inRange;bool played;const char*tier;float distSq;};
static SoundResult PlayExplosionSound(const Vec3&origin,void*player){SoundResult r={};r.tier="NONE";const Vec3*pp=player?VPos(player):nullptr;r.distSq=pp?DistSq(origin,*pp):0.0f;r.api=InitSound();if(!r.api)return r;const char*path=g_soundNear;if(pp){if(r.distSq>SOUND_MAX_SQ){r.tier="OUT_OF_RANGE";return r;}if(r.distSq>SOUND_FAR_SQ){path=g_soundFar;r.tier="FAR";}else if(r.distSq>SOUND_MID_SQ){path=g_soundMid;r.tier="MID";}else r.tier="NEAR";}else r.tier="NEAR_NO_PLAYER";r.inRange=true;r.played=g_playSoundA(path,nullptr,SND_FILENAME|SND_ASYNC|SND_NODEFAULT)!=0;return r;}


// ---- Native NFSMW particle path -------------------------------------------------
// Verified retail v1.3 / supplied speed.exe addresses.
static const uptr RVA_STRING_TO_KEY           = 0x00454640u - PREFERRED_BASE;
static const uptr RVA_EFFECT_NAME_TO_KEY      = 0x00573140u - PREFERRED_BASE;
static const uptr RVA_FIND_COLLECTION         = 0x00455FD0u - PREFERRED_BASE;
static const uptr RVA_QUEUE_SPAWN_CTX_B       = 0x00508B10u - PREFERRED_BASE;
static const uptr RVA_CREATE_EMITTER_GROUP    = 0x0050C7B0u - PREFERRED_BASE;
static const uptr RVA_SET_EMITTER_LOCAL_WORLD = 0x00503BC0u - PREFERRED_BASE;
static const uptr RVA_EMITTER_SYSTEM_OBJECT   = 0x009166C0u - PREFERRED_BASE;
static const u32 PARTICLE_COLLECTION_CLASS_KEY = 0xABA86E60u;
static const u32 NATIVE_GROUP_FLAGS = 0x08000000u;
static const DWORD NATIVE_EMIT_STOP_MS = 1400u; // stop emitters after initial blast; existing particles finish naturally

struct NativeMatrix { float m[4][4]; };
struct NativeFxRequest {
    bool pending;
    DWORD tick;
    Vec3 simOrigin;
    u32 queueKey;
    u32 attribKey;
    u32 serial;
};
static NativeFxRequest g_nativeReq[8] = {};
static u32 g_nativeSerial=0;
static u32 g_fxQueueKey=0;
static u32 g_fxAttribKey=0;

struct ActiveNativeFx { void* group; DWORD spawnTick; u32 serial; bool active; };
static ActiveNativeFx g_activeNativeFx[8] = {};

typedef u32 (__cdecl *StringToKeyFn)(const char*);
typedef u32 (__cdecl *EffectNameToKeyFn)(const char*);
typedef void* (__cdecl *FindCollectionFn)(u32,u32);
typedef void (__cdecl *QueueSpawnFn)(u32*,u32,void*,void*,u32);
typedef void* (__thiscall *CreateEmitterGroupFn)(void*,void*,u32);
typedef void (__thiscall *SetEmitterLocalWorldFn)(void*,const NativeMatrix*);
typedef void (__thiscall *EmitterGroupFreeEmittersFn)(void*,BOOL);

static void BuildNativeWorldMatrix(const Vec3&sim,NativeMatrix&out){
    memset(&out,0,sizeof(out));
    // NFSMW physics/sim coordinates are Y-up. Renderer/particle world is Z-up.
    // Confirmed from the supplied build's camera vs. vehicle positions:
    // render = (sim.z, -sim.x, sim.y).
    out.m[0][0]=1.0f;
    out.m[1][1]=1.0f;
    out.m[2][2]=1.0f;
    out.m[3][3]=1.0f;
    out.m[3][0]=sim.z;
    out.m[3][1]=-sim.x;
    out.m[3][2]=sim.y + 1.0f;
}

static void* FindNativeFxCollection(u32 attribKey,u32 queueKey,u32&usedKey){
    FindCollectionFn find=(FindCollectionFn)(g_base+RVA_FIND_COLLECTION);
    void*c=nullptr;
    usedKey=0;
    if(attribKey){c=find(PARTICLE_COLLECTION_CLASS_KEY,attribKey);if(c){usedKey=attribKey;return c;}}
    if(queueKey && queueKey!=attribKey){c=find(PARTICLE_COLLECTION_CLASS_KEY,queueKey);if(c){usedKey=queueKey;return c;}}
    return nullptr;
}

static void TrackNativeFxGroup(void*group,u32 serial){
    if(!group)return;
    u32 slot=8;
    for(u32 i=0;i<8;i++)if(!g_activeNativeFx[i].active){slot=i;break;}
    if(slot==8){DWORD now=KGetTickCount();u32 oldest=0;DWORD best=0;for(u32 i=0;i<8;i++){DWORD a=now-g_activeNativeFx[i].spawnTick;if(a>best){best=a;oldest=i;}}slot=oldest;}
    g_activeNativeFx[slot].group=group;g_activeNativeFx[slot].spawnTick=KGetTickCount();g_activeNativeFx[slot].serial=serial;g_activeNativeFx[slot].active=true;
}

static void MaintainNativeFxLifecycle(){
    DWORD now=KGetTickCount();
    EmitterGroupFreeEmittersFn stop=(EmitterGroupFreeEmittersFn)(g_base+(0x00508BA0u-PREFERRED_BASE));
    for(u32 i=0;i<8;i++){
        ActiveNativeFx &a=g_activeNativeFx[i];
        if(!a.active||!a.group)continue;
        DWORD age=now-a.spawnTick;
        if(age>=NATIVE_EMIT_STOP_MS){
            // false = stop/free emitter instances but keep already emitted particles alive so the first explosion can finish naturally.
            stop(a.group,0);
            LB l;I(l);S(l,"NATIVE_FX_ONESHOT serial=");U(l,a.serial);S(l," group=");P(l,a.group);S(l," age_ms=");U(l,age);S(l," action=FREE_EMITTERS_KEEP_PARTICLES result=ISSUED\r\n");LogRaw(l.b);
            a.active=false;a.group=nullptr;
        }
    }
}

static bool CreateNativeGasStationFx(NativeFxRequest*r,const char*phase){
    if(!r)return false;
    u32 usedKey=0;
    void*collection=FindNativeFxCollection(r->attribKey,r->queueKey,usedKey);
    LB l;I(l);S(l,"NATIVE_FX_CREATE phase=");S(l,phase);S(l," serial=");U(l,r->serial);S(l," collection=");P(l,collection);S(l," attribKey=");HX(l,r->attribKey);S(l," queueKey=");HX(l,r->queueKey);S(l," usedKey=");HX(l,usedKey);
    if(!collection){S(l," result=COLLECTION_NOT_FOUND\r\n");LogRaw(l.b);return false;}

    CreateEmitterGroupFn create=(CreateEmitterGroupFn)(g_base+RVA_CREATE_EMITTER_GROUP);
    void*emitterSystem=(void*)(g_base+RVA_EMITTER_SYSTEM_OBJECT);
    void*group=create(emitterSystem,collection,NATIVE_GROUP_FLAGS);
    S(l," group=");P(l,group);
    if(!group){S(l," result=GROUP_CREATE_FAILED\r\n");LogRaw(l.b);return false;}

    NativeMatrix wm;BuildNativeWorldMatrix(r->simOrigin,wm);
    SetEmitterLocalWorldFn setWorld=(SetEmitterLocalWorldFn)(g_base+RVA_SET_EMITTER_LOCAL_WORLD);
    setWorld(group,&wm);
    // Existing retail particle-system call sites set bit 0 after assigning the local world.
    *(volatile u32*)((u8*)group+0x18) |= 1u;
    S(l," result=SPAWNED posSim=(");F1(l,r->simOrigin.x);C(l,',');F1(l,r->simOrigin.y);C(l,',');F1(l,r->simOrigin.z);S(l,") posRender=(");F1(l,wm.m[3][0]);C(l,',');F1(l,wm.m[3][1]);C(l,',');F1(l,wm.m[3][2]);S(l,") flags=");HX(l,*(volatile u32*)((u8*)group+0x18));S(l," oneShotStopMs=");U(l,NATIVE_EMIT_STOP_MS);S(l,"\r\n");LogRaw(l.b);
    TrackNativeFxGroup(group,r->serial);
    return true;
}

static void __cdecl NativeFxResourcesReady(void*ctx){
    NativeFxRequest*r=(NativeFxRequest*)ctx;
    if(!r)return;
    LB l;I(l);S(l,"NATIVE_FX_READY serial=");U(l,r->serial);S(l," age_ms=");U(l,KGetTickCount()-r->tick);S(l," context=");P(l,r);S(l,"\r\n");LogRaw(l.b);
    CreateNativeGasStationFx(r,"QUEUE_CALLBACK");
    r->pending=false;
}

static NativeFxRequest* AllocNativeRequest(){
    DWORD now=KGetTickCount();
    for(u32 i=0;i<8;i++)if(!g_nativeReq[i].pending)return &g_nativeReq[i];
    u32 oldest=0;DWORD oldestAge=0;
    for(u32 i=0;i<8;i++){DWORD a=now-g_nativeReq[i].tick;if(a>oldestAge){oldestAge=a;oldest=i;}}
    return &g_nativeReq[oldest];
}

static bool QueueNativeGasStationFx(const Vec3&origin){
    EffectNameToKeyFn effectKey=(EffectNameToKeyFn)(g_base+RVA_EFFECT_NAME_TO_KEY);
    StringToKeyFn attribKey=(StringToKeyFn)(g_base+RVA_STRING_TO_KEY);
    if(!g_fxQueueKey)g_fxQueueKey=effectKey("fxex_gasstation");
    if(!g_fxAttribKey)g_fxAttribKey=attribKey("fxex_gasstation");
    NativeFxRequest*r=AllocNativeRequest();
    r->pending=true;r->tick=KGetTickCount();r->simOrigin=origin;r->queueKey=g_fxQueueKey;r->attribKey=g_fxAttribKey;r->serial=++g_nativeSerial;

    LB l;I(l);S(l,"NATIVE_FX_QUEUE effect=fxex_gasstation serial=");U(l,r->serial);S(l," queueKey=");HX(l,r->queueKey);S(l," attribKey=");HX(l,r->attribKey);S(l," pos=(");F1(l,origin.x);C(l,',');F1(l,origin.y);C(l,',');F1(l,origin.z);S(l,") context=");P(l,r);S(l,"\r\n");LogRaw(l.b);
    if(!r->queueKey){LogRaw("NATIVE_FX_QUEUE result=NO_EFFECT_KEY\r\n");r->pending=false;return false;}

    // QueueSpawnEmitterGroup_ctxB(list,count,completionCallback,context,flags).
    // The engine invokes completionCallback(context) after the emitter resources are resident.
    QueueSpawnFn queue=(QueueSpawnFn)(g_base+RVA_QUEUE_SPAWN_CTX_B);
    queue(&r->queueKey,1,(void*)&NativeFxResourcesReady,r,0u);
    LogRaw("NATIVE_FX_QUEUE result=CALLED callback=NativeFxResourcesReady flags=0\r\n");
    return true;
}

#include "TrailerBodyProbe.h"

// ---- Minimal EndScene frame hook: no custom rendering -------------------------
static void** D3DVt(void*d){return d?*(void***)d:nullptr;}
static HRESULT __stdcall HookEndScene(void*dev){
    if(g_inRender||!g_origEndScene)return g_origEndScene?g_origEndScene(dev):0;
    g_inRender=true;
    MaintainFrozenTractors();
    MaintainNativeFxLifecycle();
    BodyProbe::frame();
    g_inRender=false;
    return g_origEndScene(dev);
}
static bool PatchVtEntry(void**vt,u32 slot,void*hook,void**orig){DWORD old=0;if(!KVirtualProtect(&vt[slot],sizeof(void*),PAGE_EXECUTE_READWRITE,&old))return false;*orig=vt[slot];vt[slot]=hook;DWORD tmp=0;KVirtualProtect(&vt[slot],sizeof(void*),old,&tmp);return true;}
static bool EnsureFrameHook(){
    if(g_renderHookInstalled)return true;
    void*dev=*(void**)(g_base+RVA_D3D_DEVICE_PTR);
    if(!dev){LogRaw("FRAME_HOOK install=NO reason=DEVICE_NULL\r\n");return false;}
    void**vt=D3DVt(dev);if(!vt||!vt[42]){LogRaw("FRAME_HOOK install=NO reason=VTABLE_NULL\r\n");return false;}
    void*orig=nullptr;if(!PatchVtEntry(vt,42,(void*)&HookEndScene,&orig)){LogRaw("FRAME_HOOK install=NO reason=ENDSCENE_VIRTUALPROTECT\r\n");return false;}
    g_origEndScene=(EndSceneFn)orig;g_hookedD3DVtable=vt;g_renderHookInstalled=true;
    LB l;I(l);S(l,"FRAME_HOOK install=YES device=");P(l,dev);S(l," vtable=");P(l,vt);S(l," originalEndScene=");P(l,(void*)g_origEndScene);S(l," purpose=TRACTOR_HOLD_ONLY customD3Dfx=NO\r\n");LogRaw(l.b);return true;
}

static void LogCop(bool pursuit,const Vec3&o,const CopStats&s){LB l;I(l);S(l,"COPKILL pursuit=");S(l,pursuit?"YES":"NO");S(l," radius_m=50 origin=(");F1(l,o.x);C(l,',');F1(l,o.y);C(l,',');F1(l,o.z);S(l,") total=");U(l,s.total);S(l," alive=");U(l,s.alive);S(l," inRadius=");U(l,s.inRadius);S(l," calls=");U(l,s.calls);S(l," confirmed=");U(l,s.confirmed);S(l,"\r\n");LogRaw(l.b);}

static void __fastcall HookDamageCopImpact(void*self,void*,void*v1,void*v2,float f1,float f2,void*surface,void*otherSim){
    void*selfSim=self?*(void**)((u8*)self+0x34):nullptr;
    void*selfV=FindVehicleBySim(selfSim);void*otherV=FindVehicleBySim(otherSim);
    const char*selfN=selfV?VName(selfV):nullptr;const char*otherN=otherV?VName(otherV):nullptr;
    bool tanker=selfV&&selfN&&EqI(selfN,"trailera");void*tractor=tanker?FindTractor(selfV):nullptr;
    bool external=tanker&&otherV&&otherV!=selfV&&otherV!=tractor;
    const Vec3*prePos=selfV?VPos(selfV):nullptr;Vec3 origin={0,0,0};if(prePos)origin=*prePos;
    bool fresh=tanker&&!AlreadyTriggeredAt(selfV,origin);bool hard=(f2>=5.0f)||(f1>=12000.0f);
    g_origImpact(self,v1,v2,f1,f2,surface,otherSim);
    if(g_inImpact||!tanker||!external||!fresh||!hard)return;
    g_inImpact=true;MarkTriggeredAt(selfV,origin);
    LB l;I(l);S(l,"TANKER_TRIGGER tick=");U(l,KGetTickCount());S(l," trailer=");P(l,selfV);S(l," tractor=");P(l,tractor);S(l," other=");S(l,otherN?otherN:"<vehicle>");S(l," otherDrv=");SI(l,VDriver(otherV));S(l," f1=");F1(l,f1);S(l," closing=");F1(l,f2);S(l," pos=(");F1(l,origin.x);C(l,',');F1(l,origin.y);C(l,',');F1(l,origin.z);S(l,") oneShotMarked=YES\r\n");LogRaw(l.b);

    bool stopped=HoldTractorSpeed(tractor);FreezeTractor(tractor,origin);bool frameHook=EnsureFrameHook();
    bool nativeQueued=QueueNativeGasStationFx(origin);
    void*player=FindPlayer();SoundResult sr=PlayExplosionSound(origin,player);
    LB a;I(a);S(a,"EXPLOSION_STAGE tractorStopped=");S(a,stopped?"YES":"NO");S(a," frameHook=");S(a,frameHook?"YES":"NO");S(a," nativeGasStationQueued=");S(a,nativeQueued?"YES":"NO");S(a," customD3Dfx=NO soundApi=");S(a,sr.api?"YES":"NO");S(a," soundTier=");S(a,sr.tier);S(a," soundPlayed=");S(a,sr.played?"YES":"NO");S(a," soundDistSq=");F1(a,sr.distSq);S(a,"\r\n");LogRaw(a.b);

    bool pursuit=PursuitActive(player);CopStats cs={};if(pursuit)cs=KillCops50(origin);LogCop(pursuit,origin,cs);
    BodyProbe::run(self,selfV,selfSim,"PRE_DESTROY");
    bool destroyCall=DestroyVehicle(selfV);bool destroyed=VDestroyed(selfV);
    LB z;I(z);S(z,"TANKER_DONE destroyCall=");S(z,destroyCall?"YES":"NO");S(z," trailerDestroyed=");S(z,destroyed?"YES":"NO");S(z," tractorDestroyed=NO oneShot=YES visual=NATIVE_FXEX_GASSTATION\r\n");LogRaw(z.b);
    g_inImpact=false;
}

static bool InstallImpactHook(){u8*target=(u8*)(g_base+RVA_DAMAGE_COP_ON_IMPACT);const u8 sig[6]={0x53,0x56,0x8B,0x74,0x24,0x20};for(u32 i=0;i<6;i++)if(target[i]!=sig[i]){LB l;I(l);S(l,"ERROR Impact signature mismatch byte=");U(l,i);S(l," got=");HX(l,target[i]);S(l," expected=");HX(l,sig[i]);S(l,"\r\n");LogRaw(l.b);return false;}u8*tr=(u8*)KVirtualAlloc(nullptr,64,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);if(!tr){LogRaw("ERROR Impact trampoline VirtualAlloc failed.\r\n");return false;}for(u32 i=0;i<6;i++)tr[i]=target[i];tr[6]=0xE9;*(s32*)(tr+7)=(s32)((target+6)-(tr+11));g_origImpact=(ImpactFn)tr;DWORD old=0;if(!KVirtualProtect(target,6,PAGE_EXECUTE_READWRITE,&old)){LogRaw("ERROR Impact VirtualProtect failed.\r\n");return false;}target[0]=0xE9;*(s32*)(target+1)=(s32)((u8*)&HookDamageCopImpact-(target+5));target[5]=0x90;DWORD tmp=0;KVirtualProtect(target,6,old,&tmp);LB l;I(l);S(l,"HOOK DamageCopCar::OnImpact target=");P(l,target);S(l," trampoline=");P(l,tr);S(l," code=");S(l,target[0]==0xE9?"PATCHED":"BAD");S(l,"\r\n");LogRaw(l.b);return true;}

static void RestoreFrameHook(){if(g_renderHookInstalled&&g_hookedD3DVtable&&g_origEndScene){DWORD old=0;if(KVirtualProtect(&g_hookedD3DVtable[42],sizeof(void*),PAGE_EXECUTE_READWRITE,&old)){if(g_hookedD3DVtable[42]==(void*)&HookEndScene)g_hookedD3DVtable[42]=(void*)g_origEndScene;DWORD tmp=0;KVirtualProtect(&g_hookedD3DVtable[42],sizeof(void*),old,&tmp);}}g_renderHookInstalled=false;}

extern "C" BOOL WINAPI DllMain(HMODULE h,DWORD reason,LPVOID){
    if(reason==DLL_PROCESS_ATTACH){
        g_selfModule=h;g_base=PREFERRED_BASE;InitLog();
        BuildSiblingPath(g_soundNear,sizeof(g_soundNear),"TrailerImpactMod_explosion_near.wav");BuildSiblingPath(g_soundMid,sizeof(g_soundMid),"TrailerImpactMod_explosion_mid.wav");BuildSiblingPath(g_soundFar,sizeof(g_soundFar),"TrailerImpactMod_explosion_far.wav");
        bool snd=InitSound();
        LogRaw("--- TrailerImpactMod 3.3b NATIVE BODY REBUILD TEST loaded; gameplay source=2.9c ---\r\n");
        LogRaw("Trigger: TRAILERA DamageCopCar::OnImpact; external vehicle only; own SEMIA excluded; hard impact gate; one-shot per physical spawn (100m pointer-reuse reset).\r\n");
        LogRaw("Visual: native NFSMW fxex_gasstation; emitters stopped after initial blast while already-emitted particles finish naturally. Custom D3D particles disabled.\r\n");
        LogRaw("Sound: sibling bombastic NEAR/MID/FAR WAV selected by player distance; PlaySoundA async.\r\n");
        LogRaw("Gameplay: safe speed-only SEMIA hold from 2.8; destroy TRAILERA; active-pursuit cops within 50m destroyed.\r\n");
        LB l;I(l);S(l,"INIT d3dDevicePtrGlobal=");HX(l,g_base+RVA_D3D_DEVICE_PTR);S(l," emitterSystem=");HX(l,g_base+RVA_EMITTER_SYSTEM_OBJECT);S(l," createEmitterGroup=");HX(l,g_base+RVA_CREATE_EMITTER_GROUP);S(l," soundApi=");S(l,snd?"YES":"NO");S(l,"\r\n");LogRaw(l.b);
        if(InstallImpactHook())LogRaw("TrailerImpactMod 3.3b: tanker hook installed; guarded per-instance BODY rebuild. Native fxex_gasstation one-shot + per-spawn spatial lock armed.\r\n");
    }else if(reason==DLL_PROCESS_DETACH){RestoreFrameHook();if(g_log&&g_log!=INVALID_HANDLE_VALUE){KCloseHandle(g_log);g_log=INVALID_HANDLE_VALUE;}}
    return 1;
}
