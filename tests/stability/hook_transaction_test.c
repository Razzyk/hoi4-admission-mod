/* Disposable process test; includes private engine routines, never targets HOI4. */
#define STABILITY_GUARD_TEST 1
#include "../../native/stability/stability_guard.c"

static volatile LONG64 original_calls, kernel_entries;
static unsigned assertions;
_Static_assert(sizeof(StabilityGuardStats)==48, "stable diagnostic layout");
static void mock_scheduler(void *state) { (void)state; InterlockedIncrement64(&original_calls); }
static void mock_kernel(CareerCapture *capture,const CareerRange *range)
{
    if (range->begin!=0 || range->end!=capture->countries->count) ExitProcess(99);
    for (int32_t i=range->begin;i<range->end;++i) InterlockedIncrement64(&kernel_entries);
}
static DWORD WINAPI idle_thread(void *unused) { (void)unused; return 0; }
static int check(int truth,const char *label)
{
    ++assertions;
    if (!truth) { fprintf(stderr,"FAIL: %s (Win32 %lu)\n",label,(unsigned long)GetLastError()); return 0; }
    return 1;
}

typedef enum {
    FAULT_NONE, FAULT_QUERY_LATE_THREAD, FAULT_QUERY_REUSED_ID, FAULT_QUERY_MALFORMED_OFFSET,
    FAULT_QUERY_MALFORMED_COUNT, FAULT_QUERY_SHORT_BUFFER, FAULT_QUERY_BUFFER_FULL,
    FAULT_QUERY_ERROR, FAULT_QUERY_WARNING, FAULT_QUERY_WRONG_OWNER, FAULT_QUERY_DUPLICATE_ID,
    FAULT_QUERY_MISSING_PROCESS, FAULT_QUERY_MISSING_CALLER,
    FAULT_OPEN, FAULT_OWNER, FAULT_THREAD_ID, FAULT_TIMES,
    FAULT_CREATED_TIME, FAULT_SUSPEND, FAULT_CONTEXT, FAULT_RESUME_ONCE,
    FAULT_RESUME_ALWAYS, FAULT_PROTECT_WRITE, FAULT_PROTECT_RESTORE, FAULT_FLUSH_ONCE,
    FAULT_FLUSH_ALWAYS
} FaultMode;

static FaultMode fault_mode;
static DWORD fault_thread_id;
static QuerySystemInformation real_query;
static unsigned fault_query_calls, fault_hits, fault_rw_calls;

/* Hooks allocate and log nothing: they may execute while other threads are frozen. */
static NTSTATUS NTAPI fault_query(SYSTEM_INFORMATION_CLASS info,PVOID buffer,ULONG capacity,PULONG used)
{
    NTSTATUS result=real_query(info,buffer,capacity,used);
    ++fault_query_calls;
    if (result<0 || fault_query_calls!=2) return result;
    switch (fault_mode) {
    case FAULT_QUERY_SHORT_BUFFER: ++fault_hits; *used=sizeof(SYSTEM_PROCESS_INFORMATION)-1; return 0;
    case FAULT_QUERY_BUFFER_FULL: ++fault_hits; return (NTSTATUS)0xc0000004u;
    case FAULT_QUERY_ERROR: ++fault_hits; return (NTSTATUS)0xc0000022u;
    case FAULT_QUERY_WARNING: ++fault_hits; return 1;
    case FAULT_QUERY_MALFORMED_OFFSET:
        ++fault_hits; ((SYSTEM_PROCESS_INFORMATION *)buffer)->NextEntryOffset=1; return 0;
    default: break;
    }
    if (fault_mode!=FAULT_QUERY_LATE_THREAD && fault_mode!=FAULT_QUERY_REUSED_ID &&
        fault_mode!=FAULT_QUERY_MALFORMED_COUNT && fault_mode!=FAULT_QUERY_WRONG_OWNER &&
        fault_mode!=FAULT_QUERY_DUPLICATE_ID && fault_mode!=FAULT_QUERY_MISSING_PROCESS &&
        fault_mode!=FAULT_QUERY_MISSING_CALLER) return result;
    size_t offset=0;
    while (offset+sizeof(SYSTEM_PROCESS_INFORMATION)<=*used) {
        SYSTEM_PROCESS_INFORMATION *process=(SYSTEM_PROCESS_INFORMATION *)((unsigned char *)buffer+offset);
        if ((uintptr_t)process->UniqueProcessId==GetCurrentProcessId()) {
            if (fault_mode==FAULT_QUERY_MISSING_PROCESS) {
                ++fault_hits; process->UniqueProcessId=(HANDLE)(uintptr_t)0x3fffffffu; return 0;
            }
            if (fault_mode==FAULT_QUERY_MISSING_CALLER) {
                ++fault_hits; process->NumberOfThreads=0; return 0;
            }
            if (fault_mode==FAULT_QUERY_MALFORMED_COUNT) {
                ++fault_hits; process->NumberOfThreads=MAXDWORD; return 0;
            }
            SYSTEM_THREAD_INFORMATION *entries=(SYSTEM_THREAD_INFORMATION *)(process+1);
            for (ULONG i=0;i<process->NumberOfThreads;++i) {
                if ((uintptr_t)entries[i].ClientId.UniqueThread==fault_thread_id) {
                    if (fault_mode==FAULT_QUERY_LATE_THREAD)
                        entries[i].ClientId.UniqueThread=(HANDLE)(uintptr_t)0x3fffffffu;
                    else if (fault_mode==FAULT_QUERY_WRONG_OWNER)
                        entries[i].ClientId.UniqueProcess=(HANDLE)(uintptr_t)(GetCurrentProcessId()+1);
                    else if (fault_mode==FAULT_QUERY_DUPLICATE_ID)
                        entries[i].ClientId.UniqueThread=(HANDLE)(uintptr_t)GetCurrentThreadId();
                    else entries[i].Reserved1[2].QuadPart^=1;
                    ++fault_hits; return 0;
                }
            }
            return (NTSTATUS)0xc0000001u;
        }
        if (!process->NextEntryOffset || process->NextEntryOffset>*used-offset) break;
        offset+=process->NextEntryOffset;
    }
    return (NTSTATUS)0xc0000001u;
}

static int fault_target(HANDLE thread) { return GetThreadId(thread)==fault_thread_id; }
static HANDLE WINAPI fault_open(DWORD access,BOOL inherit,DWORD id)
{
    if (fault_mode==FAULT_OPEN && id==fault_thread_id) {
        ++fault_hits; SetLastError(ERROR_ACCESS_DENIED); return NULL;
    }
    return OpenThread(access,inherit,id);
}
static DWORD WINAPI fault_owner(HANDLE thread)
{
    if (fault_mode==FAULT_OWNER && fault_target(thread)) { ++fault_hits; return GetCurrentProcessId()+1; }
    return GetProcessIdOfThread(thread);
}
static DWORD WINAPI fault_id(HANDLE thread)
{
    DWORD id=GetThreadId(thread);
    if (fault_mode==FAULT_THREAD_ID && id==fault_thread_id) { ++fault_hits; return id+1; }
    return id;
}
static BOOL WINAPI fault_times(HANDLE thread,LPFILETIME created,LPFILETIME exited,LPFILETIME kernel_time,LPFILETIME user_time)
{
    if (fault_mode==FAULT_TIMES && fault_target(thread)) {
        ++fault_hits; SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    BOOL result=GetThreadTimes(thread,created,exited,kernel_time,user_time);
    if (result && fault_mode==FAULT_CREATED_TIME && fault_target(thread)) { ++fault_hits; created->dwLowDateTime^=1; }
    return result;
}
static DWORD WINAPI fault_suspend(HANDLE thread)
{
    if (fault_mode==FAULT_SUSPEND && fault_target(thread)) {
        ++fault_hits; SetLastError(ERROR_ACCESS_DENIED); return (DWORD)-1;
    }
    return SuspendThread(thread);
}
static BOOL WINAPI fault_context(HANDLE thread,LPCONTEXT context)
{
    if (fault_mode==FAULT_CONTEXT && fault_target(thread)) {
        ++fault_hits; SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return GetThreadContext(thread,context);
}
static DWORD WINAPI fault_resume(HANDLE thread)
{
    if ((fault_mode==FAULT_RESUME_ALWAYS || (fault_mode==FAULT_RESUME_ONCE && !fault_hits)) && fault_target(thread)) {
        ++fault_hits; SetLastError(ERROR_ACCESS_DENIED); return (DWORD)-1;
    }
    return ResumeThread(thread);
}
static BOOL WINAPI fault_protect(LPVOID address,SIZE_T size,DWORD protection,PDWORD old)
{
    if (address==call_site && protection==PAGE_EXECUTE_READWRITE) ++fault_rw_calls;
    if (address==call_site && !fault_hits &&
        ((fault_mode==FAULT_PROTECT_WRITE && protection==PAGE_EXECUTE_READWRITE) ||
         (fault_mode==FAULT_PROTECT_RESTORE && protection==PAGE_EXECUTE_READ))) {
        ++fault_hits; SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return VirtualProtect(address,size,protection,old);
}
static BOOL WINAPI fault_flush(HANDLE process,LPCVOID address,SIZE_T size)
{
    if (address==call_site && (fault_mode==FAULT_FLUSH_ALWAYS || (fault_mode==FAULT_FLUSH_ONCE && !fault_hits))) {
        ++fault_hits; SetLastError(ERROR_WRITE_FAULT); return FALSE;
    }
    return FlushInstructionCache(process,address,size);
}

static void set_fault_hooks(FaultMode mode,DWORD target_id)
{
    memset(&stability_test_hooks,0,sizeof(stability_test_hooks));
    fault_mode=mode; fault_thread_id=target_id;
    fault_hits=fault_query_calls=fault_rw_calls=0;
    real_query=(QuerySystemInformation)(uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation");
    stability_test_hooks.query=fault_query;
    stability_test_hooks.open_thread=fault_open;
    stability_test_hooks.process_id_of_thread=fault_owner;
    stability_test_hooks.thread_id=fault_id;
    stability_test_hooks.get_thread_times=fault_times;
    stability_test_hooks.suspend_thread=fault_suspend;
    stability_test_hooks.get_thread_context=fault_context;
    stability_test_hooks.resume_thread=fault_resume;
    stability_test_hooks.protect=fault_protect;
    stability_test_hooks.flush=fault_flush;
}

static int fault_case(FaultMode mode,const char *label,const unsigned char original[5])
{
    DWORD id;
    HANDLE thread=CreateThread(NULL,0,idle_thread,NULL,CREATE_SUSPENDED,&id);
    if (!check(thread!=NULL,"create already-paused failure fixture thread")) return 0;
    set_fault_hooks(mode,id);
    DWORD result=patch_transaction(original,installed_bytes);
    memset(&stability_test_hooks,0,sizeof(stability_test_hooks));
    printf("FAULT %s: result=%lu; injected=%u; query=%u; touched=%u; poison=%ld\n",label,
           (unsigned long)result,fault_hits,fault_query_calls,patch_last_written,(long)patch_poisoned);
    if (!check(fault_hits>0,"requested failure was actually injected")) return 0;
    if (mode==FAULT_RESUME_ONCE) {
        if (!check(result==ERROR_SUCCESS && patch_last_thaw_error==0 && !patch_poisoned &&
                   !memcmp(call_site,installed_bytes,5),"transient resume failure retries safely and installs complete CALL")) return 0;
    } else {
        if (!check(result!=ERROR_SUCCESS && !memcmp(call_site,original,5),label)) return 0;
        if (mode!=FAULT_FLUSH_ONCE && mode!=FAULT_PROTECT_RESTORE && mode!=FAULT_FLUSH_ALWAYS) {
            if (!check(!patch_last_written,"pre-write refusal leaves all instruction bytes untouched")) return 0;
            if (mode!=FAULT_PROTECT_WRITE && !check(fault_rw_calls==0,"thread/query refusal never enables writing")) return 0;
        }
    }
    MEMORY_BASIC_INFORMATION memory;
    if (!check(VirtualQuery(call_site,&memory,sizeof(memory))==sizeof(memory) && memory.Protect==PAGE_EXECUTE_READ,
               "failure or recovered transaction retains original RX protection")) return 0;
    if (!check(ResumeThread(thread)==1,"failure removes only its own suspension increment")) return 0;
    if (!check(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0,"failure fixture thread terminates")) return 0;
    CloseHandle(thread);
    if (mode==FAULT_RESUME_ONCE && !check(patch_transaction(installed_bytes,original)==ERROR_SUCCESS,
                                         "restore successful CALL after transient resume test")) return 0;
    if (mode==FAULT_PROTECT_RESTORE || mode==FAULT_FLUSH_ALWAYS) {
        if (!check(patch_poisoned && !StabilityGuardInstalled() &&
                   patch_transaction(original,installed_bytes)==ERROR_INVALID_STATE && !memcmp(call_site,original,5),
                   "uncertain protection/cache recovery poisons future patching")) return 0;
    } else if (!check(!patch_poisoned && failed_freeze==NULL,"recoverable failure retains no frozen allocation")) return 0;
    return 1;
}

static int persistent_resume_case(const unsigned char original[5])
{
    DWORD id;
    HANDLE thread=CreateThread(NULL,0,idle_thread,NULL,CREATE_SUSPENDED,&id);
    if (!check(thread!=NULL,"create persistent resume fixture")) return 0;
    set_fault_hooks(FAULT_RESUME_ALWAYS,id);
    DWORD result=patch_transaction(original,installed_bytes);
    memset(&stability_test_hooks,0,sizeof(stability_test_hooks));
    if (!check(result!=ERROR_SUCCESS && fault_hits==3 && patch_last_thaw_error!=0 && patch_poisoned &&
               failed_freeze!=NULL && !StabilityGuardInstalled(),"three failed resumes preserve frozen bookkeeping and poison lifecycle")) return 0;
    if (!check(!memcmp(call_site,installed_bytes,5) && patch_last_written &&
               patch_transaction(installed_bytes,original)==ERROR_INVALID_STATE,
               "failed thaw preserves resident complete hook and blocks future memory changes")) return 0;
    MEMORY_BASIC_INFORMATION memory;
    if (!check(VirtualQuery(call_site,&memory,sizeof(memory))==sizeof(memory) && memory.Protect==PAGE_EXECUTE_READ,
               "persistent resume failure leaves executable page RX")) return 0;
    unsigned owned_frozen=0;
    for (size_t i=0;i<failed_freeze->count;++i)
        if (failed_freeze->threads[i].id==id && failed_freeze->threads[i].suspended && failed_freeze->threads[i].handle) ++owned_frozen;
    if (!check(owned_frozen==1 && VirtualQuery(failed_freeze->query_buffer,&memory,sizeof(memory))==sizeof(memory) &&
               memory.State==MEM_COMMIT,"failed thaw retains its handle and preallocated query buffer")) return 0;
    /* Probe the count without releasing either existing increment. */
    if (!check(SuspendThread(thread)==2 && ResumeThread(thread)==3,
               "persistent failure retained both owned and preexisting suspension increments")) return 0;
    if (!check(StabilityGuardTestRecoverFrozen()==ERROR_SUCCESS && failed_freeze==NULL &&
               !frozen_failure && patch_poisoned,
               "test-only recovery thaws retained handles without clearing poison")) return 0;
    if (!check(ResumeThread(thread)==1,"test-only recovery preserves the preexisting suspension count")) return 0;
    if (!check(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0,"manually recovered fixture thread terminates")) return 0;
    CloseHandle(thread);
    return 1;
}

typedef struct {
    CareerScheduler invoke;
    void *state;
    volatile LONG stop;
    volatile LONG64 iterations;
    volatile LONG64 created_threads;
    volatile LONG worker_errors;
} CallStress;

static DWORD WINAPI continuous_calls(void *argument)
{
    CallStress *stress=argument;
    unsigned local_calls=0;
    while (!InterlockedCompareExchange(&stress->stop,0,0)) {
        stress->invoke(stress->state);
        InterlockedIncrement64(&stress->iterations);
        if ((++local_calls & 255u)==0) SwitchToThread();
    }
    return 0;
}

static DWORD WINAPI one_new_thread_call(void *argument)
{
    CallStress *stress=argument;
    stress->invoke(stress->state);
    InterlockedIncrement64(&stress->iterations);
    return 0;
}

static DWORD WINAPI continuous_thread_creation(void *argument)
{
    CallStress *stress=argument;
    while (!InterlockedCompareExchange(&stress->stop,0,0)) {
        HANDLE child=CreateThread(NULL,0,one_new_thread_call,stress,0,NULL);
        if (!child) { InterlockedIncrement(&stress->worker_errors); return 1; }
        InterlockedIncrement64(&stress->created_threads);
        DWORD exit_code=1;
        if (WaitForSingleObject(child,5000)!=WAIT_OBJECT_0 ||
            !GetExitCodeThread(child,&exit_code) || exit_code) {
            InterlockedIncrement(&stress->worker_errors);
            CloseHandle(child);
            return 1;
        }
        CloseHandle(child);
        Sleep(1);
    }
    return 0;
}

static int stress_refusal(DWORD result)
{
    /* A short-lived thread can exit between the enumeration and Open/GetContext. */
    return result==ERROR_BUSY || result==ERROR_INVALID_PARAMETER || result==ERROR_INVALID_HANDLE ||
        result==ERROR_NOT_FOUND || result==ERROR_ACCESS_DENIED || result==ERROR_NO_MORE_FILES;
}

static int concurrent_patch_stress(CareerScheduler invoke,void *state,const unsigned char original[5])
{
    CallStress stress={0};
    stress.invoke=invoke; stress.state=state;
    LONG64 old_original=InterlockedCompareExchange64(&original_calls,0,0);
    LONG64 old_entries=InterlockedCompareExchange64(&kernel_entries,0,0);
    HANDLE threads[3]={0};
    threads[0]=CreateThread(NULL,0,continuous_calls,&stress,0,NULL);
    threads[1]=CreateThread(NULL,0,continuous_calls,&stress,0,NULL);
    threads[2]=CreateThread(NULL,0,continuous_thread_creation,&stress,0,NULL);
    if (!check(threads[0] && threads[1] && threads[2],"create CALL workers and continuous thread creator")) return 0;
    DWORD start=GetTickCount();
    unsigned cycles=0,refusals=0;
    int patched=0;
    while (cycles<16 && GetTickCount()-start<15000) {
        const unsigned char *expected=patched?installed_bytes:original;
        const unsigned char *replacement=patched?original:installed_bytes;
        DWORD result=patch_transaction(expected,replacement);
        if (result) {
            if (!check(stress_refusal(result),"live thread churn is refused safely")) return 0;
            if (!check(!memcmp(call_site,expected,5),"refused live patch preserves all expected bytes")) return 0;
            ++refusals;
        } else {
            patched=!patched;
            if (!patched) ++cycles;
            if (!check(!memcmp(call_site,replacement,5),"successful live patch writes the complete replacement")) return 0;
        }
        MEMORY_BASIC_INFORMATION memory;
        if (!check(VirtualQuery(call_site,&memory,sizeof(memory))==sizeof(memory) && memory.Protect==PAGE_EXECUTE_READ,
                   "live patch or refusal leaves CALL page RX")) return 0;
        Sleep(2);
    }
    InterlockedExchange(&stress.stop,1);
    if (!check(WaitForMultipleObjects(3,threads,TRUE,5000)==WAIT_OBJECT_0,
               "CALL workers and thread creator all terminate after freeze cycles")) return 0;
    for (unsigned i=0;i<3;++i) {
        DWORD exit_code=1;
        if (!check(GetExitCodeThread(threads[i],&exit_code) && exit_code==0,"stress worker exits successfully")) return 0;
        CloseHandle(threads[i]);
    }
    if (patched && !check(patch_transaction(installed_bytes,original)==ERROR_SUCCESS,
                          "restore original CALL after stopped stress workers")) return 0;
    LONG64 native_calls=InterlockedCompareExchange64(&original_calls,0,0)-old_original;
    LONG64 serial_entries=InterlockedCompareExchange64(&kernel_entries,0,0)-old_entries;
    if (!check(cycles==16,"complete sixteen install/remove cycles during actual CALL and thread creation")) return 0;
    if (!check(stress.worker_errors==0 && stress.created_threads>0,"continuous thread creation made progress without leaks")) return 0;
    if (!check(native_calls>0 && serial_entries>0 && serial_entries%4==0 &&
               native_calls+serial_entries/4==stress.iterations,
               "every completed concurrent CALL executes exactly one original or guarded callback")) return 0;
    if (!check(!memcmp(call_site,original,5),"concurrent fixture ends with original CALL")) return 0;
    printf("PASS concurrent CALL/thread-creation stress: cycles=%u; safe refusals=%u; calls=%lld; created=%lld\n",
           cycles,refusals,(long long)stress.iterations,(long long)stress.created_threads);
    return 1;
}
int main(int argc,char **argv)
{
    if (!check(StabilityGuardStart(NULL,NULL)==ERROR_INVALID_PARAMETER && !StabilityGuardInstalled(),
               "missing admission module rejected before lifecycle changes")) return 1;
    if (!check(StabilityGuardVerify()==ERROR_INVALID_STATE,
               "verification refuses an uninstalled guard")) return 1;
    if (!check(StabilityGuardGetStats(NULL)==ERROR_INVALID_PARAMETER,
               "missing statistics destination refused")) return 1;
    uintptr_t center=(uintptr_t)&mock_scheduler & ~(uintptr_t)65535;
    unsigned char *page=NULL;
    for (uintptr_t distance=65536;distance<0x40000000 && !page;distance+=65536) {
        if (center>distance) page=VirtualAlloc((void *)(center-distance),4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    }
    if (!check(page!=NULL,"allocate test code near fixture")) return 1;
    const unsigned char prologue[4]={0x48,0x83,0xec,0x28};
    const unsigned char epilogue[5]={0x48,0x83,0xc4,0x28,0xc3};
    memcpy(page,prologue,4); memcpy(page+9,epilogue,5); call_site=page+4;
    unsigned char original[5]={0xe8,0,0,0,0};
    intptr_t distance=(intptr_t)&mock_scheduler-(intptr_t)(call_site+5);
    if (!check(distance>=INT32_MIN && distance<=INT32_MAX,"original CALL reach")) return 1;
    int32_t relative=(int32_t)distance;
    memcpy(original+1,&relative,4); memcpy(call_site,original,5);
    DWORD ignored;
    if (!check(VirtualProtect(page,4096,PAGE_EXECUTE_READ,&ignored),"fixture RX")) return 1;
    call_protection=PAGE_EXECUTE_READ;
    FlushInstructionCache(GetCurrentProcess(),page,14);
    native_scheduler=mock_scheduler; native_kernel=mock_kernel;
    if (!check(prepare_relay()==0,"prepare register-preserving relay")) return 1;
    unsigned char state[HOI4_COUNTRY_ARRAY_OFFSET+sizeof(CareerArray)]={0};
    int32_t countries[4]={3,3,7,7};
    CareerArray array={countries,4,4,NULL};
    memcpy(state+HOI4_COUNTRY_ARRAY_OFFSET,&array,sizeof(array));
    CareerScheduler invoke=(CareerScheduler)(uintptr_t)page;
    if (argc==2) {
        int success=0;
        if (!strcmp(argv[1],"--protect-restore-failure"))
            success=fault_case(FAULT_PROTECT_RESTORE,"restore-protection failure rolls back and refuses future patching",original);
        else if (!strcmp(argv[1],"--persistent-flush-failure"))
            success=fault_case(FAULT_FLUSH_ALWAYS,"both cache flush failures roll back and poison future patching",original);
        else if (!strcmp(argv[1],"--persistent-resume-failure")) success=persistent_resume_case(original);
        else { fprintf(stderr,"Unknown fixture mode.\n"); return 1; }
        if (success) printf("All %u isolated poisoned-transaction assertions passed: %s.\n",assertions,argv[1]);
        /* Intentionally retain mapped fixture code until this process exits. */
        return success?0:1;
    }
    if (!check(argc==1,"fixture argument count")) return 1;
    invoke(state);
    if (!check(original_calls==1 && kernel_entries==0,"native CALL before hook")) return 1;

    unsigned char wrong[5]; memcpy(wrong,original,5); wrong[4]^=1;
    if (!check(patch_transaction(wrong,installed_bytes)==ERROR_REVISION_MISMATCH &&
               !memcmp(call_site,original,5),"changed instruction rejected without writes")) return 1;
    MEMORY_BASIC_INFORMATION memory;
    VirtualQuery(page,&memory,sizeof(memory));
    if (!check(memory.Protect==PAGE_EXECUTE_READ,"mismatch preserves RX")) return 1;

    HANDLE thread=CreateThread(NULL,0,idle_thread,NULL,CREATE_SUSPENDED,NULL);
    if (!check(thread!=NULL,"create paused fixture thread")) return 1;
    CONTEXT saved={0}; saved.ContextFlags=CONTEXT_CONTROL;
    if (!check(GetThreadContext(thread,&saved),"capture paused thread")) return 1;
    CONTEXT unsafe=saved; unsafe.Rip=(DWORD64)(uintptr_t)call_site;
    if (!check(SetThreadContext(thread,&unsafe),"set paused RIP for collision test")) return 1;
    if (!check(patch_transaction(original,installed_bytes)==ERROR_BUSY &&
               !memcmp(call_site,original,5),"thread inside patch span refused")) return 1;
    if (!check(SetThreadContext(thread,&saved) && ResumeThread(thread)==1,
               "preexisting thread suspension preserved")) return 1;
    if (!check(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0,"fixture thread exits")) return 1;
    CloseHandle(thread);

    if (!check(patch_transaction(original,installed_bytes)==0,"CALL installation")) return 1;
    VirtualQuery(page,&memory,sizeof(memory));
    if (!check(memory.Protect==PAGE_EXECUTE_READ,"installed page restores RX")) return 1;
    VirtualQuery(relay,&memory,sizeof(memory));
    if (!check(memory.Protect==PAGE_EXECUTE_READ,"relay is RX")) return 1;
    InterlockedExchange(&lifecycle,2);
    if (!check(StabilityGuardInstalled() && StabilityGuardVerify()==ERROR_SUCCESS,
               "ported installed state verifies CALL and page protections")) return 1;
    invoke(state);
    if (!check(original_calls==1 && kernel_entries==4,"patched relay invokes serial wrapper with preserved argument")) return 1;
    if (!check(!memcmp(countries,(int32_t[]){3,3,7,7},sizeof(countries)),"player list immutable")) return 1;
    StabilityGuardStats stats;
    if (!check(StabilityGuardGetStats(&stats)==ERROR_SUCCESS && stats.size==sizeof(stats) &&
               stats.version==1 && stats.installed==1 && stats.reserved==0 && stats.calls==1 &&
               stats.serialized_days==1 && stats.duplicate_entries_detected==2 && stats.rejected_inputs==0,
               "ported diagnostics report serialization without skipped entries")) return 1;
    if (!check(patch_transaction(installed_bytes,original)==0 && !memcmp(call_site,original,5),"original bytes restored")) return 1;
    InterlockedExchange(&lifecycle,4);
    VirtualQuery(page,&memory,sizeof(memory));
    if (!check(memory.Protect==PAGE_EXECUTE_READ,"uninstalled page restores RX")) return 1;
    if (!check(!StabilityGuardInstalled() && StabilityGuardGetStats(&stats)==ERROR_SUCCESS && stats.installed==0,
               "restored state reports guard inactive")) return 1;
    /* This fixture's synthetic CALL is deliberately not the pinned HOI4 CALL. */
    if (!check(StabilityGuardVerify()==ERROR_REVISION_MISMATCH,
               "restored verifier refuses synthetic bytes as actual HOI4 bytes")) return 1;
    invoke(state);
    if (!check(original_calls==2 && kernel_entries==4,"restored CALL executes original once")) return 1;
    const struct { FaultMode mode; const char *label; } failures[]={
        {FAULT_QUERY_LATE_THREAD,"fresh unknown thread is refused before write"},
        {FAULT_QUERY_REUSED_ID,"fresh reused thread ID with changed creation time is refused"},
        {FAULT_QUERY_MALFORMED_OFFSET,"misaligned process query offset is refused"},
        {FAULT_QUERY_MALFORMED_COUNT,"unbounded thread count is refused"},
        {FAULT_QUERY_SHORT_BUFFER,"truncated process query buffer is refused"},
        {FAULT_QUERY_BUFFER_FULL,"frozen process query capacity failure is refused"},
        {FAULT_QUERY_ERROR,"frozen process query system failure is refused"},
        {FAULT_QUERY_WARNING,"nonzero process query warning is refused"},
        {FAULT_QUERY_WRONG_OWNER,"fresh query thread owner mismatch is refused"},
        {FAULT_QUERY_DUPLICATE_ID,"duplicate query thread identity is refused"},
        {FAULT_QUERY_MISSING_PROCESS,"missing process record is refused"},
        {FAULT_QUERY_MISSING_CALLER,"missing caller thread record is refused"},
        {FAULT_OPEN,"thread open failure is refused"},
        {FAULT_OWNER,"opened thread owner mismatch is refused"},
        {FAULT_THREAD_ID,"opened thread identity mismatch is refused"},
        {FAULT_TIMES,"thread creation-time read failure is refused"},
        {FAULT_CREATED_TIME,"opened thread creation-time mismatch is refused"},
        {FAULT_SUSPEND,"thread suspension failure is refused"},
        {FAULT_CONTEXT,"suspended thread context failure is refused"},
        {FAULT_RESUME_ONCE,"one transient resume failure is recovered"},
        {FAULT_PROTECT_WRITE,"write-protection failure leaves expected instructions unchanged"},
        {FAULT_FLUSH_ONCE,"cache flush failure restores expected instructions and RX protection"}
    };
    for (size_t i=0;i<sizeof(failures)/sizeof(failures[0]);++i)
        if (!fault_case(failures[i].mode,failures[i].label,original)) return 1;
    if (!concurrent_patch_stress(invoke,state,original)) return 1;
    /* Keep code resident through all calls, release only now in this fixture. */
    VirtualFree(page,0,MEM_RELEASE); VirtualFree(relay,0,MEM_RELEASE);
    printf("All %u hook transaction assertions passed: CALL/relay execution, input preservation, mismatch refusal, suspended-RIP refusal, original suspend count, RX protections, ported diagnostics, and uninstall restoration.\n",assertions);
    return 0;
}
