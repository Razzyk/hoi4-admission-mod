/* Ported from Razzyk/hoi4-mp-stability-guard. See STABILITY-PROVENANCE.md.
 * Admission owns DLL startup and logging; all code remains resident until exit. */
#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE 1
#endif
#ifndef _UNICODE
#define _UNICODE 1
#endif
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "target_spec.h"
#include "career_guard.h"
#include "stability_guard.h"
_Static_assert(sizeof(SYSTEM_PROCESS_INFORMATION) == 256, "Windows x64 process query layout");
_Static_assert(sizeof(SYSTEM_THREAD_INFORMATION) == 80, "Windows x64 thread query layout");
_Static_assert(offsetof(SYSTEM_PROCESS_INFORMATION,UniqueProcessId) == 0x50, "Windows x64 queried process identity");
_Static_assert(offsetof(SYSTEM_THREAD_INFORMATION,ClientId) == 0x28, "Windows x64 queried thread identity");
_Static_assert(offsetof(SYSTEM_THREAD_INFORMATION,ThreadState) == 0x44, "Windows x64 queried thread state");
#define THREAD_QUERY_BUFFER_SIZE (8u * 1024u * 1024u)
#define MAX_FROZEN_THREADS 4096u
typedef NTSTATUS (NTAPI *QuerySystemInformation)(SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG);
typedef struct {
    HANDLE handle;
    DWORD id;
    ULONGLONG creation_time;
    DWORD prior_suspend_count;
    unsigned suspended;
} PinnedThread;
typedef struct {
    PinnedThread threads[MAX_FROZEN_THREADS];
    size_t count;
    unsigned char *query_buffer;
    ULONG query_length;
    QuerySystemInformation query;
    DWORD process_id, caller_id;
} FreezeSet;

#ifdef STABILITY_GUARD_TEST
typedef struct {
    QuerySystemInformation query;
    HANDLE (WINAPI *open_thread)(DWORD,BOOL,DWORD);
    DWORD (WINAPI *suspend_thread)(HANDLE);
    BOOL (WINAPI *get_thread_context)(HANDLE,LPCONTEXT);
    DWORD (WINAPI *resume_thread)(HANDLE);
    BOOL (WINAPI *protect)(LPVOID,SIZE_T,DWORD,PDWORD);
    BOOL (WINAPI *flush)(HANDLE,LPCVOID,SIZE_T);
    DWORD (WINAPI *process_id_of_thread)(HANDLE);
    DWORD (WINAPI *thread_id)(HANDLE);
    DWORD (WINAPI *wait_thread)(HANDLE,DWORD);
    BOOL (WINAPI *get_thread_times)(HANDLE,LPFILETIME,LPFILETIME,LPFILETIME,LPFILETIME);
} StabilityGuardTestHooks;
static StabilityGuardTestHooks stability_test_hooks;
#define TEST_API(name,real) (stability_test_hooks.name ? stability_test_hooks.name : real)
#else
#define TEST_API(name,real) real
#endif
static volatile LONG patch_poisoned;
static unsigned patch_last_written;
static DWORD patch_last_thaw_error;
/* A failed thaw may leave target threads paused: do not free or log then. */
static FreezeSet *failed_freeze;
static volatile LONG frozen_failure;

static StabilityGuardLogger stability_logger;
static volatile LONG lifecycle;
static volatile LONG64 calls, guarded_days, skipped_entries, rejected_inputs;
static unsigned char *call_site, *relay;
static unsigned char installed_bytes[5];
static CareerScheduler native_scheduler;
static CareerKernel native_kernel;
static DWORD call_protection;

static void log_line(const char *text)
{
    if (stability_logger) stability_logger(text);
}

static DWORD verify_hash(void)
{
    wchar_t file_path[32768];
    unsigned char digest[32], buffer[65536];
    char actual[65];
    DWORD length = GetModuleFileNameW(NULL,file_path,32768), read_count;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD result = ERROR_INVALID_DATA;
    if (!length || length >= 32768) return ERROR_BAD_PATHNAME;
    file = CreateFileW(file_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    if (BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0) < 0 ||
        BCryptCreateHash(algorithm,&hash,NULL,0,NULL,0,0) < 0) goto done;
    for (;;) {
        if (!ReadFile(file,buffer,sizeof(buffer),&read_count,NULL)) goto done;
        if (!read_count) break;
        if (BCryptHashData(hash,buffer,read_count,0) < 0) goto done;
    }
    if (BCryptFinishHash(hash,digest,sizeof(digest),0) < 0) goto done;
    for (unsigned i = 0; i < 32; ++i) {
        static const char hex[] = "0123456789abcdef";
        actual[i*2] = hex[digest[i] >> 4]; actual[i*2+1] = hex[digest[i]&15];
    }
    actual[64] = 0;
    result = strcmp(actual,HOI4_GAME_SHA256) ? ERROR_REVISION_MISMATCH : ERROR_SUCCESS;
done:
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm,0);
    CloseHandle(file);
    return result;
}

static int readable_executable(const void *address, size_t length)
{
    MEMORY_BASIC_INFORMATION memory;
    if (VirtualQuery(address,&memory,sizeof(memory)) != sizeof(memory) ||
        memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD|PAGE_NOACCESS)) ||
        !(memory.Protect & (PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) return 0;
    uintptr_t start = (uintptr_t)address, end = (uintptr_t)memory.BaseAddress + memory.RegionSize;
    return start <= end && length <= end-start;
}

static DWORD verify_targets(void)
{
    unsigned char *base = (unsigned char *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        dos->e_lfanew > 1048576) return ERROR_BAD_EXE_FORMAT;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base+dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.TimeDateStamp != HOI4_PE_TIMESTAMP ||
        nt->OptionalHeader.SizeOfImage != HOI4_IMAGE_SIZE) return ERROR_BAD_EXE_FORMAT;
    call_site = base+HOI4_CALL_RVA;
    unsigned char *scheduler = base+HOI4_SCHEDULER_RVA, *kernel = base+HOI4_KERNEL_RVA;
    if (!readable_executable(call_site,5) || !readable_executable(scheduler,sizeof(hoi4_scheduler_bytes)) ||
        !readable_executable(kernel,sizeof(hoi4_kernel_bytes)) ||
        memcmp(call_site,hoi4_call_bytes,5) ||
        memcmp(scheduler,hoi4_scheduler_bytes,sizeof(hoi4_scheduler_bytes)) ||
        memcmp(kernel,hoi4_kernel_bytes,sizeof(hoi4_kernel_bytes))) return ERROR_REVISION_MISMATCH;
    int32_t displacement;
    memcpy(&displacement,call_site+1,4);
    if (call_site+5+displacement != scheduler) return ERROR_REVISION_MISMATCH;
    native_scheduler = (CareerScheduler)(uintptr_t)scheduler;
    native_kernel = (CareerKernel)(uintptr_t)kernel;
    MEMORY_BASIC_INFORMATION memory;
    VirtualQuery(call_site,&memory,sizeof(memory));
    call_protection=memory.Protect;
    return ERROR_SUCCESS;
}

static void career_wrapper(void *state)
{
    int32_t scratch[HOI4_MAX_CAREER_ENTRIES];
    CareerOutcome outcome = career_dispatch(state,
        (const CareerArray *)((unsigned char *)state+HOI4_COUNTRY_ARRAY_OFFSET),
        native_scheduler,native_kernel,scratch,HOI4_MAX_CAREER_ENTRIES);
    InterlockedIncrement64(&calls);
    if (outcome.duplicates) {
        InterlockedIncrement64(&guarded_days);
        InterlockedAdd64(&skipped_entries,outcome.duplicates);
    }
    if (outcome.fallback) InterlockedIncrement64(&rejected_inputs);
}

static DWORD prepare_relay(void)
{
    SYSTEM_INFO system;
    GetSystemInfo(&system);
    uintptr_t granularity = system.dwAllocationGranularity;
    uintptr_t center = (uintptr_t)call_site & ~(granularity-1);
    for (uintptr_t step = granularity; step < 0x7fff0000u; step += granularity) {
        uintptr_t candidates[2] = {center >= step ? center-step : 0,center+step};
        for (unsigned i = 0; i < 2; ++i) {
            if (!candidates[i] || candidates[i] < system.dwPageSize ||
                candidates[i] > (uintptr_t)system.lpMaximumApplicationAddress) continue;
            MEMORY_BASIC_INFORMATION memory;
            if (VirtualQuery((void *)candidates[i],&memory,sizeof(memory)) != sizeof(memory) ||
                memory.State != MEM_FREE) continue;
            relay = (unsigned char *)VirtualAlloc((void *)candidates[i],4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
            if (relay) goto found;
        }
    }
    return ERROR_NOT_ENOUGH_MEMORY;
found:
    {
        intptr_t delta = (intptr_t)relay-(intptr_t)(call_site+5);
        if (delta < INT32_MIN || delta > INT32_MAX) { VirtualFree(relay,0,MEM_RELEASE); relay=NULL; return ERROR_INVALID_ADDRESS; }
        /* RIP-indirect JMP forwards without clobbering argument registers. */
        const unsigned char prefix[6] = {0xff,0x25,0,0,0,0};
        uintptr_t destination = (uintptr_t)&career_wrapper;
        memcpy(relay,prefix,6); memcpy(relay+6,&destination,8);
        DWORD old;
        if (!VirtualProtect(relay,4096,PAGE_EXECUTE_READ,&old) || !FlushInstructionCache(GetCurrentProcess(),relay,14)) {
            DWORD result=GetLastError(); VirtualFree(relay,0,MEM_RELEASE); relay=NULL; return result;
        }
        installed_bytes[0]=0xe8;
        int32_t relative=(int32_t)delta;
        memcpy(installed_bytes+1,&relative,4);
    }
    return ERROR_SUCCESS;
}

static DWORD api_error(void)
{
    DWORD result=GetLastError();
    return result ? result : ERROR_GEN_FAILURE;
}

static int thread_exited(HANDLE handle)
{
    return TEST_API(wait_thread,WaitForSingleObject)(handle,0)==WAIT_OBJECT_0;
}

/* Only the one successful SuspendThread increment owned here is removed. */
static DWORD thaw(FreezeSet *threads)
{
    DWORD result=ERROR_SUCCESS;
    for (size_t i=threads->count;i>0;--i) {
        PinnedThread *thread=&threads->threads[i-1];
        if (thread->suspended) {
            DWORD resumed=(DWORD)-1, failure=ERROR_GEN_FAILURE;
            for (unsigned attempt=0;attempt<3;++attempt) {
                resumed=TEST_API(resume_thread,ResumeThread)(thread->handle);
                if (resumed!=(DWORD)-1) break;
                failure=api_error();
                if (thread_exited(thread->handle)) { thread->suspended=0; break; }
            }
            if (resumed!=(DWORD)-1) {
                thread->suspended=0;
                if (resumed!=thread->prior_suspend_count+1 && !result) result=ERROR_INVALID_STATE;
            } else if (thread->suspended && !result) result=failure;
        }
        if (!thread->suspended) { CloseHandle(thread->handle); thread->handle=NULL; }
    }
    return result;
}

static DWORD query_threads(FreezeSet *threads)
{
    ULONG length=0;
    NTSTATUS status=threads->query((SYSTEM_INFORMATION_CLASS)5,threads->query_buffer,
                                  THREAD_QUERY_BUFFER_SIZE,&length);
    if (status!=0) {
        if ((ULONG)status==0xc0000004u || (ULONG)status==0xc0000023u)
            return ERROR_INSUFFICIENT_BUFFER;
        if ((ULONG)status==0xc0000002u || (ULONG)status==0xc0000003u)
            return ERROR_NOT_SUPPORTED;
        return ERROR_GEN_FAILURE;
    }
    if (!length || length>THREAD_QUERY_BUFFER_SIZE) return ERROR_INVALID_DATA;
    threads->query_length=length;
    return ERROR_SUCCESS;
}

/* The same bounded buffer is reused by the final query under suspension. */
static DWORD inspect_threads(FreezeSet *threads,int freeze_complete)
{
    size_t offset=0;
    unsigned found_process=0, found_caller=0;
    for (;;) {
        if (offset>threads->query_length || threads->query_length-offset<sizeof(SYSTEM_PROCESS_INFORMATION))
            return ERROR_INVALID_DATA;
        SYSTEM_PROCESS_INFORMATION *process=(SYSTEM_PROCESS_INFORMATION *)(threads->query_buffer+offset);
        size_t remaining=threads->query_length-offset;
        size_t span=process->NextEntryOffset ? process->NextEntryOffset : remaining;
        if (span>remaining || span<sizeof(*process) || (process->NextEntryOffset && (span&7)) ||
            process->NumberOfThreads>(span-sizeof(*process))/sizeof(SYSTEM_THREAD_INFORMATION))
            return ERROR_INVALID_DATA;
        if ((uintptr_t)process->UniqueProcessId==threads->process_id) {
            if (found_process++) return ERROR_INVALID_DATA;
            if (process->NumberOfThreads>MAX_FROZEN_THREADS+1) return ERROR_TOO_MANY_TCBS;
            SYSTEM_THREAD_INFORMATION *entries=(SYSTEM_THREAD_INFORMATION *)(process+1);
            for (ULONG index=0;index<process->NumberOfThreads;++index) {
                SYSTEM_THREAD_INFORMATION *entry=&entries[index];
                uintptr_t tid_value=(uintptr_t)entry->ClientId.UniqueThread;
                if ((uintptr_t)entry->ClientId.UniqueProcess!=threads->process_id ||
                    !tid_value || tid_value>MAXDWORD) return ERROR_INVALID_DATA;
                DWORD tid=(DWORD)tid_value;
                for (ULONG previous=0;previous<index;++previous)
                    if ((uintptr_t)entries[previous].ClientId.UniqueThread==tid_value) return ERROR_INVALID_DATA;
                if (tid==threads->caller_id) { if (found_caller++) return ERROR_INVALID_DATA; continue; }
                ULONGLONG created=(ULONGLONG)entry->Reserved1[2].QuadPart;
                if (freeze_complete) {
                    unsigned matched=0;
                    for (size_t i=0;i<threads->count;++i) {
                        const PinnedThread *pinned=&threads->threads[i];
                        if (pinned->id==tid && pinned->creation_time==created && pinned->suspended) {
                            matched=1; break;
                        }
                    }
                    if (!matched) return ERROR_BUSY;
                } else {
                    if (threads->count==MAX_FROZEN_THREADS) return ERROR_TOO_MANY_TCBS;
                    for (size_t i=0;i<threads->count;++i)
                        if (threads->threads[i].id==tid) return ERROR_INVALID_DATA;
                    HANDLE handle=TEST_API(open_thread,OpenThread)(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|
                        THREAD_QUERY_INFORMATION|SYNCHRONIZE,FALSE,tid);
                    if (!handle) { DWORD failure=api_error(); return failure==ERROR_INVALID_PARAMETER ? ERROR_BUSY : failure; }
                    DWORD owner=TEST_API(process_id_of_thread,GetProcessIdOfThread)(handle);
                    DWORD actual_id=TEST_API(thread_id,GetThreadId)(handle);
                    FILETIME created_file={0}, exited_file={0}, kernel_file={0}, user_file={0};
                    BOOL times=TEST_API(get_thread_times,GetThreadTimes)(handle,&created_file,&exited_file,&kernel_file,&user_file);
                    if (!times) { DWORD failure=api_error(); CloseHandle(handle); return failure; }
                    ULARGE_INTEGER actual_created;
                    actual_created.LowPart=created_file.dwLowDateTime;
                    actual_created.HighPart=created_file.dwHighDateTime;
                    if (owner!=threads->process_id || actual_id!=tid || actual_created.QuadPart!=created) {
                        CloseHandle(handle); return ERROR_BUSY;
                    }
                    if (thread_exited(handle)) { CloseHandle(handle); continue; }
                    PinnedThread *pinned=&threads->threads[threads->count++];
                    pinned->handle=handle; pinned->id=tid; pinned->creation_time=created;
                }
            }
        }
        if (!process->NextEntryOffset) break;
        offset+=span;
    }
    return found_process==1 && found_caller==1 ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

static DWORD prepare_threads(FreezeSet *threads)
{
    threads->process_id=GetCurrentProcessId(); threads->caller_id=GetCurrentThreadId();
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return ERROR_NOT_SUPPORTED;
    threads->query=(QuerySystemInformation)(uintptr_t)GetProcAddress(ntdll,"NtQuerySystemInformation");
#ifdef STABILITY_GUARD_TEST
    if (stability_test_hooks.query) threads->query=stability_test_hooks.query;
#endif
    if (!threads->query) return ERROR_NOT_SUPPORTED;
    threads->query_buffer=VirtualAlloc(NULL,THREAD_QUERY_BUFFER_SIZE,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!threads->query_buffer) return ERROR_NOT_ENOUGH_MEMORY;
    /* Touch the complete reservation before freezing any process thread. */
    memset(threads->query_buffer,0,THREAD_QUERY_BUFFER_SIZE);
    DWORD result=query_threads(threads);
    return result ? result : inspect_threads(threads,0);
}

static void poison_patch(void)
{
    InterlockedExchange(&patch_poisoned,1);
    InterlockedExchange(&lifecycle,-2);
}

/* No heap/loader/Toolhelp calls or logging after the first suspension. */
static DWORD patch_transaction(const unsigned char expected[5],const unsigned char replacement[5])
{
    if (InterlockedCompareExchange(&patch_poisoned,0,0)) return ERROR_INVALID_STATE;
    patch_last_written=0; patch_last_thaw_error=0;
    FreezeSet *threads=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*threads));
    if (!threads) return ERROR_NOT_ENOUGH_MEMORY;
    DWORD result=prepare_threads(threads), old_protection=0, ignored;
    if (result) goto done;
    for (size_t i=0;i<threads->count;++i) {
        PinnedThread *thread=&threads->threads[i];
        if (thread_exited(thread->handle)) continue;
        DWORD prior=TEST_API(suspend_thread,SuspendThread)(thread->handle);
        if (prior==(DWORD)-1) {
            if (thread_exited(thread->handle)) continue;
            result=api_error(); goto done;
        }
        thread->prior_suspend_count=prior; thread->suspended=1;
        CONTEXT context={0}; context.ContextFlags=CONTEXT_CONTROL;
        if (!TEST_API(get_thread_context,GetThreadContext)(thread->handle,&context)) { result=api_error(); goto done; }
        if (context.Rip >= (DWORD64)(uintptr_t)call_site && context.Rip < (DWORD64)(uintptr_t)(call_site+5)) {
            result=ERROR_BUSY; goto done;
        }
    }
    result=query_threads(threads);
    if (!result) result=inspect_threads(threads,1);
    if (result) goto done;
    if (memcmp(call_site,expected,5)) { result=ERROR_REVISION_MISMATCH; goto done; }
    if (!TEST_API(protect,VirtualProtect)(call_site,5,PAGE_EXECUTE_READWRITE,&old_protection)) { result=api_error(); goto done; }
    memcpy(call_site,replacement,5); patch_last_written=1;
    if (!TEST_API(flush,FlushInstructionCache)(GetCurrentProcess(),call_site,5)) {
        result=api_error(); memcpy(call_site,expected,5);
        if (!TEST_API(flush,FlushInstructionCache)(GetCurrentProcess(),call_site,5)) poison_patch();
    }
    if (!TEST_API(protect,VirtualProtect)(call_site,5,old_protection,&ignored)) {
        result=api_error(); poison_patch();
        memcpy(call_site,expected,5);
        TEST_API(flush,FlushInstructionCache)(GetCurrentProcess(),call_site,5);
        TEST_API(protect,VirtualProtect)(call_site,5,old_protection,&ignored);
    }
done:
    patch_last_thaw_error=thaw(threads);
    if (patch_last_thaw_error) { result=patch_last_thaw_error; poison_patch(); }
    unsigned still_frozen=0;
    for (size_t i=0;i<threads->count;++i) still_frozen|=threads->threads[i].suspended;
    if (still_frozen) { failed_freeze=threads; InterlockedExchange(&frozen_failure,1); return result; }
    if (threads->query_buffer) VirtualFree(threads->query_buffer,0,MEM_RELEASE);
    HeapFree(GetProcessHeap(),0,threads);
    return result;
}

DWORD StabilityGuardStart(HMODULE module, StabilityGuardLogger logger)
{
    if (!module) return ERROR_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&lifecycle,1,0)!=0) return ERROR_ALREADY_INITIALIZED;
    stability_logger = logger;
    DWORD result=verify_hash();
    if (!result) result=verify_targets();
    if (!result) result=prepare_relay();
    if (!result) {
        for (unsigned attempt=0;attempt<8;++attempt) {
            result=patch_transaction(hoi4_call_bytes,installed_bytes);
            if (result!=ERROR_BUSY || patch_last_written ||
                InterlockedCompareExchange(&patch_poisoned,0,0) || !StabilityGuardSafeToLog()) break;
            if (attempt<7) Sleep(20);
        }
    }
    if (result) {
        if (StabilityGuardSafeToLog()) {
            char message[160];
            snprintf(message,sizeof(message),"STABILITY_GUARD_INSTALL_FAILED status=%lu poisoned=%ld",
                (unsigned long)result,(long)InterlockedCompareExchange(&patch_poisoned,0,0));
            log_line(message);
        }
        if (!InterlockedCompareExchange(&patch_poisoned,0,0)) InterlockedExchange(&lifecycle,-1);
        return result;
    }
    InterlockedExchange(&lifecycle,2);
    log_line("Installed: HOI4 1.19.3.0 career-profile co-op serialization at RVA 0x1d6001. Army modifier teardown is not patched.");
    return ERROR_SUCCESS;
}

DWORD StabilityGuardGetStats(StabilityGuardStats *destination)
{
    if (!destination) return ERROR_INVALID_PARAMETER;
    StabilityGuardStats stats={sizeof(StabilityGuardStats),1,StabilityGuardInstalled(),0,0,0,0,0};
    stats.calls=InterlockedCompareExchange64(&calls,0,0);
    stats.serialized_days=InterlockedCompareExchange64(&guarded_days,0,0);
    stats.duplicate_entries_detected=InterlockedCompareExchange64(&skipped_entries,0,0);
    stats.rejected_inputs=InterlockedCompareExchange64(&rejected_inputs,0,0);
    memcpy(destination,&stats,sizeof(stats));
    return ERROR_SUCCESS;
}

DWORD StabilityGuardVerify(void)
{
    LONG state=InterlockedCompareExchange(&lifecycle,0,0);
    if (state!=2 && state!=4) return ERROR_INVALID_STATE;
    if (memcmp(call_site,state==2?installed_bytes:hoi4_call_bytes,5)) return ERROR_REVISION_MISMATCH;
    MEMORY_BASIC_INFORMATION memory;
    if (VirtualQuery(call_site,&memory,sizeof(memory))!=sizeof(memory) || memory.Protect!=call_protection)
        return ERROR_INVALID_ACCESS;
    if (VirtualQuery(relay,&memory,sizeof(memory))!=sizeof(memory) || memory.Protect!=PAGE_EXECUTE_READ)
        return ERROR_INVALID_ACCESS;
    return ERROR_SUCCESS;
}

#ifdef STABILITY_GUARD_DIAGNOSTICS
/* Startup verification only: native range callback on inert, non-country tags. */
DWORD StabilityGuardExercise(void)
{
    if (InterlockedCompareExchange(&lifecycle,0,0)!=2) return ERROR_INVALID_STATE;
    unsigned char *state=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,
                                  HOI4_COUNTRY_ARRAY_OFFSET+sizeof(CareerArray));
    if (!state) return ERROR_NOT_ENOUGH_MEMORY;
    int32_t inert_tags[4]={0,0,-1,-1};
    CareerArray source={inert_tags,4,4,NULL};
    memcpy(state+HOI4_COUNTRY_ARRAY_OFFSET,&source,sizeof(source));
    LONG64 old_calls=InterlockedCompareExchange64(&calls,0,0);
    LONG64 old_days=InterlockedCompareExchange64(&guarded_days,0,0);
    LONG64 old_duplicates=InterlockedCompareExchange64(&skipped_entries,0,0);
    career_wrapper(state);
    DWORD result=ERROR_SUCCESS;
    if (memcmp(state+HOI4_COUNTRY_ARRAY_OFFSET,&source,sizeof(source)) ||
        memcmp(inert_tags,(int32_t[]){0,0,-1,-1},sizeof(inert_tags)) ||
        InterlockedCompareExchange64(&calls,0,0)!=old_calls+1 ||
        InterlockedCompareExchange64(&guarded_days,0,0)!=old_days+1 ||
        InterlockedCompareExchange64(&skipped_entries,0,0)!=old_duplicates+2) result=ERROR_INVALID_DATA;
    HeapFree(GetProcessHeap(),0,state);
    return result;
}

DWORD StabilityGuardUninstall(void)
{
    if (InterlockedCompareExchange(&lifecycle,3,2)!=2) return ERROR_INVALID_STATE;
    DWORD result=patch_transaction(installed_bytes,hoi4_call_bytes);
    if (!InterlockedCompareExchange(&patch_poisoned,0,0)) InterlockedExchange(&lifecycle,result?2:4);
    if (!result) log_line("Original CALL restored. DLL and relay remain resident until process exit.");
    return result;
}

#endif

int StabilityGuardInstalled(void)
{
    return InterlockedCompareExchange(&lifecycle,0,0) == 2;
}

int StabilityGuardSafeToLog(void)
{
    return !InterlockedCompareExchange(&frozen_failure,0,0);
}

#ifdef STABILITY_GUARD_TEST
/* Disposable fixture recovery only; poison stays set after all threads thaw. */
DWORD StabilityGuardTestRecoverFrozen(void)
{
    FreezeSet *threads=failed_freeze;
    if (!threads) return ERROR_INVALID_STATE;
    DWORD result=thaw(threads);
    for (size_t i=0;i<threads->count;++i)
        if (threads->threads[i].suspended) return result ? result : ERROR_BUSY;
    failed_freeze=NULL;
    InterlockedExchange(&frozen_failure,0);
    if (threads->query_buffer) VirtualFree(threads->query_buffer,0,MEM_RELEASE);
    HeapFree(GetProcessHeap(),0,threads);
    return result;
}
#endif
