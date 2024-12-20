## Introduction to Hypervisor Implants
Hypervisors are pieces of software used to manage VMs (Virtual Machines) or Guest machines on a Host machine.
The main difference between a hypervisor and an emulator is that the former allows the guest machine to execute *most* instructions on the hardware of the host machine by translating the guest's instructions into the native machine code of the host - this provides superior performance compared to emulators, especially when it comes to tasks that are computationally intensive.

There are two main types of hypervisors:
- **Bare-Metal**: the software is installed directly on the host hardware, bypassing the host's operating system (VMWare ESXi, KVM, MS Hyper-V, ...)
So the execution order is: UEFI / BIOS → Hypervisor → OS executed by the Hypervisor
- **Hosted**: the hypervisor runs as an application on top of a host OS (VirtualBox, VMware Workstation, ...)
In this case, the execution order is: UEFI / BIOS → Host OS → Hypervisor loaded by the Host OS → Guest OS

As I lately started getting into kernel development, I ran into some posts talking about how it's possible to develop **hypervisor implants** - what intrigues me the most is the fact that if an attacker were to establish kernel-level access on a Windows machine with something like a kernel driver, other drivers could abuse the fact that kernel memory is shared to examine the vulnerable driver or rootkit used by the attacker. However, when it comes to Hypervisors, once the software itself is loaded into memory and it starts using the virtualization extensions for the CPU it's built for, it's virtually possible to hide any memory related to the Hypervisor from the Host OS.

This "feature" is, of course, used legitimately by solutions like [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/): a security feature introduced by Microsoft to protect user credentials from theft or compromise - the products works in conjunction with hypervisors to create a secure, isolated environment for storing and processing sensitive authentication data. This is an example of VBS (Virtualization-based security).
CG (Credential Guard) leverages hardware-based security features to isolate sensitive data such as "NTLM hashes, TGTs and other kinds of credentials stored applications as domain credentials".

If you want to look at how hypervisor code might look like, I highly suggest looking at [SimpleVisor](https://github.com/ionescu007/SimpleVisor/tree/master), its [entrypoint](https://github.com/ionescu007/SimpleVisor/blob/master/shv.c) and the [wiki](https://ionescu007.github.io/SimpleVisor/).

Some examples of the before-mentioned articles are:
- [New Malware Families Found Targeting VMware ESXi Hypervisors](https://thehackernews.com/2022/09/new-malware-families-found-targeting.html)
- [Ransomware operators exploit ESXi hypervisor vulnerability for mass encryption](https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/)
- [Protect Your Organization from MosaicRegressor and Other UEFI Implants](https://eclypsium.com/blog/protecting-your-organization-from-mosaicregressor-and-other-uefi-implants/)

---

The first thing someone might notice is that installing an additional (and malicious) hypervisor on a guest OS that is already running on an underlying hypervisor might now work as hardware only supports having one hypervisor active. This setup will still be possible as the first hypervisor will extend the support by "emulating" the hardware's functionality.
This means that the first hypervisor has to be able to forward hardware instructions from the CPU to the malicious hypervisor, effectively acting as a middle-man.

With that out of the way we can start implementing a basic driver for Windows: to do that you'll have to set up your VM by [installing WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) and enabling 
Then you'll have to enable Test Signing mode and reboot the machine
```
bcdedit /debug on
bcdedit /set testsigning on
```

### Setting up a simple driver
In order to see the debug messages from the driver you will also need to open `regedit`, navigate to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` and create a new Key called **Debug Print Filter**. Within that, add a new `DWORD` Value and give it the name `DEFAULT` and a value of `8`.

> [!info]
> You might also need to disable MS Defender and anti-tampering mode.

Now you can open Visual Studio and create a new `Kernel Mode Driver, Empty (KMDF)` and add the following boilerplate code (the `macros.h` file contains some macros for debug printing and can be found [here](https://github.com/otterpwn/blister/blob/main/macros.h))
```c
#include <ntddk.h>

#include "macros.h"

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	SUCCESS("Driver successfully unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	SUCCESS("Driver successfully loaded\n");
	return STATUS_SUCCESS;
}
```

This simply defines the `DriverEntry` / `DriverUnload` functions, which are responsible for loading and unloading the driver from memory, and printing some debugging messages in the process.
Now we can create the service for the driver, start it and stop it at will and we'll be able to see it load & unload from memory with a tool like [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview).
```
sc create hypervisor binPath= C:\Users\otter\Desktop\projects\hypervisor\x64\Debug\hypervisor.sys type= kernel

sc start hypervisor
sc stop hypervisor
```

![](https://i.imgur.com/GdJ0HLk.png)

### Interacting with the CPU
Since we'll need to talk to the hardware components directly, the code we write will be brand-specific as CPUs of different brands (Intel, AMD, ...) have different register structures and instruction sets.
In this case, I'm working with an Intel processor so I will be using the [official `Intel 64 and IA-32 Architectures Software Developer’s Manual`](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

Before the driver loads into memory, we will need to perform some checks to enumerate the state of Intel's Virtualization Technology, or Intel-VTx, component.
VTx is a fundamental component for any hypervisor as it allows the software to use CPU extensions for virtualization purposes so we need to check for whether the feature is enabled on the CPU.
In our case, we'll focus on VMX, the Virtual Machine Monitor Extension: a specific implementation of VT-x that provides the tools and mechanisms for hypervisors to create and manage virtual machines.

Part of these properties can be also enumerated with commands like `systeminfo`, but if you run it on a VM you'll only get a message along the lines of
```
systeminfo

...

Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Looking at page `3925` of the manual we'll find the `Discovering Support for VMX`
> Before system software enters into VMX operation, it must discover the presence of VMX support in the processor.
> System software can determine whether a processor supports VMX operation using CPUID. 
> If `CPUID.1:ECX.VMX[bit 5] = 1`, then VMX operation is supported.

So it's possible for us to enumerate the VMX state by issuing a `CPUID` instruction to the CPU and checking the 5th bit of the result found in the `ECX` register, if the bit is `1` then VMX is enabled, otherwise the feature is disabled.

*What does the `CPUID` instruction do?* Heading to page `803` we find the `CPUID - CPU Identification` section where the `CPUID` instruction is described as 
> Returns processor identification and feature information to the `EAX`, `EBX`, `ECX`, and `EDX` registers, as determined by input entered in `EAX` (in some cases, `ECX` as well).

and looking at the implementation of the instruction we see that if `EAX` contains `0x1` when the instruction is called, `ECX` will contain the VMX-related information at bit 5, just like the first paragraph mentioned (shocker, I know).

![](https://i.imgur.com/gZTHVOo.png)

### Setting up the driver for virtualization
Now we can implement this instruction in our driver, call it, and check the 5th bit of the `ECX` register is set to `1`.
The following is the complete code with the instruction implementation and the check for VMX.
```c
#include <ntddk.h>
#include <intrin.h>

#include "macros.h"

/*
this function is a helper for the CPUID instruction using the __cpuid intrinsic function

@note originally, the return registers are stored in a 4-element array, but we are only 
interested in the EBX, ECX, and EDX registers so we'll use pointers to store the values

@param UINT32 eax: the value to be passed to the EAX register
@param UINT32* ebx: the value to be returned by the CPUID instruction in the EBX register
@param UINT32* ecx: the value to be returned by the CPUID instruction in the ECX register
@param UINT32* edx: the value to be returned by the CPUID instruction in the EDX register

@reference https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170
*/
void cpuid(UINT32 eax, UINT32* ebx, UINT32* ecx, UINT32* edx) {
	int cpuInfo[4];
	__cpuid(cpuInfo, eax);
	*ebx = cpuInfo[1];
	*ecx = cpuInfo[2];
	*edx = cpuInfo[3];
}

/*
this function checks if the fifth bit of the ECX register is 1
to enumerate whether VMX is supported by the CPU

@param UINT32 eax: the value to be passed to the EAX register

@return BOOLEAN: TRUE if the fifth bit of the ECX register is 1, FALSE otherwise
*/
BOOLEAN checkFifthBit(UINT32 eax) {
	UINT32 ebx, ecx, edx;
	cpuid(eax, &ebx, &ecx, &edx);
	return (ecx & 0x20) != 0;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	SUCCESS("Driver successfully unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	SUCCESS("Driver successfully loaded\n");

	// verify whether the CPU supports VMX
	// by checking the fifth bit of the ECX register
	// after the CPUID instruction is executed with EAX = 0x1
	if (checkFifthBit(0x1)) {
		SUCCESS("VMX is supported by the target CPU\n");
	}
	else {
		ERROR("VMX is not supported by the target CPU\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	return STATUS_SUCCESS;
}
```

Mind the `@note` line in the comment for the `cpuid` wrapper function: for most, if not all, of the functionalities we will implement there is a more "official" way of handling things by declaring a type for each register and describing its structure and the purpose of each bit like so
```c
typedef union _IA32_FEATURE_CONTROL_MSR {
    ULONG64 All;
    struct {
        ULONG64 Lock : 1;
        ULONG64 EnableSMX : 1;
        ULONG64 EnableVmxon : 1; 
        ULONG64 Reserved2 : 5;
        ULONG64 EnableLocalSENTER : 7; 
        ULONG64 EnableGlobalSENTER : 1;
        ULONG64 Reserved3a : 16;
        ULONG64 Reserved3b : 32;
    } Fields;
} IA32_FEATURE_CONTROL_MSR, *PIA32_FEATURE_CONTROL_MSR;

typedef struct _CPUID {
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, *PCPUID;
```

So if you're following along you might want to look into implementing these types and structures.

![](https://i.imgur.com/LD1UrDG.png)

As you can see from the debug prints and the code, I made it so the driver won't load properly if VMX is not supported as it would make no sense going through with the driver entry function when the CPU we're targeting cannot be exploited.

> [!info]
> In this case, my VM didn't have virtualization enabled so the check "fails successfully".
> 
> I'm using VirtualBox so to enable it go to Settings > System > Enable Nested VT-x/AMD-V.
> If the option is grayed-out, turn off the VM and execute `VBoxManage modifyvm <vm_name> --nested-hw-virt on`; this should select the box and allow for nested virtualization.

Another basic check we could run consists in running `CPUID` with `EAX` set to `0x0`, this allows us to verify whether the CPU we're attacking is an Intel CPU; if it is the values in the `EBX`, `EDX` and `ECX` registers (in that order) should spell the string `GenuineIntel` if decoded from hex and read in LE format, this is known as the "manufacturer string".

This is the code to implement it
```c
/*
check whether we're working with an intel CPU by calling the CPUID instruction with EAX = 0x0
and checking the EBX, ECX, and EDX registers for the manufacturer string

@return BOOLEAN: TRUE if the CPU is an Intel CPU, FALSE otherwise
*/
BOOLEAN isIntelCPU() {
	UINT32 ebx, ecx, edx;
	cpuid(0x0, &ebx, &ecx, &edx);
	return ebx == 'uneG' && edx == 'Ieni' && ecx == 'letn';
}
```
So we can add a simple if / else check in the `DriverEntry` function just like we did with the VMX check and we should get something along these lines

![](https://i.imgur.com/03jjXfm.png)

Now we are sure that we are working on an Intel CPU and VMX is supported so we are free to start setting up the structure for VM control: as the manual states, the hypervisor can enter VMX operation only by setting the 13th bit of the `CR4` register to 1 (` CR4.VMXE[bit 13] = 1`), after this is set the system enters VMX operation by executing the `VMXON` instruction.

> `VMXON` is also controlled by the `IA32_FEATURE_CONTROL MSR` (`MSR` address `3AH`). This `MSR` is cleared to zero when a logical processor is reset. The relevant bits of the `MSR` are:
> - **Bit 0** is the lock bit. If this bit is clear, `VMXON` causes a general-protection exception. If the lock bit is set, `WRMSR` to this `MSR` causes a general-protection exception; the `MSR` cannot be modified until a power-up reset condition. System BIOS can use this bit to provide a setup option for BIOS to disable support for `VMX`. To enable `VMX` support in a platform, BIOS must set bit 1, bit 2, or both (see below), as well as the lock bit.
> - **Bit 1** enables `VMXON` in `SMX` operation. If this bit is clear, execution of `VMXON` in `SMX` operation causes a general-protection exception. Attempts to set this bit on logical processors that do not support both `VMX` operation and `SMX` operation cause general-protection exceptions.
> - **Bit 2** enables `VMXON` outside `SMX` operation. If this bit is clear, execution of `VMXON` outside `SMX` operation causes a general-protection exception. Attempts to set this bit on logical processors that do not support `VMX` operation cause general-protection exceptions

Since it's not the BIOS setting bits in the register, we'll have to set the lock bit and then bit 1, bit 2, or both.
In this specific case we'll be operating outside `SMX` so we only need to set the lock bit and bit 1.

So to move on we'll need some functions to read and write values from MSR register, thankfully we can use the intrinsic functions to write a quick (and somewhat useless) wrapper
```c
/*
read the value from a MSR register

@param UINT32 msr: the MSR register to be read

@return UINT64: the value stored in the MSR register

@reference https://learn.microsoft.com/en-us/cpp/intrinsics/readmsr?view=msvc-170
*/
UINT64 readMSR(UINT32 msr) {
	return __readmsr(msr);
}

/*
write a value to a MSR register

@param UINT32 msr: the MSR register to be written to
@param UINT64 value: the value to be written to the MSR register

@reference https://learn.microsoft.com/en-us/cpp/intrinsics/writemsr?view=msvc-170
*/
void writeMSR(UINT32 msr, UINT64 value) {
	__writemsr(msr, value);
}
```

Now that we have the helper functions we can run the checks we need
```c
#define IA32_FEATURE_CONTROL 0x3A

...

/*
check if the lock bit is set in the IA32_FEATURE_CONTROL MSR register

@return BOOLEAN: TRUE if the lock bit is set, FALSE otherwise
*/
BOOLEAN isLockBitSet() {
	UINT64 featureControl = readMSR(IA32_FEATURE_CONTROL);
	return (featureControl & 0x1) != 0;
}

/*
check if the VMXON outside SMX bit is set in the IA32_FEATURE_CONTROL MSR register

@return BOOLEAN: TRUE if the VMXON outside SMX bit is set, FALSE otherwise
*/
BOOLEAN isVmxonEnabledOutsideSMX() {
	UINT64 featureControl = readMSR(IA32_FEATURE_CONTROL);
	return (featureControl & 0x4) != 0;
}
```

![](https://i.imgur.com/pTFc70d.png)

Another step we need to take to prepare for the `VMXON` instruction is allocating what's known as a **VMXON Region**: a 4k-byte aligned memory area used by the CPU to support the VMX operation.
> Before executing VMXON, software allocates a region of memory (called the VMXON region)1 that the logical
> processor uses to support VMX operation. The physical address of this region (the VMXON pointer) is provided in an operand to VMXON. The VMXON pointer is subject to the limitations that apply to VMCS pointers:
> - The VMXON pointer must be 4-KByte aligned (bits 11:0 must be zero).
> - The VMXON pointer must not set any bits beyond the processor’s physical-address width.
> 
> Before executing VMXON, software should write the VMCS revision identifier to the VMXON
> region. (Specifically, it should write the 31-bit VMCS revision identifier to bits 30:0 of the first 4 bytes of the VMXON region; bit 31 should be cleared to 0.) It need not initialize the VMXON region in any other way. Software should use a separate region for each logical processor and should not access or modify the VMXON region of a logical processor between execution of VMXON and VMXOFF on that logical processor. Doing otherwise may lead to unpredictable behavior

This process seems incredibly tedious to do in C, thankfully we can use some of the intrinsic functions the Windows API provides for the `VMXON` instruction (using [`__vmx_on()`](https://learn.microsoft.com/en-us/cpp/intrinsics/vmxon?view=msvc-170)).

The VMXON region should be zeroed prior to executing `VXMON`, and the VMCS revision identifier written into the VMXON region at the appropriate offset.

| Byte Offset | Contents                             |
| ----------- | ------------------------------------ |
| 0           | Buts `31:0` VMCS revision identifier |
| 4           | VMXON data                           |

| Byte Offset | Contents                             |
| ----------- | ------------------------------------ |
| 0           | Bits `30:0` VMCS revision identifier |
| 4           | VMX-abort indicator                  |
| 8           | VMCS data                            | 

For simplicity's sake, we’ll only be allocating a single `VMXON` region, and the respective `VMCS` region, for only one CPU core. In order to keep track of where the regions are I made a simple structure that represents the state of an individual Virtual Machine by storing the pointers for both the VMXON and VMCS regions.
```c
typedef struct VM_STATE {
	UINT64 vmxonRegion;
	UINT64 vmcsRegion;
} VM_STATE, *PVM_STATE;

// global value for the VM state
VM_STATE guestVmState;
```

This is the `allocateVmxonRegion` function I made to allocate the VMXON region as a continuous 4k-byte aligned memory region.
```c
#define IA32_FEATURE_CONTROL 0x3A
#define IA32_VMX_BASIC 0x480

#define VMXON_REGION_SIZE 0x1000
#define VMCS_REGION_SIZE 0x1000
#define ALIGNMENT 0x1000

typedef struct VM_STATE {
	UINT64 vmxonRegion;
	UINT64 vmcsRegion;
} VM_STATE, *PVM_STATE;

typedef union _IA32_VMX_BASIC_MSR {
	ULONG64 All;
	struct
	{
		ULONG32 RevisionIdentifier : 31;
		ULONG32 Reserved1 : 1;
		ULONG32 RegionSize : 12;
		ULONG32 RegionClear : 1;
		ULONG32 Reserved2 : 3;
		ULONG32 SupportedIA64 : 1;
		ULONG32 SupportedDualMoniter : 1;
		ULONG32 MemoryType : 4;
		ULONG32 VmExitReport : 1;
		ULONG32 VmxCapabilityHint : 1;
		ULONG32 Reserved3 : 8;
	} Fields;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;

...

/*
returns the physical address of a virtual address
 
@param UINT64 virtualAddress: the virtual address to be converted to a physical address

@return UINT64: the physical address of the virtual address

@reference https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmgetphysicaladdress
*/
UINT64 getPhysicalAddress(UINT64 virtualAddress) {
	PHYSICAL_ADDRESS physicalAddress = MmGetPhysicalAddress((PVOID)virtualAddress);
	return physicalAddress.QuadPart;
}

/*
allocate and load the VMXON region using the __vmx_on intrinsic function

@param VM_STATE* guestVmState: the VM state of the guest

@return BOOLEAN: TRUE if the VMXON region is successfully allocated, FALSE otherwise
*/
BOOLEAN allocateVmxonRegion(IN VM_STATE* vmState) {
	// if the current IRQL is greater than DISPATCH_LEVEL, raise it to DISPATCH_LEVEL
	// to avoid any potential issues with the memory allocation
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel();
	}

	PHYSICAL_ADDRESS maxPhysicalAddress = { 0 };
	maxPhysicalAddress.QuadPart = MAXULONG64;

	// use mmallocatecontiguousmemory to allocate a contiguous region of memory
	// for the VMXON instruction making sure that the memory is aligned to a 4KB boundary
	int sizeOfVmxonRegion = 2 * VMXON_REGION_SIZE;
	PVOID vmxRegionBuffer = MmAllocateContiguousMemory(sizeOfVmxonRegion + ALIGNMENT, maxPhysicalAddress);

	PHYSICAL_ADDRESS highestAddress = { 0 };
	highestAddress.QuadPart = ~0;

	if (vmxRegionBuffer == NULL) {
		ERROR("Failed to allocate the VMXON region\n");
		return FALSE;
	}

	UINT64 physicalAddress = getPhysicalAddress((UINT64)vmxRegionBuffer);

	// check if the VMXON region is successfully allocated
	if (physicalAddress == 0) {
		ERROR("Failed to get the physical address of the VMXON region\n");
		return FALSE;
	}

	// zero out the allocated region
	RtlSecureZeroMemory(vmxRegionBuffer, sizeOfVmxonRegion + ALIGNMENT);

	// align the VMXON region to a 4KB boundary
	UINT64 alignedPhysicalBuffer = (UINT64)((ULONG_PTR)(physicalAddress + ALIGNMENT - 1) & ~(ALIGNMENT - 1));
    UINT64 alignedVirtualBuffer = (UINT64)((ULONG_PTR)((PUCHAR)vmxRegionBuffer + ALIGNMENT - 1) & ~(ALIGNMENT - 1));

	INFO("Allocated VMXON region with an aligned virtual buffer from %llx\n", alignedVirtualBuffer);

	// get the IA32_VMX_BASIC MSR register value
	IA32_VMX_BASIC_MSR vmxBasicMsr;
	vmxBasicMsr.All = readMSR(IA32_VMX_BASIC);

	// change the revision identifier
	*(UINT64*)alignedVirtualBuffer = vmxBasicMsr.Fields.RevisionIdentifier;

	// load the VMXON region using the __vmx_on intrinsic function
	int returnValue = __vmx_on(&alignedPhysicalBuffer);

	if (returnValue) {
		ERROR("Failed to load the VMXON region\n");
		return FALSE;
	}

	// update the VM state with the VMXON region
	vmState->vmxonRegion = alignedPhysicalBuffer;

	return TRUE;
}
```
I used [`MmAllocateContiguousMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmallocatecontiguousmemory) to allocate the contiguous and non-paged physical memory for the region for two main reasons:
1. We don't have to pick a cache type for the allocated memory
2. The starting address of the allocated buffer is aligned by default to a memory page boundary

After we call `MmAllocateContiguousMemory`, the VMXON region is completely uninitialized so we have to zero it using a macro like [`RtlSecureZeroMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsecurezeromemory).

The next part of the function addresses the revision identifier
> Before executing VMXON, software should write the VMCS revision identifier to the VMXON region.

by reading the identifier from the `IA32_VMX_BASIC_MSR` register and writing it into the VMXON region; now we're ready to use the `__vmx_on` and checking its result: if it's `0`, the operation succeeded and we can update the `vmxonRegion` pointer in the `VM_STATE` structure we defined earlier.

The last thing we will do in this post is allocating and initializing the VMCS region to complete the `VM_STATE` setup; the responsible code will be pretty much the same as the requirements are shared between the two memory regions, the only difference is that we'll be replacing the `__vmx_on()` function with the [`__vmx_vmptrld()`](https://learn.microsoft.com/en-us/cpp/intrinsics/vmx-vmptrld?view=msvc-170) intrinsic function which "Loads the pointer to the current virtual-machine control structure (VMCS) from the specified address".
```c
/*
allocate and load the VMCS region using the __vmx_vmclear intrinsic function

@param VM_STATE* guestVmState: the VM state of the guest

@return BOOLEAN: TRUE if the VMCS region is successfully allocated, FALSE otherwise

@reference https://learn.microsoft.com/en-us/cpp/intrinsics/vmx-vmptrld?view=msvc-170
*/
BOOLEAN allocateVmcsRegion(IN VM_STATE* vmState) {
	// if the current IRQL is greater than DISPATCH_LEVEL, raise it to DISPATCH_LEVEL
	// to avoid any potential issues with the memory allocation
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel();
	}

	PHYSICAL_ADDRESS maxPhysicalAddress = { 0 };
	maxPhysicalAddress.QuadPart = MAXULONG64;

	// use mmallocatecontiguousmemory to allocate a contiguous region of memory
	// for the VMCS instruction making sure that the memory is aligned to a 4KB boundary
	int sizeOfVmcsRegion = 2 * VMCS_REGION_SIZE;
	PVOID vmcsRegionBuffer = MmAllocateContiguousMemory(sizeOfVmcsRegion + ALIGNMENT, maxPhysicalAddress);

	PHYSICAL_ADDRESS highestAddress = { 0 };
	highestAddress.QuadPart = ~0;

	if (vmcsRegionBuffer == NULL) {
		ERROR("Failed to allocate the VMCS region\n");
		return FALSE;
	}

	UINT64 physicalAddress = getPhysicalAddress((UINT64)vmcsRegionBuffer);

	// check if the VMCS region is successfully allocated
	if (physicalAddress == 0) {
		ERROR("Failed to get the physical address of the VMCS region\n");
		return FALSE;
	}

	// zero out the allocated region
	RtlSecureZeroMemory(vmcsRegionBuffer, sizeOfVmcsRegion + ALIGNMENT);

	// align the VMCS region to a 4KB boundary
	UINT64 alignedPhysicalBuffer = (UINT64)((ULONG_PTR)(physicalAddress + ALIGNMENT - 1) & ~(ALIGNMENT - 1));
	UINT64 alignedVirtualBuffer = (UINT64)((ULONG_PTR)((PUCHAR)vmcsRegionBuffer + ALIGNMENT - 1) & ~(ALIGNMENT - 1));

	INFO("Allocated VMCS region with an aligned virtual buffer from %llx\n", alignedVirtualBuffer);

	// get the IA32_VMX_BASIC MSR register value
	IA32_VMX_BASIC_MSR vmcsBasicMsr;
	vmcsBasicMsr.All = readMSR(IA32_VMX_BASIC);

	// change the revision identifier
	*(UINT64*)alignedVirtualBuffer = vmcsBasicMsr.Fields.RevisionIdentifier;

	// load the VMXON region using the __vmx_vmptrld intrinsic function
	int returnValue = __vmx_vmptrld(&alignedPhysicalBuffer);

	if (returnValue) {
		ERROR("Failed to load the VMCS region\n");
		return FALSE;
	}

	// update the VM state with the VMCS region
	vmState->vmcsRegion = alignedPhysicalBuffer;

	return TRUE;
}
```

This is all I'm gonna cover in this post; thanks for sticking around until the end <3

ʕ •ᴥ•ʔ
