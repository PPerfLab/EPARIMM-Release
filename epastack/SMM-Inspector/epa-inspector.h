#include <Library/BaseCryptLib.h>
#include <Base.h>
#include <Library/BaseLib.h>
#include "Library/BaseMemoryLib.h"  
#include <Library/CpuLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/MpService.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmCpuSaveState.h>
#include <Library/SmmMemLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Protocol/SmmSwDispatch.h>
#include <Library/TimerLib.h>


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define MAX_TASKS 	   14  // Max tasks in a bin (4K page / size of task structure) 

// CONFIG, will need to set for your system
#define MAX_MEMORY_MEASUREMENT_LEN_INIT 0x400000
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Other constants
#define NONCE_VAL 	0x37
#define NOT_FOUND 	   0
#define FOUND 		   1

#define OFF 0
#define ON 1

#define MEASURE_LINUX 0x00
#define MEASURE_XEN 0x1

#define SIGN_INTS 5
#define SHA256_INTS 8
#define HMAC_KEY_LEN 20
#define SIGNATURE_SIZE 20
#define SHA256_HASH_SIZE 32
#define HMAC_SIZE 32
#define AES_CIPHER_CTX_SIZE 0x1e8
#define AES_KEYSIZE 256 // bits
#define ENCRYPT_OFFSET 16 // Start encrypting task_t after (Ivec1 and Ivec2) as the Ivecs are plaintext

// The task data structure needs to match the Backend Manager's copy exactly
#pragma pack(1)

typedef struct InspectorConfig_t 
{
	UINT8 HmacCreateEnable;
	UINT8 HmacCheckEnable;
	UINT8 AesEncryptEnable;
	UINT8 AesDecryptEnable;
	UINT8 CheckSmrrOverlapEnable;
	UINT8 InspectorUsecsCostEnable;
	UINT32 MaxMemoryHashSize; 
	UINT32 MaxTasks; 
	UINT32 InspectorSig[SIGN_INTS]; 
	UINT32 ManagerSig[SIGN_INTS]; 
	UINT8 Aes256CbcKey[AES_KEYSIZE/8]; 
	UINT8 HmacKey[HMAC_KEY_LEN]; 
} INSPECTOR_CONFIG;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair0;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair1;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair2;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair3;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair4;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair5;

typedef union  {
	UINT32 SmallStat[2];
	UINT64 BigStat;
}StatPair6;

typedef struct task_t
{
	UINT64 Ivec1; // Plaintext
	UINT64 Ivec2; // Plaintext
	UINT64 Cmd; 
	UINT64 Operand;
	UINT64 VirtAddr;  
	UINT64 PhysAddr;
	UINT64 Len;
	UINT64 Result; 		//(CHANGED, UNCHANGED, INIT, ERROR)
	UINT64 Nonce;
	UINT64 Cost;
	UINT64 Priority;   
	UINT64 LastChecked;
	UINT64 TaskUuid;
	UINT64 Reserved1;
	UINT32 Hash[SHA256_INTS];
	UINT32 ManagerSig[SIGN_INTS];
	UINT32 InspectorSig[SIGN_INTS];
	StatPair0 Stat0;
	StatPair1 Stat1;
	StatPair2 Stat2;
	StatPair3 Stat3;
	StatPair4 Stat4;
	StatPair5 Stat5;
	StatPair6 Stat6;
	UINT8 Hmac[HMAC_SIZE];
} EPA_TASK;

/*
 * For STM
 */

typedef struct {
  UINT64                            Signature;
  UINT16                            Size;
  UINT8                             VmmDescriptorVerMajor;
  UINT8                             VmmDescriptorVerMinor;
  UINT32                            LocalApicId;
  UINT64                            VmmCr0;
  UINT64                            VmmCr3;
  UINT32                            VmmCr4;
  UINT64                            VmmLdtrBase;
  UINT64                            VmmGdtrBase;
  UINT64                            VmmIdtrBase;
  UINT64                            VmmEfer;
  UINT8                             PhysicalAddressBits;
} MLE_VMM_DESCRIPTOR;

typedef struct {
  UINT64   VmDescriptor;
  UINT32   VmIndex;
} STM_GET_EXECUTIVE_MONITOR_CONTEXT_DESCRIPTOR;
#pragma pack()

// Encryption key (Insert your (test) keys here!)
CONST UINT8 Aes256CbcKeyInit[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };


CONST UINT8 Aes256CbcDataInit[] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

CONST UINT8 HmacKeyInit[] = {
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  0x0b, 0x0b, 0x0b, 0x0b};

#pragma pack()

// Inspector Commands
#define CHECK_REG	    0x10
#define HASH_MEM_VIRT   0x13
#define HASH_MEM_PHYS   0x14
#define CHANGE_MEM      0x40
#define CHECK_MSR       0x42
#define CHECK_IDTR_IDT  0x43

// SMI Triggers
#define EPA_SMI_CMD     0x88
#define INSPECTOR_CONF  0x89

// Operands
#define IDT_REG		0x20
#define CR0_REG		0x21
#define CR3_REG		0x22
#define CR4_REG		0x23
#define LDT_REG		0x24
#define GDT_REG		0x25

// Constants
#define UNDEFINED		0x00
#define UNSUPPORTED		0x00
#define SUPPORTED		0x01
#define INIT			0x100
#define INVALID			0x200
#define UNCHANGED		0x80
#define CHANGED			0x81


EFI_STATUS EFIAPI InspectorInit(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE  *SystemTable);
VOID EFIAPI InspectorMain(IN  EFI_HANDLE DispatchHandle,  IN  EFI_SMM_SW_DISPATCH_CONTEXT   *DispatchContext);
VOID EFIAPI InspectorConfig(IN  EFI_HANDLE DispatchHandle,  IN  EFI_SMM_SW_DISPATCH_CONTEXT   *DispatchContext);

UINT32 EncryptTask(struct task_t *cur_task, UINT32 index);
UINT32 DecryptTask(struct task_t *cur_task, UINT32 index);
UINT32 EncryptTasks(VOID);

UINT32 TestHmac(VOID);
UINT64* GetBin(UINT64* ptr64, UINT32*);
UINTN CheckRemoteSignature(UINT32 manager_sig[SIGN_INTS]);
UINT32 MeasureMemory(struct task_t *cur_task, UINT32 IssuingProcessor);
UINT32 MeasureRegister(struct task_t *cur_task, UINT32 IssuingProcessor);
UINT32 MeasureIdtrIdt(struct task_t *cur_task, UINT32 IssuingProcessor);
UINT32 MeasureMsr(struct task_t *cur_task);
UINT64 DoHash(const char* Ptr, struct task_t *cur_task);
UINT32 ProcessBin(UINT32 IssuingProcesser);
UINT32 EFIAPI GetApicId (IN VOID *Buffer);
UINT32 PrintMem(void *Mem, UINT64 Len);
UINT32 PrintBin(VOID);
UINT32 PrintTask(UINT32 Index);
VOID PrintHash(UINT32 hash[], UINT32);
VOID PrintHashBytes(UINT8 hash[SHA256_HASH_SIZE], UINT32 NumBytes);
UINT64 VaToPhysWalk(UINT32 index, UINTN VirtualAddr); // Wraps TranslateGuestLinearToPhysical(..)
VOID PrintConfig(VOID);


/*
 * For STM
 */

#define STM_API_GET_EXECUTIVE_MONITOR_CONTEXT      0x00000005

#define STM_SUCCESS 	 0x00000000
#define STM_SMM_REV_ID   0x80010100



/**

  This function invokes VMCALL with context.

  @param Eax   EAX register
  @param Ebx   EBX register
  @param Ecx   ECX register
  @param Edx   EDX register

  @return EAX register

**/
UINT32
EFIAPI
AsmVmCall (
  IN UINT32  Eax,
  IN UINT32  Ebx,
  IN UINT32  Ecx,
  IN UINT32  Edx
  );

