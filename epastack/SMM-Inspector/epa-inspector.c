/*
	EPA-RIMM Team
	July 30, 2019

	This module inspects the host-side environment from SMM to identify changes in resources.
	
	Important: 
	
	This code is a demonstration prototype. It has not been functionally or security-validated for production usages.
*/

#include "epa-inspector.h"
#include "PageWalk/pagewalk.h"
#include "msr-whitelist.h"

//
// Inspector globals
//
UINTN NumberOfEnabledProcessors 									= 0;
struct InspectorConfig_t	EpaConfig 								= {0};
struct task_t 				Bin[MAX_TASKS]							= {0}; 	  // Store a local copy of bin
STM_GET_EXECUTIVE_MONITOR_CONTEXT_DESCRIPTOR						*ExecMonDesc;
BOOLEAN						XEN_VIRT 								= FALSE;
UINT64						mGetVmmInfoBefore						= 0;
UINT64						mGetVmmInfoAfter						= 0;
UINT64						CpuFreq									= 0;
UINT32 						InitialBemSignature[SIGN_INTS]		= {0x414e414d, 0x31524547, 0x35343332, 0x39383736, 0x33323130}; 
VOID 						*gHmacCtx = NULL;							
UINT8						*gHashCoalesce = NULL;						

//
// Print the contents of a bin
//
UINT32 PrintBin()
{
  UINT32					i=0;
  
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: PrintBin\n\n"));
  for (i=0; i < MAX_TASKS; i++) { 
    if (Bin[i].Cmd ==0) {
      DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: End of Bin\n"));
      return 0;
    }
	switch (Bin[i].Cmd) {
		case 0:
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: End of Bin\n"));
			return 0;
			break;
		case HASH_MEM_VIRT:
		case HASH_MEM_PHYS:
		case CHECK_REG:
		case CHECK_MSR:
		case CHECK_IDTR_IDT:
			break;
		default:
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Skipping print of unknown command %Lx. Leaving PrintBin\n", Bin[i].Cmd));
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Encryption enable:%d\n", EpaConfig.AesEncryptEnable));
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Decryption enable:%d\n", EpaConfig.AesDecryptEnable));
			return 0;
			break;
		}
	}
  
	return 0;
}

//
// Print the Task
//
UINT32 PrintTask(UINT32 Index)
{
  UINT8 i = 0;
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Task #%d\n", Index));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Ivec1 0x%016LX\n", Bin[Index].Ivec1));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Ivec2 0x%016LX\n", Bin[Index].Ivec2));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Command 0x%016LX\n", Bin[Index].Cmd));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Operand 0x%016LX\n", Bin[Index].Operand));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Virtual Address 0x%016LX\n", Bin[Index].VirtAddr));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Physical Address 0x%016LX\n", Bin[Index].PhysAddr));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Length (Dec) %Ld\n", Bin[Index].Len));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Result 0x%016LX\n", Bin[Index].Result));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Nonce 0x%016LX\n", Bin[Index].Nonce));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost (Dec) %Ld\n", Bin[Index].Cost));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: TaskUuid %LX\n", Bin[Index].TaskUuid));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Reserved1 (Dec) %Ld\n", Bin[Index].Reserved1));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Hash: "));
  PrintHash(Bin[Index].Hash,SHA256_INTS);
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Manager Signature ", Bin[Index].ManagerSig));
  PrintHash(Bin[Index].ManagerSig,SIGN_INTS);
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Inspector Signature ", Bin[Index].ManagerSig));
  PrintHash(Bin[Index].InspectorSig,SIGN_INTS);
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat0.BigStat %Ld\n", Bin[Index].Stat0.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat1.BigStat %Ld\n", Bin[Index].Stat1.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat2.BigStat %Ld\n", Bin[Index].Stat2.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat3.BigStat %Ld\n", Bin[Index].Stat3.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat4.BigStat %Ld\n", Bin[Index].Stat4.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat5.BigStat %Ld\n", Bin[Index].Stat5.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat6.BigStat %Ld\n", Bin[Index].Stat6.BigStat));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat0.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat0.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat0.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat0.SmallStat[1]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat1.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat1.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat1.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat1.SmallStat[1]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat2.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat2.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat2.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat2.SmallStat[1]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat3.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat3.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat3.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat3.SmallStat[1]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat4.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat4.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat4.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat4.SmallStat[1]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat5.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat5.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat5.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat5.SmallStat[1]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat6.SmallStat[0] (dec) %Ld\n", Bin[Index].Stat6.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat6.SmallStat[1] (dec) %Ld\n", Bin[Index].Stat6.SmallStat[1]));

  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: HMAC "));
  for (i=0; i < HMAC_SIZE; i++) {
	DEBUG ((EFI_D_ERROR, " %02x ", Bin[Index].Hmac[i])); 
  }
  DEBUG((EFI_D_ERROR, "\n"));
  return 0;
}

//
// Encrypt a task into indexed bin
//
UINT32 EncryptTask(struct task_t *CurTask, UINT32 Index)
{
  UINT8    CipherCtx[AES_CIPHER_CTX_SIZE]={0}; 
  BOOLEAN  Status=0;
  UINT8*   CurTaskPtr = (UINT8*)CurTask;
  UINT8*   BinPtr = (UINT8*)&Bin[Index];
  UINT64   BeforeClk=0,AfterClk=0;
  UINT8    Ivec[AES_BLOCK_SIZE]={0};
  
  //
  // Set up AES
  //
  BeforeClk = AsmReadTsc();  // Measure performance
  Status = AesInit (CipherCtx, EpaConfig.Aes256CbcKey, AES_KEYSIZE);
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AesInit Status %x\n", Status));
  if (!Status) {
	  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AesInit Returning invalid %x\n", INVALID));
	  return INVALID;
  }
  //
  // Encrypt task into global bin structure
  //
  CopyMem(Ivec, &(CurTask->Ivec1), sizeof(CurTask->Ivec1));
  CopyMem(Ivec+8, &(CurTask->Ivec2), sizeof(CurTask->Ivec2));
  
  Status = AesCbcEncrypt (CipherCtx, (CurTaskPtr + AES_BLOCK_SIZE), (sizeof(struct task_t) - AES_BLOCK_SIZE), Ivec, (BinPtr + AES_BLOCK_SIZE)); 
  if (Status == FALSE) {
	  return INVALID;
  }
  AfterClk = AsmReadTsc();  // Measure performance
  
  //
  // Note can't write into the encrypted portion of the bin after encrypt!
  //
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: AesCbcEncrypt cost in clocks= %Lx\n", AfterClk - BeforeClk));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: AesCbcEncrypt Status = %x\n", Status));
  DEBUG ((EFI_D_ERROR, "\n"));
  
  return EFI_SUCCESS;
}

//
// Decrypt a task from an indexed bin
// Don't write to task until we HMAC!
//
UINT32 DecryptTask(struct task_t *CurTask, UINT32 Index)
{
  UINT8    CipherCtx[AES_CIPHER_CTX_SIZE]={0};  
  BOOLEAN  Status;
  
  UINT8*  curTaskPtr = (UINT8*)CurTask;
  UINT8*  BinPtr = (UINT8*)&Bin[Index];
  UINT64 BeforeClk=0, AfterClk=0;
  UINT8  Ivec[AES_BLOCK_SIZE]={0};

  if (EpaConfig.AesDecryptEnable==ON) {
	  DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: Decrypt bin\n"));
	  
	  //
	  // Set up AES
	  //
	  BeforeClk = AsmReadTsc();  // Measure performance
	  Status = AesInit (CipherCtx, EpaConfig.Aes256CbcKey, AES_KEYSIZE);
	
	  if (!Status) {
  		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AesInit Returning invalid %x\n", INVALID));
	     return INVALID;
	  }  
	   
	  CopyMem(Ivec, curTaskPtr, AES_BLOCK_SIZE); // First 16 bytes are Ivec in plaintext
	  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: DecryptTask retrieved Ivec:\n"));
	  PrintMem(Ivec,AES_BLOCK_SIZE );
	  Status = AesCbcDecrypt (CipherCtx, (curTaskPtr + AES_BLOCK_SIZE), (sizeof(struct task_t) - AES_BLOCK_SIZE), Ivec, (BinPtr + AES_BLOCK_SIZE));
	  
	  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: DecryptTask Ivec after AesCbcDecrypt:\n"));
	  PrintMem(Ivec,AES_BLOCK_SIZE );
	  
	  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AesCbcDecrypt Status %x\n", Status));

	  AfterClk = AsmReadTsc();  // Measure performance

	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: AesCbcDecrypt cost = %Lx\n", AfterClk - BeforeClk));
  
  } else {
	DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: Decrypt disabled in Inspector\n"));
  }
  return 0;
}

//
// Print the contents of memory as hex
//
UINT32 PrintMem(void *Mem, UINT64 Len)
{
  UINT8 *p = Mem;
  UINT64 i=0;
  
  for (i=0; i < Len; i++) {
    
    if ((i % 32==0) && (i > 0)) { // Print newline  
      DEBUG ((EFI_D_ERROR, "\n"));
    }
    DEBUG((EFI_D_ERROR, " %02x", p[i]));
  }
  DEBUG ((EFI_D_ERROR, "\n"));
  return 0;
}

//
// Simple mechanism to estimate the CPU frequency to allow reporting measurement 
// cost in usecs instead of clock ticks
//
UINT64 EstimateCpuFrequency(void)
{
	UINT64 Before = 0;
	UINT64 After = 0;
	UINT64 Delta[3] = { 0 };
	UINT64 EstimatedCpuFreq = 0;

	UINT32 i = 0;
	
	//
	// Take three 1ms samples and estimate CPU frequency
	//
	for (i = 0; i < 3; i++) {
		Before = AsmReadTsc();
		MicroSecondDelay(1000);
		After = AsmReadTsc();

		Delta[i] = After - Before;
	}
	
	EstimatedCpuFreq = (((Delta[0] + Delta[1] + Delta[2]) / 3)*1000);
	return EstimatedCpuFreq;
}

//
// Initial configuration entrypoint for this module
//
EFI_STATUS EFIAPI InspectorInit(IN EFI_HANDLE  ImageHandle, IN EFI_SYSTEM_TABLE  *SystemTable)
{
  EFI_STATUS 					Status;
  EFI_SMM_BASE2_PROTOCOL		*InternalSmmBase2;
  EFI_SMM_CPU_PROTOCOL 			*mSmmCpu = NULL;
  EFI_MP_SERVICES_PROTOCOL   	*MpServices;
  UINTN                      	mNumberOfProcessors;
  UINTN							CtxSize = 0;	// For HMAC
  UINTN                         CpuIndex;
  EFI_PHYSICAL_ADDRESS          VmmDescAddress;
  EFI_PHYSICAL_ADDRESS          ExecMonDescAddress;	
  EFI_SMM_SW_DISPATCH_PROTOCOL  *SwDispatch;
  EFI_SMM_SW_DISPATCH_CONTEXT   SwContext;
  EFI_HANDLE                    Handle = NULL;
    
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector Loading\n"));  
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector Locate SmmBase2Protocol\n"));  
  InternalSmmBase2 = NULL;
  Status = SystemTable->BootServices->LocateProtocol (
                                        &gEfiSmmBase2ProtocolGuid,
                                        NULL,
                                        (VOID **)&InternalSmmBase2
                                        );
  ASSERT_EFI_ERROR (Status);
  ASSERT (InternalSmmBase2 != NULL);
  
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector - GetSmstLocation\n"));  
  InternalSmmBase2->GetSmstLocation (InternalSmmBase2, &gSmst);
  ASSERT (gSmst != NULL);

  Status = SystemTable->BootServices->LocateProtocol (&gEfiMpServiceProtocolGuid, NULL, (VOID **)&MpServices);
  ASSERT_EFI_ERROR (Status);
	
  Status = MpServices->GetNumberOfProcessors (MpServices, &mNumberOfProcessors, &NumberOfEnabledProcessors);
  ASSERT_EFI_ERROR (Status);
    
  DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: number of enabled processors %d.\n",NumberOfEnabledProcessors));
  CpuFreq = EstimateCpuFrequency();
  DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: estimated CPU frequency %ld.\n",CpuFreq));
  

  //
  //  Get the Sw dispatch protocol
  //
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector - Getting SwDispatch Protocol to register an SMI\n"));  
  Status = SystemTable->BootServices->LocateProtocol (
                  &gEfiSmmSwDispatchProtocolGuid,
                  NULL,
  				 (void **)&SwDispatch
                  );
  ASSERT_EFI_ERROR(Status);
  
  //
  // Register EPA RIMM measurement SMI
  //
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector - Registering an SMI\n"));  
  SwContext.SwSmiInputValue = EPA_SMI_CMD; 
  Status = SwDispatch->Register (
                         SwDispatch,
                         InspectorMain,
                         &SwContext,
                         &Handle
                         );
  ASSERT_EFI_ERROR(Status);
  
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector - Registering an SMI for debug configuration\n"));  
  SwContext.SwSmiInputValue = INSPECTOR_CONF; 
  Status = SwDispatch->Register ( // Debug method of changing Inspector parameters at runtime
                         SwDispatch,
                         InspectorConfig,
                         &SwContext,
                         &Handle
                         );
  ASSERT_EFI_ERROR(Status);
    
  Status = gSmst->SmmLocateProtocol (
				     &gEfiSmmCpuProtocolGuid,
				     NULL,
				     (VOID **)&mSmmCpu
				     );
  ASSERT_EFI_ERROR(Status);
  
  //
  // Allocating Pages for Executive Monitor
  //
    Status = gSmst->SmmAllocatePages (
				AllocateAnyPages,
				EfiRuntimeServicesData,
				EFI_SIZE_TO_PAGES(sizeof(STM_GET_EXECUTIVE_MONITOR_CONTEXT_DESCRIPTOR)*NumberOfEnabledProcessors),
				&ExecMonDescAddress);

    if (EFI_ERROR (Status)) {
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Failed to Allocate page for ExecMonDescAddress\n"));
		return 0;
	}
#if 0
    DEBUG ((EFI_D_ERROR, "EPA-RIMM: ExecMonDesc %x\n", ExecMonDescAddress));
#endif
    ExecMonDesc = (STM_GET_EXECUTIVE_MONITOR_CONTEXT_DESCRIPTOR*)(UINTN)(ExecMonDescAddress);

  //
  // Allocate Pages per CPU VMM Descriptor
  //
  for (CpuIndex = 0; CpuIndex < NumberOfEnabledProcessors; CpuIndex++) {
    Status = gSmst->SmmAllocatePages (
        AllocateAnyPages,
        EfiRuntimeServicesData,
        EFI_SIZE_TO_PAGES(sizeof(MLE_VMM_DESCRIPTOR)),
        &VmmDescAddress);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Failed to Allocate page for Vmm Descriptor\n"));
      return Status;
    }
#if 0
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: VmmDescAddress %x\n", VmmDescAddress));
#endif
    ExecMonDesc[CpuIndex].VmDescriptor = (UINT64)(UINTN)VmmDescAddress;
  }

  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector - Setting default configuration\n"));  
  
  //
  // Set default config
  //
  EpaConfig.HmacCreateEnable = ON;
  EpaConfig.HmacCheckEnable = ON;
  EpaConfig.AesEncryptEnable = ON;
  EpaConfig.AesDecryptEnable = ON;
  EpaConfig.CheckSmrrOverlapEnable = ON;
  EpaConfig.MaxMemoryHashSize = MAX_MEMORY_MEASUREMENT_LEN_INIT;
  EpaConfig.MaxTasks = MAX_TASKS;
  EpaConfig.InspectorUsecsCostEnable = ON;
	
  CopyMem(EpaConfig.InspectorSig, "INSPECTOR12345678901", SIGNATURE_SIZE);
  CopyMem(EpaConfig.ManagerSig, InitialBemSignature, SIGNATURE_SIZE);
  CopyMem(EpaConfig.Aes256CbcKey, Aes256CbcKeyInit, AES_KEYSIZE/8);
  CopyMem(EpaConfig.HmacKey, HmacKeyInit, HMAC_KEY_LEN);
  PrintConfig();
      
  CtxSize  = HmacSha256GetContextSize();
  Status = gSmst->SmmAllocatePool (EfiRuntimeServicesData, CtxSize, (VOID**) &gHmacCtx);
  ASSERT_EFI_ERROR (Status);

  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Allocating %d bytes for gHashCoalesce\n", NumberOfEnabledProcessors * sizeof(UINT64)));
  Status = gSmst->SmmAllocatePool (EfiRuntimeServicesData, NumberOfEnabledProcessors * sizeof(UINT64), (VOID**) &gHashCoalesce);
  ASSERT_EFI_ERROR (Status);  

  return EFI_SUCCESS;
}

//
// Request for VMM-specific info from STM VMCS Database
//
EFI_STATUS GetVmmInfo(UINT32 CpuIndex)
{
  UINTN											ExecMonDescAddress;
  MLE_VMM_DESCRIPTOR 							  	*VmmDesc;
  UINT32											Eax;
  UINT32											Lo;
  UINT32											Hi;

  ExecMonDescAddress = (UINTN)&ExecMonDesc[CpuIndex];
  VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)(ExecMonDesc[CpuIndex].VmDescriptor);
  SetMem((VOID*)(UINTN)(ExecMonDesc[CpuIndex].VmDescriptor), sizeof(MLE_VMM_DESCRIPTOR), 0);
  VmmDesc->LocalApicId = CpuIndex;

  Lo = (UINT32)ExecMonDescAddress;
  Hi = ((UINT64)ExecMonDescAddress) >> 32;
#if 0
  DEBUG ((EFI_D_ERROR, "EPA-RIMM: ExecMonDescAddress Lo %016lx\n", Lo));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM: ExecMonDescAddress Hi %016lx\n", Hi));
#endif

  Eax = AsmVmCall(STM_API_GET_EXECUTIVE_MONITOR_CONTEXT, Lo, Hi, 0);
  if (Eax != STM_SUCCESS) {
	    DEBUG ((EFI_D_ERROR, "EPA-RIMM: STM_API_GET_EXECUTIVE_MONITOR_CONTEXT error %x\n", Eax));
		return Eax;
  }
  DEBUG ((EFI_D_ERROR, "EPA-RIMM: STM_API_GET_EXECUTIVE_MONITOR_CONTEXT Ret %x\n", Eax));
#if 0
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->Signature %x\n", VmmDesc->Signature));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmDescriptorVerMajor %x\n", VmmDesc->VmmDescriptorVerMajor));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmDescriptorVerMinor %x\n", VmmDesc->VmmDescriptorVerMinor));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->LocalApicId %0x\n", VmmDesc->LocalApicId));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmCr0 %016lx\n", VmmDesc->VmmCr0));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmCr3 %016lx\n", VmmDesc->VmmCr3));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmCr4 %0x\n", VmmDesc->VmmCr4));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmLdtrBase %016lx\n", VmmDesc->VmmLdtrBase));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmGdtrBase %016lx\n", VmmDesc->VmmGdtrBase));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmIdtrBase %016lx\n", VmmDesc->VmmIdtrBase));
  DEBUG ((EFI_D_INFO, "EPA-RIMM: VmmDesc->VmmEfer %016lx\n", VmmDesc->VmmEfer));
#endif
  return EFI_SUCCESS;
}

//
// Read a bin from the address the Ring 0 Manager specified
//
UINT64* GetBin(UINT64 *Ptr64, UINT32 *IssuingProcessor)
{
  UINT64					Rax = 0;
  UINT64					Rbx = 0;
  UINT64					Rcx = 0;
  UINT64					Rdx = 0;
  UINT32					Found = 0;
  UINT32					i = 0;
  UINT64*					PhysAddrPtr=NULL;
  EFI_STATUS                Status = EFI_SUCCESS;
  EFI_SMM_CPU_PROTOCOL      *mSmmCpu = NULL;
  UINT64					SmmRevId = 0;
  
  //
  // Use EfiSmmCpuProtocol to read SMRAM Save State Map
  //
  Status = gSmst->SmmLocateProtocol (
				     &gEfiSmmCpuProtocolGuid,
				     NULL,
				     (VOID **)&mSmmCpu
				     );
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR(Status)) // For release builds
      return 0;
  //
  // Check all CPU threads for EPA_SMI_CMD on RAX. 
  // Once found: read Rax/Rbx/Rcx/Rdx and break to save time.
  //
  for (i=0; i < NumberOfEnabledProcessors; i++) {
    mSmmCpu->ReadSaveState (
			    mSmmCpu,
			    sizeof(UINT64),
			    EFI_SMM_SAVE_STATE_REGISTER_RAX,
			    i, //Which CPU to read from
			    &Rax
			    );	
    
    if ( (Rax & 0xFF) == EPA_SMI_CMD) { // Mask out upper bits, leaving command
      DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Found EPA_SMI_CMD on %d\n", i));
      Found = 1;
      
      mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINT64),
			      EFI_SMM_SAVE_STATE_REGISTER_RBX,
			      i, //Which CPU to read from
			      &Rbx
			      );	
      
      mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINT64),
			      EFI_SMM_SAVE_STATE_REGISTER_RCX,
			      i, //Which CPU to read from
			      &Rcx
			      );	
      
      mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINT64),
			      EFI_SMM_SAVE_STATE_REGISTER_RDX,
			      i, //Which CPU to read from
			      &Rdx
			      );	

      SmmRevId = (( EFI_SMM_CPU_STATE *)(gSmst->CpuSaveState[i]))->x64.SMMRevId;
      *IssuingProcessor = i;
	  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Set IssuingProcessor to %x\n",*IssuingProcessor ));
      break;
    }		   
    
  }
  
  //
  // If there was no bin found, exit
  //
  if (Found == NOT_FOUND) {
    DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: ERROR, did not find EPA_SMI_CMD."));
    return NOT_FOUND;
  }
  
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: RAX: 0x%016LX . RBX 0x%016LX. RCX 0x%016LX. RDX 0x%016LX\n", Rax, Rbx, Rcx, Rdx));
  
  if( (Rdx & 0xFF) == MEASURE_XEN) { // Xen measurement specified

    if(SmmRevId != STM_SMM_REV_ID) { // Xen measurement specified but no STM present - error
      return 0;
    }
	
    XEN_VIRT = TRUE;

    ExecMonDesc[*IssuingProcessor].VmIndex = 0;
    mGetVmmInfoBefore = AsmReadTsc();
    Status = GetVmmInfo(*IssuingProcessor);
    mGetVmmInfoAfter = AsmReadTsc();
    if (EFI_ERROR(Status))
      return 0;
  }
  /*
    Get address of Manager provided command/data buffer, convert its virtual address to physical, and copy to a local copy in SMM
    (Copying locally avoids attack "time of check to time of use" (aka "TOCTOU") issue where bin is modified before SMM Inspector deals with it)
  */
  Ptr64 = (UINT64*)(UINTN)Rbx; // Address Parameter from Manager is in Rbx, fixme: sanity check RBX value
  PhysAddrPtr = (UINT64*)(UINTN)VaToPhysWalk(*IssuingProcessor, (UINT64)Ptr64);  
  
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: RBX %Lx. Phys of RBX = %Lx\n", Ptr64, PhysAddrPtr));
  if (PhysAddrPtr == 0)
    return 0;
  CopyMem(&Bin[0], PhysAddrPtr, (sizeof(struct task_t)*MAX_TASKS));
  //PrintBin(); // Print out bin
    
  return (UINT64*)(UINTN)PhysAddrPtr;
}

//
// Measure a register based on values in SMRAM Save State Map
//
UINT32 MeasureRegister(struct task_t *CurTask, UINT32 IssuingProcessor)
{
  UINT32					Val32 = 0;
  UINT64					Val64 = 0;
  UINT64*					Val64Ptr = &Val64;
  UINT32					i = 0;
  EFI_SMM_CPU_PROTOCOL 		*mSmmCpu = NULL;
  EFI_STATUS 				Status = EFI_SUCCESS;
  MLE_VMM_DESCRIPTOR   		*VmmDesc;
  UINT32					Smbase = 0;
  UINT64					OrigLength  = CurTask->Len;
  
  ASSERT (gHashCoalesce != NULL);
  if (gHashCoalesce == NULL) {
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: gHashCoalesce is null!\n"));
	  return INVALID;
  }

  if(XEN_VIRT) {
    for (i=0; i < NumberOfEnabledProcessors; i++) {
      if(i != IssuingProcessor) {
        ExecMonDesc[i].VmIndex = 0;  // 0 - for VMX root
        Status = GetVmmInfo(i);
        if (EFI_ERROR(Status))
          return INVALID;
      }
    }
  }

  Status = gSmst->SmmLocateProtocol (
				     &gEfiSmmCpuProtocolGuid,
				     NULL,
				     (VOID **)&mSmmCpu
				     );
  
  ASSERT_EFI_ERROR(Status);
    
  //
  // Check that hash size is greater than 0 but not greater than max hash size
  //
  if ((CurTask->Len == 0) || (CurTask->Len > MAX_MEMORY_MEASUREMENT_LEN_INIT) ) {
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Invalid hash size specified!\n"));
	  CurTask->Result = INVALID;
	  return INVALID;
  }
  
  //
  // Find the type of register to inspect
  //
  switch (CurTask->Operand) { 
  case IDT_REG:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: IDTR Measurement Requested\n"));
    
    for (i=0; i < NumberOfEnabledProcessors; i++) {
      if(XEN_VIRT) {
        VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
        Val64 = VmmDesc->VmmIdtrBase;
      }
      else {
		mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINTN),
			      EFI_SMM_SAVE_STATE_REGISTER_IDTBASE,
			      i, // CPU #
			      &Val64
			      );
	  }
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CPU %d IDTR = 0x%016LX\n", i, Val64));	
	  CopyMem(gHashCoalesce + (i*sizeof(UINT64)), Val64Ptr, sizeof(UINT64));
    } // end for (IDT)
	
    break;
  case CR0_REG:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CR0 Measurement\n"));		
    //
	// We treat CR0 as 64bit based on UEFI file : edk2\UefiCpuPkg\Include\Register\SmramSaveStateMap.h
    //
    for (i=0; i < NumberOfEnabledProcessors; i++) {
      if(XEN_VIRT) {
        VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
        Val64 = VmmDesc->VmmCr0;
      }
      else {
        mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINTN),
			      EFI_SMM_SAVE_STATE_REGISTER_CR0,
			      i, // CPU #
			      &Val64  
			      );
      }
      DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CPU %d CR0 = 0x%016LX\n", i, Val64));	
	  CopyMem(gHashCoalesce + (i*sizeof(UINT64)), Val64Ptr, sizeof(UINT64));
	  
    } // end for (CR0)
    
    break;
  case LDT_REG:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: LDTR Measurement\n"));		
    for (i=0; i < NumberOfEnabledProcessors; i++) {
		if(XEN_VIRT) {
			VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
			Val64 = VmmDesc->VmmLdtrBase;
		}
		mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINTN),
			      EFI_SMM_SAVE_STATE_REGISTER_LDTBASE,
			      i, // CPU #
			      &Val64
			      );
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CPU %d LDTR = 0x%016LX\n", i, Val64));	
		CopyMem(gHashCoalesce + (i*sizeof(UINT64)), Val64Ptr, sizeof(UINT64));
	   
    } // end for (LDT)
	
    break;
  case CR3_REG:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CR3 Measurement\n"));		
    for (i=0; i < NumberOfEnabledProcessors; i++) {
      if(XEN_VIRT) {
        VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
        Val64 = VmmDesc->VmmCr3;
      }
      else {
        mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINTN),
			      EFI_SMM_SAVE_STATE_REGISTER_CR3,
			      i, // CPU #
			      &Val64  
			      );
      }
	   DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CPU %d CR3 = 0x%016LX\n", i, Val64));	
	   CopyMem(gHashCoalesce + (i*sizeof(UINT64)), Val64Ptr, sizeof(UINT64));

    } // end for (CR3)
    break;
  case CR4_REG:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CR4 Measurement\n"));		
    for (i=0; i < NumberOfEnabledProcessors; i++) {
		if(XEN_VIRT) {
			VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
			Val32 = VmmDesc->VmmCr4;
		} else {
          //
		  // CR4 doesn't appear readable from the mSmmCpu->ReadSaveState API 
          // (returns 0), so we get from SMRAM Save State Map directly.
		  // We treat CR4 as 32bit based on UEFI file : edk2\UefiCpuPkg\Include\Register\SmramSaveStateMap.h
		  //
		  Smbase = (( EFI_SMM_CPU_STATE *)(gSmst->CpuSaveState[i]))->x64.SMBASE;
		  Val32 = *(UINT32*)(UINTN)(Smbase + 0x8000 + 0x7E40);
		}
		  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CPU %d CR4 = 0x%x\n", i, Val32));
		  CopyMem(gHashCoalesce + (i*sizeof(UINT32)), &Val32, sizeof(UINT32));
		  
	} // end for (CR4)
    break;
  case GDT_REG:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: GDTR Measurement\n"));		
    for (i=0; i < NumberOfEnabledProcessors; i++) {
      if(XEN_VIRT) {
        VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
        Val64 = VmmDesc->VmmGdtrBase;
      }
      else {
        mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINTN),
			      EFI_SMM_SAVE_STATE_REGISTER_GDTBASE,
			      i, // CPU #
			      &Val64
			      );
      }
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: CPU %d GDTR = 0x%016LX\n", i, Val64));	
	  CopyMem(gHashCoalesce + (i*sizeof(UINT64)), Val64Ptr, sizeof(UINT64));
	  
    } // end for (GDT)
    break;
  default:
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Error, unknown Register Measurement Requested 0x%016LX: \n", CurTask->Operand));
	CurTask->Result = INVALID;
    return INVALID;
    break;
  }
  
  //
  // Do the hash across data from all CPUs
  //
  CurTask->Len = NumberOfEnabledProcessors * sizeof(UINT64);
  DoHash((const char*)gHashCoalesce, CurTask);
  CurTask->Len = OrigLength;
  //
  // Update stats
  //
  
  CurTask->LastChecked = AsmReadTsc();
  CurTask->Nonce = CurTask->Nonce ^ NONCE_VAL;
  
  //
  // "Sign" the task measurement
  //
  CopyMem(CurTask->InspectorSig, EpaConfig.InspectorSig, sizeof(CurTask->InspectorSig));
  
  if (EpaConfig.InspectorUsecsCostEnable==ON) {
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in CPU clocks %d\n", CurTask->Cost));
	  CurTask->Cost = ((CurTask->Cost * 1000000) / CpuFreq);
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in microseconds %d\n", CurTask->Cost));
  }  
	
  return 0;
}

//
// Make sure the Backend Manaqer's signature is correct
//
UINTN CheckRemoteSignature(UINT32 ManagerSig[SIGN_INTS])
{
  UINTN 				Comparison=0;
  
  
  Comparison = CompareMem(ManagerSig, EpaConfig.ManagerSig, SIGNATURE_SIZE);
  
  if (Comparison==0) {
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Manager signature ok.\n"));
  } else {
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Bad manager signature!\n"));
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Provided BEM signature:"));
	PrintHashBytes((UINT8*)ManagerSig, SIGNATURE_SIZE);
	DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: Configured BEM signature:"));
	PrintHashBytes((UINT8*)EpaConfig.ManagerSig, SIGNATURE_SIZE);
	DEBUG ((EFI_D_ERROR, "\n"));
  }
  
  return Comparison;
}

//
// Measure an MSR. (fixme: only works for this CPU's MSRs)
//
UINT32 MeasureMsr(struct task_t *CurTask)
{
  UINT64 Val=0;
  UINT64 *ValPtr = &Val;
  UINT64 MsrValid = 0;
    
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: MSR Measurement.\n"));
    
  //  
  // Some MSRs aren't supported on this CPU, first check if MSR is on whitelist
  //
  MsrValid = CheckMsrValidSilvermontAtom(CurTask->Operand);
  if (MsrValid == 0) {
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Prohibited MSR on this CPU! %Lx\n", CurTask->Operand));
	CurTask->Result = INVALID;
	return 0;
  }
  
  //
  // Read in the current MSR value
  //
  if (CurTask->Len == sizeof(UINT64)) {
	Val = AsmReadMsr64((UINT32)CurTask->Operand);
  } else if (CurTask->Len == sizeof(UINT32)) {
	Val = AsmReadMsr32((UINT32)CurTask->Operand);
  } else {
	  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: MeasureMsr, unexpected MSR len %LX", (UINT32)CurTask->Len));
	  CurTask->Result = INVALID;
	  return 0;
	}
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector, MSR %x=%x\n", (UINT32)CurTask->Operand, Val));
  //
  // Hash the MSR
  //
  DoHash((const char*)ValPtr, CurTask);
  
  //
  // Update Stats
  //
  if (EpaConfig.InspectorUsecsCostEnable == ON) {
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in CPU clocks %d\n", CurTask->Cost));
	  CurTask->Cost = ((CurTask->Cost * 1000000) / CpuFreq);
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in microseconds %d\n", CurTask->Cost));
  }

  CurTask->LastChecked = AsmReadTsc();
  
  //
  // Sign the measurement
  //
  CopyMem(CurTask->InspectorSig, EpaConfig.InspectorSig, sizeof(CurTask->InspectorSig));
  CurTask->Nonce = CurTask->Nonce ^ NONCE_VAL;
  return 0;
}

//
// Measure a combined check (IDTR measurement + IDT measurement)
//
UINT32 MeasureIdtrIdt(struct task_t *CurTask, UINT32 IssuingProcessor)
{
  UINT32 					i = 0;
  UINT32					Ret = 0;
  UINT64					CurIdt = 0;
  UINT64					BeforeClk, AfterClk;
  struct task_t			TempTask;
  EFI_STATUS 			Status = EFI_SUCCESS;
  EFI_SMM_CPU_PROTOCOL 	*mSmmCpu = NULL;
  MLE_VMM_DESCRIPTOR		*VmmDesc;
  
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: MeasureIdtrIdt\n"));
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: WARNING! Not implemented: MeasureIdtrIdt\n"));
  SetMem(&TempTask, sizeof(struct task_t),0);
  
  BeforeClk = AsmReadTsc();  // Measure performance
  
  Status = gSmst->SmmLocateProtocol (
				     &gEfiSmmCpuProtocolGuid,
				     NULL,
				     (VOID **)&mSmmCpu
				     );
  ASSERT_EFI_ERROR(Status);

  // First measure or re-measure IDTR
  for (i = 0; i < NumberOfEnabledProcessors; i++) {
    if(XEN_VIRT) {
	  if( i != IssuingProcessor) {
		  ExecMonDesc[i].VmIndex = 0;  // 0 - for VMX root
		  Status = GetVmmInfo(i);
		  if(EFI_ERROR(Status))
			  return 0;
	  }
	  VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[i].VmDescriptor;
	  CurIdt = VmmDesc->VmmIdtrBase;
    }
    else {
      mSmmCpu->ReadSaveState (
			    mSmmCpu,
			    sizeof(UINTN),
			    EFI_SMM_SAVE_STATE_REGISTER_IDTBASE,
			    i, // CPU #
			    &CurIdt
			    );
    }
    
	//
    // Set up a temp task to be able to use existing API for measuring memory. 
	// Note: Need to put select temp values back into CurTask!
	//
    TempTask.PhysAddr = VaToPhysWalk(i, CurIdt); //fixme, first parameter;
    TempTask.Cmd	= HASH_MEM_PHYS;
    TempTask.Len = 0x1000; // IDT Size
    CopyMem(TempTask.Hash, CurTask->Hash, SHA256_HASH_SIZE); // Set hash

  } // end for (IDTR)
  
  // Now measure IDT (once)
  Ret = MeasureMemory(&TempTask, IssuingProcessor);
  if (Ret == INVALID)
	  return INVALID;
  CopyMem(CurTask->Hash, TempTask.Hash, SHA256_HASH_SIZE); // Save hash
  if (CurTask->Result != CHANGED) { // Don't overwrite a changed IDTR finding
    CurTask->Result = TempTask.Result;
  }
  
  AfterClk = AsmReadTsc();  // Measure performance
  CurTask->Cost = AfterClk - BeforeClk;

  if (EpaConfig.InspectorUsecsCostEnable == ON) {
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in CPU clocks %d\n", CurTask->Cost));
	CurTask->Cost = ((CurTask->Cost * 1000000) / CpuFreq);
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in microseconds %d\n", CurTask->Cost));
  }

  return 0;
}

//
// Encrypt tasks in a bin
//
UINT32 EncryptTasks(void)
{
  UINT32 i = 0;
  UINT32 Ret = FALSE;
  
  if (EpaConfig.AesEncryptEnable == ON) {
	  for (i=0; i < MAX_TASKS; i++) {
		switch (Bin[i].Cmd) {
			case CHECK_IDTR_IDT:
			case CHECK_MSR:
			case HASH_MEM_PHYS:
			case HASH_MEM_VIRT:
			case CHECK_REG:
			  Ret = EncryptTask(&Bin[i], i);
			  break;			
		}
	  }
  }  

  return Ret;
}

//
// Walk all tasks in bin and perform their respective commands
//
UINT32 ProcessBin(UINT32 IssuingProcesser)
{
  UINT32 				i=0;
  UINT32 				Ret = 0;
  INTN					Comparison=0;
  UINT8					CheckHmac[HMAC_SIZE] = {0};
  INTN					HmacComparison = 0;
  UINT64 				BeforeClk1;
  UINT64 				AfterClk1; 
  BOOLEAN           	HmacRet = FALSE;

  if (gHmacCtx == NULL) {
	  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: HMAC context is null! Exiting.\n"));
	  return 0;
  }
  
  //
  // Go through each task in bin and process
  //
  for (i=0; i < MAX_TASKS; i++) {
    DecryptTask(&Bin[i], i);
    
    Comparison = CheckRemoteSignature(Bin[i].ManagerSig);	 
      
    if (Comparison !=0) {
      return i;
    }
	
	//
	// Don't write to bin before HMAC otherwise HMAC will not match!
	//
	if (EpaConfig.HmacCheckEnable) {
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector:Beginning HMAC\n"));
		BeforeClk1 = AsmReadTsc();
		HmacRet = HmacSha256Init(gHmacCtx, EpaConfig.HmacKey, HMAC_KEY_LEN);
		if (HmacRet == FALSE) {
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Unable to HmacSha256Init\n"));
			return 0;
		}
		HmacRet = HmacSha256Update(gHmacCtx, &Bin[i], sizeof(struct task_t) - HMAC_SIZE); 
		//
		// HMAC the task except for the HMAC part at the end (skip the last 32 bytes), // assumes HMAC at end of task with nothing following it 
		// 
		if (HmacRet == FALSE) {
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector:Error in HmacSha256Update!\n"));
			return 0;
		}
		HmacRet = HmacSha256Final(gHmacCtx, CheckHmac);
		if (HmacRet == FALSE) {
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector:Error in HmacSha256Final!\n"));
			return 0;
		}
		
		AfterClk1 = AsmReadTsc();
		HmacComparison = CompareMem(CheckHmac, Bin[i].Hmac, HMAC_SIZE);
		if (HmacComparison  == 0) {
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: HMAC of incoming task ok!\n"));
		} else {
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: HMAC comparison failed! Task may have been tampered with!!!\n"));  
			DEBUG ((EFI_D_INFO, "EPA-RIMM-Inspector: Bin HMAC:\n"));
			PrintMem(Bin[i].Hmac, HMAC_SIZE);
			DEBUG ((EFI_D_INFO, "EPA-RIMM-Inspector: Expected HMAC:\n"));
			PrintMem(CheckHmac, HMAC_SIZE);
			return i;
		}

		Bin[i].Stat3.SmallStat[1] = (UINT32)(AfterClk1 - BeforeClk1); //Cost of HMAC
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Stat3.SmallStat[1] 0x%x\n", Bin[i].Stat3.SmallStat[1]));
	}
	
    PrintTask(i);
    switch (Bin[i].Cmd) {
    case CHECK_IDTR_IDT:
		Ret = MeasureIdtrIdt(&Bin[i], IssuingProcesser);
      break;
    case CHECK_MSR:
		MeasureMsr(&Bin[i]);
      break;
    case HASH_MEM_PHYS: // Fall through
    case HASH_MEM_VIRT:
      DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: Performing Memory Region Check.\n"));
		Ret = MeasureMemory(&Bin[i],IssuingProcesser);
      break;
    case CHECK_REG:
      DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Performing Register Check.\n"));
		Ret = MeasureRegister(&Bin[i], IssuingProcesser);
      
      break;
    case UNDEFINED:
      DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Reached end of bin.\n"));
      return i;
      break;
    default:
      DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Unknown command received. %Lx\n", Bin[i].Cmd));
      return i;
      break;
    }
  }
  
  return i;
}

//
// Call modified version of STM's virtual to physical conversion routine
//
UINT64 VaToPhysWalk(UINT32 Index, UINTN VirtualAddr)
{
  
  BOOLEAN  *Ia32e = 0;
  BOOLEAN  *Pg = 0;
  BOOLEAN  *Pae = 0;
  BOOLEAN  *Pse = 0;
  BOOLEAN  *Sp = 0;
  UINTN    Cr0 = 0;
  UINTN    Cr3 = 0;
  UINT32    Cr4 = 0;
  UINT64   Efer = 0;
  UINT64   **Entry=NULL;
  UINT64   PhysAddr=0;
  UINT32   Smbase = 0;
  EFI_SMM_CPU_PROTOCOL *mSmmCpu = NULL;
  EFI_STATUS Status = EFI_SUCCESS;
  
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector:VaToPhysWalk with CPU# %d.\n", Index));
  
  Status = gSmst->SmmLocateProtocol (
				     &gEfiSmmCpuProtocolGuid,
				     NULL,
				     (VOID **)&mSmmCpu
				     );
  ASSERT_EFI_ERROR (Status);
  
  if(XEN_VIRT) {
	MLE_VMM_DESCRIPTOR   *VmmDesc;
	VmmDesc = (MLE_VMM_DESCRIPTOR*)(UINTN)ExecMonDesc[Index].VmDescriptor;
	Cr0     = VmmDesc->VmmCr0;
	Cr3     = VmmDesc->VmmCr3;
	Cr4     = VmmDesc->VmmCr4;
	Efer    = (UINT32)(UINTN)(VmmDesc->VmmEfer);
  }
  else {
    mSmmCpu->ReadSaveState (
			  mSmmCpu,
			  sizeof(UINTN),
			  EFI_SMM_SAVE_STATE_REGISTER_CR3,
			  Index,
			  &Cr3
			  );	
  
  mSmmCpu->ReadSaveState (
			  mSmmCpu,
			  sizeof(UINTN),
			  EFI_SMM_SAVE_STATE_REGISTER_CR0,
			  Index, 
			  &Cr0
			  );	
  mSmmCpu->ReadSaveState (
			  mSmmCpu,
			  sizeof(UINT32),
			  EFI_SMM_SAVE_STATE_REGISTER_CR4,
			  Index, 
			  &Cr4
			  );
    //
    // Efer does not seem accessible except directly through the Save State Map 
	//
    Smbase = (( EFI_SMM_CPU_STATE *)(gSmst->CpuSaveState[Index]))->x64.SMBASE;
    Efer = *(UINT32*)(UINTN)(Smbase + 0x8000 + 0x7fe0);
  }

  //
  // Convert virtual address to physical
  //
  PhysAddr =  TranslateGuestLinearToPhysical (Cr3, Cr0, Cr4, Efer, VirtualAddr, Ia32e, Pg, Pae, Pse, Sp, Entry);
  return PhysAddr;
}

//
// Measure virtual or physical memory
//
UINT32 MeasureMemory(struct task_t *CurTask, UINT32 IssuingProcessor)
{
  UINT64 *PhysAddrPtr=NULL;
  UINT64 *VirtAddrPtr=NULL;
  BOOLEAN OutsideSmm = TRUE;
  UINT64 BeforeClk=0, AfterClk=0;
    
  if (CurTask->Cmd == HASH_MEM_PHYS) {
    PhysAddrPtr = (UINT64*)(UINTN)CurTask->PhysAddr;

	if (CurTask->Len > EpaConfig.MaxMemoryHashSize) {
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Monitored memory address exceeds MaxMemoryHashSize %Lx", EpaConfig.MaxMemoryHashSize));
		CurTask->Result = INVALID;
		return INVALID;
	} else if ((CurTask->Len == 0) || (CurTask->Len > MAX_MEMORY_MEASUREMENT_LEN_INIT) ) {
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Invalid memory measurement requested!"));
		CurTask->Result = INVALID;
		return INVALID;
	}	
	
	if (EpaConfig.CheckSmrrOverlapEnable == ON) {
		OutsideSmm = SmmIsBufferOutsideSmmValid((UINTN)PhysAddrPtr,CurTask->Len);
		if (OutsideSmm == FALSE) { 
		//
		// Ring0 Manager-provided bin address is inside SMM, security error!
		//
		  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Monitored memory address cannot be within SMM memory!"));
		  return INVALID;
		}
	}
	
    DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: PhysAddrPtr to hash 0x%016LX: Len=%016LX\n", PhysAddrPtr, CurTask->Len));
    	
	DoHash((const char*)PhysAddrPtr, CurTask);
		
	if (EpaConfig.InspectorUsecsCostEnable == ON) {
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in CPU clocks %d\n", CurTask->Cost));
		CurTask->Cost = ((CurTask->Cost * 1000000) / CpuFreq);
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in microseconds %d\n", CurTask->Cost));
	}
	PrintMem(PhysAddrPtr, 20);
	
  } else if (CurTask->Cmd == HASH_MEM_VIRT) {
    DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Need to convert virtual address %016LX to physical, using CPU# %d\n", CurTask->VirtAddr, IssuingProcessor));
    VirtAddrPtr = (UINT64*)(UINTN)VaToPhysWalk(IssuingProcessor, CurTask->VirtAddr); 
	if (VirtAddrPtr == 0) {
		CurTask->Result = INVALID;
		return INVALID;
	}
	if (CurTask->Len > EpaConfig.MaxMemoryHashSize) {
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Monitored memory address exceeds maximum allowed value %Lx", EpaConfig.MaxMemoryHashSize));
		CurTask->Result = INVALID;		
		return INVALID;
	} else if (CurTask->Len == 0) {
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Zero byte measurement requested!"));
		CurTask->Result = INVALID;
		return INVALID;
	}		

    DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Converted VA 0x%016LX to 0x%016LX\n Hash len =%016LX\n", CurTask->VirtAddr, VirtAddrPtr, CurTask->Len));

	if (EpaConfig.CheckSmrrOverlapEnable == ON) {
		OutsideSmm = SmmIsBufferOutsideSmmValid((UINTN)VirtAddrPtr,CurTask->Len);
		if (OutsideSmm == FALSE) { 
		//
		// Ring0 Manager-provided bin address is inside SMM, security error!
		//
		  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Monitored memory address cannot be within SMM memory!"));
		  CurTask->Result = INVALID;				  
		  return INVALID;
		}
	}
    PrintMem(VirtAddrPtr, 20);
    	
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: DoHash\n"));
	DoHash((const char*)VirtAddrPtr, CurTask);
	
	if (EpaConfig.InspectorUsecsCostEnable == ON) {
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in CPU clocks %d\n", CurTask->Cost));
		CurTask->Cost = ((CurTask->Cost * 1000000) / CpuFreq);
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Cost in microseconds %d\n", CurTask->Cost));
	}
	
  } else {
    DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Warning - Unexpected command in MeasureMemory %016LX \n", CurTask->Cmd));
    return INVALID;
  }
  
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: SHA256 hash: "));
  PrintMem(CurTask->Hash, SHA256_HASH_SIZE);
    
  CurTask->LastChecked = AsmReadTsc();
  BeforeClk = AsmReadTsc();
  CopyMem(CurTask->InspectorSig, EpaConfig.InspectorSig, sizeof(CurTask->InspectorSig)); // "Sign" the measurement
  AfterClk = AsmReadTsc();
  CurTask->Stat4.SmallStat[0] = (UINT32)(AfterClk - BeforeClk);
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector:Stat4.SmallStat[0] 0x%x\n", CurTask->Stat4.SmallStat[0]));
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: SHA256 hash actual time required: (Dec) %d.\n", CurTask->Cost));
  
  // Update nonce
  CurTask->Nonce = CurTask->Nonce ^ NONCE_VAL;
  
  return 0;
}

//
// This function takes a hash at the specified address (Ptr) for the length 
// specified in CurTask->Len
//
UINT64 DoHash(const char* Ptr, struct task_t *CurTask)
{
	INTN					InitComparison = 0;
	INTN 					Comparison = 0; 
	UINT8 					InitHash[SHA256_HASH_SIZE];
	UINT8 					LocalHash[SHA256_HASH_SIZE];
	VOID					*ShaHashCtx;
	UINTN					CtxSize;
	BOOLEAN					Status;
    UINT64					BeforeClk=0, AfterClk=0;
	Status = FALSE;
	ShaHashCtx = NULL;
	
    SetMem(&LocalHash, (SHA256_INTS *sizeof(UINT32)),0);
	SetMem(&InitHash,  (SHA256_INTS *sizeof(UINT32)), 0);
	
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: DoHash of addr %LX for length %d\n", Ptr, CurTask->Len));

	CtxSize = Sha256GetContextSize();
	ShaHashCtx = AllocatePool(CtxSize);

	if(ShaHashCtx == NULL)
		return 1;

	BeforeClk = AsmReadTsc();
	Status = Sha256Init(ShaHashCtx);
	Status = Sha256Update(ShaHashCtx, Ptr, (UINT32)CurTask->Len);
	Status = Sha256Final(ShaHashCtx, LocalHash);
	AfterClk = AsmReadTsc();
	
	CurTask->Cost = (AfterClk - BeforeClk);
	
	FreePool(ShaHashCtx);

	if(Status == FALSE)
		return 1;
	
	//
	// Check if Backend Manager passed in an empty hash
	//
    InitComparison = CompareMem(CurTask->Hash, InitHash, HMAC_SIZE);
    if (InitComparison == 0) { // Empty hash passed in
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Empty hash so initializing.\n"));
		CopyMem(CurTask->Hash, LocalHash, SHA256_HASH_SIZE); 
		CurTask->Result = INIT;
    } else { // Comparison hash passed in, now compare with hash we generated
		Comparison = CompareMem(CurTask->Hash, LocalHash, SHA256_HASH_SIZE);
		if (Comparison == 0) {
			// ok
			DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Comparison hash ok!\n"));
			CurTask->Result = UNCHANGED;
		} else { // not a match
			DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Warning: Bad hash!\n"));
			
			// print them out
			DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Received hash:\n"));
			PrintHash(CurTask->Hash,SHA256_INTS);
			CurTask->Result = CHANGED;
		}
	}

	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Hash bytes %02x %02x %02x %02x\n", LocalHash[0], LocalHash[1], LocalHash[2], LocalHash[3]));
	PrintMem(LocalHash, SHA256_HASH_SIZE);

	return 0;
}

// 
// For debug purposes only! Reconfigure Inspector
//
VOID
EFIAPI
InspectorConfig (
  IN  EFI_HANDLE                    DispatchHandle,
  IN  EFI_SMM_SW_DISPATCH_CONTEXT   *DispatchContext)
{
	UINT64							CommandAddr=0;
	UINT64*							Ptr64=&CommandAddr;
	UINT64							Rax = 0, Rbx = 0, Rcx = 0, Rdx = 0;
	EFI_STATUS                		Status = EFI_SUCCESS;
	UINT32							i = 0;
	EFI_SMM_CPU_PROTOCOL 			*mSmmCpu = NULL;
	struct InspectorConfig_t 		Config;
	UINT32							Found = 0;
	UINT64*							PhysAddrPtr=NULL;
	UINT64                          SmmRevId = 0;
	
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: InspectorConfig\n"));
	
	//
	// Use EfiSmmCpuProtocol to read SMRAM Save State Map
	//
    Status = gSmst->SmmLocateProtocol (
				     &gEfiSmmCpuProtocolGuid,
				     NULL,
				     (VOID **)&mSmmCpu
				     );
	ASSERT_EFI_ERROR (Status);
	if (EFI_ERROR(Status)) // For release builds
      return;
    //
    // Check all CPU threads for EPA_SMI_CMD on RAX. 
	// Once found: read Rax/Rbx/Rcx/Rdx and break to save time.
    //
    for (i=0; i < NumberOfEnabledProcessors; i++) {
		DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: Checking cpu %d.\n",i));				
		mSmmCpu->ReadSaveState (
					mSmmCpu,
					sizeof(UINT64),
					EFI_SMM_SAVE_STATE_REGISTER_RAX,
					i, //Which CPU to read from
					&Rax
					);	
    
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: RAX: 0x%016LX . RBX 0x%016LX. RCX 0x%016LX. RDX 0x%016LX\n", Rax, Rbx, Rcx, Rdx));
		if ((Rax & 0xFF)== INSPECTOR_CONF) {
			DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Found INSPECTOR_CONF on %d\n", i));
			Found = 1;	  
	  
			mSmmCpu->ReadSaveState ( 
			      mSmmCpu,
			      sizeof(UINT64),
			      EFI_SMM_SAVE_STATE_REGISTER_RBX,
			      i, //Which CPU to read from
			      &Rbx
			      );
			
			mSmmCpu->ReadSaveState (
			      mSmmCpu,
			      sizeof(UINT64),
			      EFI_SMM_SAVE_STATE_REGISTER_RDX,
			      i, //Which CPU to read from
			      &Rdx
			      );	  
			Ptr64 = (UINT64*)(UINTN)Rbx; 
			
			SmmRevId = (( EFI_SMM_CPU_STATE *)(gSmst->CpuSaveState[i]))->x64.SMMRevId;
			if( (Rdx & 0xFF) == MEASURE_XEN) { // Xen measurement specified
				if(SmmRevId != STM_SMM_REV_ID) { // Xen measurement specified but no STM present - error
					return;
				}

				ExecMonDesc[i].VmIndex = 0;
				Status = GetVmmInfo(i);
				if (EFI_ERROR(Status))
					return;
				XEN_VIRT = TRUE;
			}

			
			//
			// Address Parameter from Manager is in Rbx, fixme: sanity check RBX value
			//
			PhysAddrPtr = (UINT64*)(UINTN)VaToPhysWalk(i, (UINT64)Ptr64);  
  
			DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: RBX %Lx. Phys of RBX = %Lx\n", Ptr64, PhysAddrPtr));
			if (PhysAddrPtr == 0) {
				DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: No Config Bin found\n"));
				return;
			}
			CopyMem(&Config, PhysAddrPtr, (sizeof(struct InspectorConfig_t)));
	
			DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Incoming config:\n"));
			PrintConfig();
			break;
		}
		
	}
	
	//
	// If no config struct found
	//
	if (Found == 0) {
		DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: No config found!\n"));			
		return;
	}
	
	if (Rdx == MEASURE_XEN) {
		// Reset the state of the Executive monitor descriptor to avoid TOCTOU;
		SetMem((VOID*)(UINTN)ExecMonDesc[i].VmDescriptor, 0, sizeof(MLE_VMM_DESCRIPTOR));
	}
 	//

	
	//
	// Apply new config
	//
	CopyMem(&EpaConfig, &Config, sizeof(struct InspectorConfig_t));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Current config:\n"));
	PrintConfig();
	return;
}

//
// Print the current Inspector configuration
// 
VOID PrintConfig(VOID)
{
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Config\n"));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: HmacCreateEnable %x\n", EpaConfig.HmacCreateEnable));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: HmacCheckEnable %x\n", EpaConfig.HmacCheckEnable));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AesEncryptEnable %x\n", EpaConfig.AesEncryptEnable));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AesDecryptEnable %x\n", EpaConfig.AesDecryptEnable));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: CheckSmrrOverlapEnable %x\n", EpaConfig.CheckSmrrOverlapEnable));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: MaxMemoryHashSize 0x%x\n", EpaConfig.MaxMemoryHashSize));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: MaxTasks 0x%x\n", EpaConfig.MaxTasks));	
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: InspectorUsecsCostEnable 0x%x\n", EpaConfig.InspectorUsecsCostEnable));
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Inspector Signature:"));
	PrintHashBytes((UINT8*)EpaConfig.InspectorSig,SIGNATURE_SIZE);
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Manager Signature:"));
	PrintHashBytes((UINT8*)EpaConfig.ManagerSig,SIGNATURE_SIZE);
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: AES Key:"));
	PrintHashBytes(EpaConfig.Aes256CbcKey, AES_KEYSIZE/8);
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: HMAC Key:"));
	PrintHashBytes(EpaConfig.HmacKey,HMAC_KEY_LEN);
	return;
}

//
// The entrypoint to the Inspector's measurement request handler
//
VOID
EFIAPI
InspectorMain (
  IN  EFI_HANDLE                    DispatchHandle,
  IN  EFI_SMM_SW_DISPATCH_CONTEXT   *DispatchContext)
{
  UINT64						CommandAddr=0;
  UINT64*						Ptr64=&CommandAddr;
  UINT64 						EntryTsc;
  UINT32						NumTasks=0;
  UINT32                        BinSpace=0;
  UINT32 						IssuingProcessor = 0;
  BOOLEAN						OutsideSmm = TRUE;
  UINT32 						i = 0;
  UINT64						CurClock = 0;
  UINT8    						Ivec[AES_BLOCK_SIZE]={0};
  BOOLEAN            			HmacRet = FALSE;
  UINT32						EncryptRet = FALSE;    
  
  EntryTsc = AsmReadTsc();
  
  BinSpace = sizeof(struct task_t) * MAX_TASKS;
  SetMem(&Bin, BinSpace, 0); // Init bin
  
  //
  // Get the bin
  //
  Ptr64 = GetBin(Ptr64, &IssuingProcessor);
  if (Ptr64 ==0) {
    DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: No bin found.\n"));
    return;
  }
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: InspectorMain: IssuingProcessor %d.\n",IssuingProcessor ));
  //
  // MUST make sure bin is not within SMM memory. Fixme: Use CommBuffer
  // 
  OutsideSmm = SmmIsBufferOutsideSmmValid((UINTN)Ptr64,(sizeof(struct task_t)*MAX_TASKS) );
  if (OutsideSmm == FALSE) { 
	//
	// Ring0 Manager-provided bin address is inside SMM, security error!
	//
	DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Bin cannot be within SMM memory!"));
	return;
  }
  DEBUG((EFI_D_ERROR, "EPA-RIMM-Inspector: Bin at physical addr 0x%016LX on CPU %d\n", Ptr64, IssuingProcessor));
    
  //
  // Do each command in the bin
  //
  NumTasks = ProcessBin(IssuingProcessor);
  DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Number of tasks in bin 0x%x\n", NumTasks));
  
 	//
	// Write results back, but only if we got a valid memory address to begin with.
	//

	// !!!!!!!!!!!!!!!!!!!!!!
	// Need to make sure to do this securely (e.g. don't let an attacker overwrite SMM memory!)
	// !!!!!!!!!!!!!!!!!!!!!!

	Bin[0].Stat1.BigStat = EntryTsc;
	Bin[0].Stat2.BigStat = AsmReadTsc();
	Bin[0].Stat5.BigStat = mGetVmmInfoBefore;
	Bin[0].Stat6.BigStat = mGetVmmInfoAfter;
	CurClock = AsmReadTsc();
	CopyMem(Ivec, &CurClock, sizeof(CurClock)); // fixme get true random
	CurClock = AsmReadTsc();
	CopyMem(Ivec+8, &CurClock, sizeof(CurClock)); // fixme get true random
	
	// Set ivec in each task result
	for (i=0; i < NumTasks; i++) {
		CopyMem(&Bin[i], Ivec, AES_BLOCK_SIZE); // First 16 bytes are Ivec in plaintext
	}
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Set Ivec to = %Lx %Lx\n", Bin[0].Ivec1, Bin[0].Ivec2));
	
	if (EpaConfig.HmacCreateEnable == ON) {
		DEBUG ((EFI_D_ERROR, "\nEPA-RIMM-Inspector: Going to HMAC in InspectorMain.\n"));
		if (gHmacCtx == NULL) {
			DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: HMAC context is null! Exiting.\n"));
			return;
		}
		
		for (i=0; i < NumTasks; i++) {
			HmacRet = HmacSha256Init(gHmacCtx, EpaConfig.HmacKey, HMAC_KEY_LEN);
			if (HmacRet == FALSE) {
				DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Unable to HmacSha256Init\n"));
				return;
			}
			
			HmacRet = HmacSha256Update(gHmacCtx, &(Bin[i]), sizeof(struct task_t) - HMAC_SIZE); // HMAC the task except for hmac part at the end (skip the last 32 bytes), assumes HMAC at end of task with nothing following it 
			if (HmacRet == FALSE) {
				DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Unable to HmacSha256Update\n"));
				return;
			}
			
			HmacRet = HmacSha256Final(gHmacCtx, Bin[i].Hmac);
			if (HmacRet == FALSE) {
				DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Unable to HmacSha256Final\n"));
				return;
			}
		}
	}
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Printing bin\n"));
	PrintBin();
	//
	// Don't write to Bin[] after you encrypt, otherwise it gets corrupted! 
	//
	
	EncryptRet = EncryptTasks(); 
	if (EncryptRet != EFI_SUCCESS) {
		DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Unable to EncryptTasks\n"));
		return;
	}
	//
	// No more editing of encrypted bin contents
	//
	DEBUG ((EFI_D_ERROR, "EPA-RIMM-Inspector: Copying results to Ring0 Manager\n"));
	CopyMem(Ptr64, &Bin[0], (sizeof(struct task_t)*NumTasks)); 
	
	return;
}

//
// Print out a hash in human readable format
//
VOID PrintHash(UINT32 Hash[], UINT32 NumInts)
{
  UINT32 i=0;
  for (i = 0; i < NumInts; i++) {
    DEBUG((EFI_D_ERROR, "%x ", Hash[i]));
  }
  
  DEBUG((EFI_D_ERROR, "\n"));
}

//
// Print a hash as hex bytes
//
VOID PrintHashBytes(UINT8 Hash[SHA256_HASH_SIZE], UINT32 NumBytes)
{
	UINT32 i=0;
	DEBUG((EFI_D_ERROR, "\nHash Bytes\n"));
	for (i=0; i < NumBytes; i++) {
		DEBUG((EFI_D_ERROR, " %02x ", Hash[i]));
	}
	DEBUG((EFI_D_ERROR, "\n"));
	return;
}

//
// Return the APIC ID for the current processor (allows identifying the particular processor thread this code is running on)
//
UINT32
EFIAPI
GetApicId (
	   IN VOID *Buffer
	   )
{
  UINT32					RegEbx;
  UINT32					ApicID=0;
  
  AsmCpuid (0x1, NULL, &RegEbx, NULL, NULL);
  ApicID = RegEbx >>24;
  DEBUG((EFI_D_ERROR, "\nEPA-RIMM-Inspector: APIC ID %d\n", ApicID));
  return ApicID;
}
