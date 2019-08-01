[Defines]
  PLATFORM_NAME                  = EPARimm
  BASE_NAME                      = EPARimm
  PLATFORM_GUID                  = 4d42afe4-a447-4a47-8de4-ca9b706558ea
  PLATFORM_VERSION               = 1.0
  MODULE_TYPE                    = DXE_SMM_DRIVER
  ENTRY_POINT                    = inspector_init
  PI_SPECIFICATION_VERSION       = 0x0001000A
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/EPARimm
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  SUPPORTED_ARCHITECTURES        = X64

[LibraryClasses]
	 BaseLib|MdePkg/Library/BaseLib/BaseLib.inf 
	 UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
	 DxeSmmDriverEntryPoint|IntelFrameworkPkg/Library/DxeSmmDriverEntryPoint/DxeSmmDriverEntryPoint.inf
	 MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
	 SmmServicesTableLib|MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib.inf
	 UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
	 DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
	 DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf

[LibraryClasses.X64.DXE_SMM_DRIVER]
	BaseCryptLib|CryptoPkg/Library/BaseCryptLib/SmmCryptLib.inf
	SmmServicesTableLib|MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib.inf
	MemoryAllocationLib|MdePkg/Library/SmmMemoryAllocationLib/SmmMemoryAllocationLib.inf
	#LockBoxLib|MdeModulePkg/Library/SmmLockBoxLib/SmmLockBoxSmmLib.inf
	PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
	SmmMemLib|MdePkg/Library/SmmMemLib/SmmMemLib.inf
	BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
	UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
	SerialPortLib|MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
	SmmCryptLib|CryptoPkg/Library/BaseCryptLib/SmmCryptLib.inf
	PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
	IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
	OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf
	IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
	!if $(TARGET) != RELEASE
		DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
	!endif
 
[Components.X64]
   EPARimm/EPARimm.inf
   
