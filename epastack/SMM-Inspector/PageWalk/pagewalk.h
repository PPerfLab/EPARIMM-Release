#define IA32_PG_P 	 1u
#define IA32_PG_PS  (1u << 7)
#define CR0_PG      (1u <<31)
#define CR4_PAE	     (1u << 5)
#define CR4_PSE      (1u << 4)

/**
  Shifts a 64-bit integer right between 0 and 63 bits. This high bits are
  filled with zeros. The shifted value is returned.

  This function shifts the 64-bit value Operand to the right by Count bits. The
  high Count bits are set to zero. The shifted value is returned.

  If Count is greater than 63, then ASSERT().

  @param  Operand The 64-bit operand to shift right.
  @param  Count   The number of bits to shift right.

  @return Operand >> Count

**/
UINT64
EFIAPI
RShiftU64 (
  IN      UINT64                    Operand,
  IN      UINTN                     Count
  );
  
UINT64
EFIAPI
InternalMathRShiftU64 (
  IN      UINT64                    Operand,
  IN      UINTN                     Count
  );
  
UINT32
EFIAPI
SwapBytes32 (
  IN      UINT32                    Value
  );

UINT16
EFIAPI
SwapBytes16 (
  IN      UINT16                    Value
  );
  
UINT64
TranslateGuestLinearToPhysical (
  IN UINTN    Cr3,
  IN UINTN    Cr0,
  IN UINTN    Cr4,
  IN UINT64   Efer,
  IN UINTN    GuestLinearAddress,
  OUT BOOLEAN *Ia32e,
  OUT BOOLEAN *Pg,
  OUT BOOLEAN *Pae,
  OUT BOOLEAN *Pse,
  OUT BOOLEAN *Sp,
  OUT UINT64  **Entry
  );