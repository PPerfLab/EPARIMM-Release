// ==================================================================
// Copyright (C) 2016-2019 Portland State University
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// ------------------------------------------------------------------
//
// EPA-RIMM Team
// June 20, 2019
// 
// ==================================================================


// Constants
#define OFF                 0
#define ON                  1
#define SHA256_INTS 	    8
#define SIGN_INTS           5
#define MAX_TASKS          14
#define MAX_STATS         100
#define MAX_STM_STATS       4
#define MAX_PROCSTAT_CMD_LEN 344
#define MAX_PROC_CMD_LEN  300 // max length of string sent to /proc file
#define APM_CNT          0xB2 // Chipset port to generate SMI
#define HMAC_KEY_LEN       20
#define HMAC_SIZE          32
#define AES_KEYSIZE       256

typedef unsigned long long ticks;

// SMM Inspector Commands
#define CHECK_REG        0x10
#define HASH_MEM_VIRT    0x13
#define HASH_MEM_PHYS    0x14
#define CHECK_MSR        0x42
#define CHECK_IDTR_IDT   0x43

// The SMM Inspector registers these two values to be handled on write to port 0xB2
#define MEASUREMENT      0x88
#define INIT             0x89

// Ring 0 Manager Commands
#define GET_BINCOST_CMD  0x11
#define SEND_BIN         0x33
#define CONFIGURE_INSPECTOR 0x50


// For Virtualization
// XEN_VIRT 0x00 - for native OS environment
// XEN_VIRT 0x01 - for virtualized environment
#define XEN_VIRT         0x00

// Important: This needs to match the SMM Inspector's version *exactly* including packing
#pragma pack(1)
typedef struct
{
  uint64_t  StartTimeStamp;
  uint64_t  EndTimeStamp;
  uint64_t  DeltaofTimeStamp;
  uint32_t  CpuIndex;
  uint32_t  Reason;
  char      Token[16];
  char      StartDescription[16];
  char      EndDescription[16];

}perf_data_entry;


typedef union Stat{
  uint32_t smallstat[2];
  uint64_t bigstat;
} Stat_t;


struct task_t
{
  // Plaintext
  uint64_t ivec1;
  uint64_t ivec2;

  // Encrypted
  uint64_t cmd;                  // Measurement command (e.g. MSR, mem, register)
  uint64_t operand;              // For MSRs/Registers, specify which one to measure
  uint64_t virt_addr;            // For virtual mem measurements
  uint64_t phys_addr;            // For phys mem measurements
  uint64_t len;                  // For mem measurements, size to hash
  uint64_t result;               // Task measurement result
  uint64_t nonce;                // Nonce value to help prevent replay attacks
  uint64_t cost;                 // Task measurement cost in clocks
  uint64_t priority;             // Unused
  uint64_t last_checked;         // RDTSC time of last check
  uint64_t task_uuid;            // Unique task id
  uint64_t reserved1;            // Reserved field
  uint32_t hash[SHA256_INTS];      // 32 byte SHA256 hash
  uint32_t manager_sig[SIGN_INTS];   // 20 bytes Backend signature
  uint32_t inspector_sig[SIGN_INTS]; // 20 bytes Inspector signature
  union Stat Stat0;
  union Stat Stat1;
  union Stat Stat2;
  union Stat Stat3;
  union Stat Stat4;
  union Stat Stat5;
  union Stat Stat6;
  uint8_t  Hmac[HMAC_SIZE];
};

struct ring0Stats
{
  uint64_t cmd;
  uint64_t start;
  uint64_t end;
  perf_data_entry stmPerf[MAX_STM_STATS];
};

struct epa_config_t
{
  uint8_t HmacCreateEnable;
  uint8_t HmacCheckEnable;
  uint8_t AesEncryptEnable;
  uint8_t AesDecryptEnable;
  uint8_t CheckSmrrOverlapEnable;
   uint8_t InspectorUsecsCostEnable;
  uint32_t MaxMemoryHashSize; 
  uint32_t MaxTasks; 
  uint32_t InspectorSig[SIGN_INTS]; 
  uint32_t ManagerSig[SIGN_INTS]; 
  uint8_t Aes256CbcKey[AES_KEYSIZE/8]; 
  uint8_t HmacKey[HMAC_SIZE]; 
};

#pragma pack()

int addToTasklist(struct task_t cur_task);
int sendSmiBuf(void);
int sendEpaConfig(struct epa_config_t *epaConfig);
static __inline__ ticks getticks(void);
static inline void myoutb(uint16_t port, uint8_t val);
int printBin(void);
int lookupCommand(uint64_t cmd);
void queryStmPerf(void);
void printStmPerf(perf_data_entry *data, uint32_t len);
void saveStmPerf(perf_data_entry *data, uint32_t len);

// Kernel module initialization / cleanup
static int ring0m_proc_show(struct seq_file *m, void *v);
static int ring0m_proc_open(struct inode *inode, struct  file *file);
static int ring0m_proc_show_stats(struct seq_file *m, void *v);
static int ring0m_proc_open_stats(struct inode *inode, struct  file *file);
static int __init ring0manager_init(void);
static void __exit ring0manager_exit(void);

#ifdef DISABLE_INT
static void interrupt_rest(void *data);
#endif
