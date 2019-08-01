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
// The Ring 0 Manager serves as an interface between the SMM Inspector and EPA Frontend
// 
// It:  
// - Receives tasks (one by one) from the EPA Frontend, places them into an array of tasks ("bin")
// - Generates an SMI with the address of the bin to trigger the SMM Inspector to do a measurement  
// - Provides measurement results back to EPA Frontend
// 
// ==================================================================


#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/irqflags.h>
#include <asm/xen/hypercall.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/string.h>
#include "ring0manager.h"

#define VERBOSE 1   // Print all debug output in Linux system log (disable for benchmarks) 
//#define SHOW_BIN_PERF // Just print out total bin times and nothing else during runtime 
//#define DEBUG_EARLY_EXIT 1 // For debugging EPA-Frontend -> Ring 0 communication (e.g. receive input from EPA-FRONTEND but don't act upon it)
//#define DISABLE_INT // Disable interrupts before/after the SMI, (optional) for benchmarking Xen
//#define STMPERF // Get STM perf stats

int task_slot = 0; // An index into the tasklist array
int stat_slot = 0;
struct task_t tasklist[MAX_TASKS]={{0}};   // List of tasks received. 
struct page *rPage = NULL;
struct ring0Stats binCosts[MAX_STATS]={{0}};
uint32_t statsarray[1000] = {0};

/*
  Add the task to the tasklist[]
*/
int addToTasklist(struct task_t cur_task)
{
  if (task_slot == MAX_TASKS) {
    printk("\nWarning, ran out of space on tasks, skipping.\n");
    return -1;
  }
#ifdef VERBOSE
  printk("\nAdding Cmd:%Lx VA:%Lx Operand:%Lx Ivec %Lx %Lx", cur_task.cmd, cur_task.virt_addr, cur_task.operand, cur_task.ivec1, cur_task.ivec2);
#endif
  tasklist[task_slot]=cur_task;
  task_slot++;
  return 0;
}

ssize_t write_proc_file_stats(struct file* file, const char __user* user_buffer, size_t count, loff_t *data)
{
   char buffer[MAX_PROCSTAT_CMD_LEN];
   struct ring0Stats statentry = {0};
   copy_from_user(buffer, user_buffer, MAX_PROCSTAT_CMD_LEN);
   memcpy(&statentry, buffer, sizeof(struct ring0Stats));

   printk("\nReceived %Lx %Lx %Lx on write proc stats", statentry.cmd, statentry.start, statentry.end); 

   // Clear out stats
   stat_slot = 0; 
   memset(binCosts, 0, sizeof(struct ring0Stats)*MAX_STATS);
   return count;
}

/*
  Receive a task or measurement trigger from EPA Frontend
*/
ssize_t write_proc_file(struct file* file, const char __user* user_buffer, size_t count, loff_t *data)
{
  char buffer[MAX_PROC_CMD_LEN];
  struct task_t cur_task = {0};

  // Get user paramters
  copy_from_user(buffer, user_buffer, MAX_PROC_CMD_LEN);
  memcpy(&cur_task, buffer, sizeof(struct task_t));

#ifdef DEBUG_EARLY_EXIT
  printk("\nEXITING WITHOUT SMI GENERATION DUE TO DEBUG_EARLY_EXIT\n");
  return count; // Return early to debug output without actually triggering an SMI
#endif
  
  switch (cur_task.cmd) {
  case SEND_BIN: // Going to trigger SMI for Inspector
#ifdef VERBOSE
    printk("\nReceived trigger command and task_slot==%d", task_slot );
    printBin();
#endif
    sendSmiBuf();
#ifdef STMPERF
    queryStmPerf();
#endif
    break;
  default: // Add task to bin
#ifdef VERBOSE
    printk("\nAdded task to bin");
#endif
    addToTasklist(cur_task);
    break;
  }

  return count;
}

/*
  Lookup the command for a cleaner printout
*/
int lookupCommand(uint64_t cmd)
{
  switch (cmd) {
  case CHECK_MSR:
    printk("MSR ");
    break;
  case CHECK_REG:
    printk("Register ");
    break;
  case HASH_MEM_VIRT:
    printk("Memory Region - Virtual ");
    break;
  case HASH_MEM_PHYS:
    printk("Memory region - Physical ");
    break;
  default:
    printk("Unknown command! %Lx", cmd);
    break;
  }
  return 0;
}
/*
  Print all tasks in bin
*/
int printBin(void)
{
  int i=0;
  int j=0;

  printk("\nPrinting bin...");
  for (i=0; i < MAX_TASKS; i++) {

    if (tasklist[i].cmd !=0) { // skip empty slots
      printk("\nTask %d\n", i);
      printk("\nIV \t\t\t0x%Lx 0x%Lx\n", tasklist[i].ivec1, tasklist[i].ivec2);
      printk("\nCommand\t\t\t0%Lx\n", tasklist[i].cmd);
      printk("\nOperand\t\t\t0x%Lx\n", tasklist[i].operand);
      printk("Virtual Address\t\t0x%Lx\n", tasklist[i].virt_addr);
      printk("Phys Address\t\t0x%Lx\n", tasklist[i].phys_addr);
      printk("Length \t\t\t0x%Lx\n", tasklist[i].len);
      printk("Result\t\t\t0x%Lx\n", tasklist[i].result);
      printk("Nonce\t\t\t0x%Lx\n", tasklist[i].nonce);
      printk("Cost\t\t\t%Lx\n", tasklist[i].cost);
      printk("Task UUID\t\t%Lx\n", tasklist[i].task_uuid);
      printk("Reserved1\t\t%Lx\n",tasklist[i].reserved1);
      printk("Stat0.bigstat\t\t%llu\n", tasklist[i].Stat0.bigstat);
      printk("Stat1.bigstat\t\t%llu\n", tasklist[i].Stat1.bigstat);
      printk("Stat2.bigstat\t\t%llu\n", tasklist[i].Stat2.bigstat);
      printk("Stat3.bigstat\t\t%llu\n", tasklist[i].Stat3.bigstat);
      printk("Stat4.bigstat\t\t%llu\n", tasklist[i].Stat4.bigstat);
      printk("Stat5.bigstat\t\t%llu\n", tasklist[i].Stat5.bigstat);
      printk("Stat6.bigstat\t\t%llu\n", tasklist[i].Stat6.bigstat);
      printk("Stat0.smallstats\t\t%u %u\n", tasklist[i].Stat0.smallstat[0], tasklist[i].Stat0.smallstat[1]);
      printk("Stat1.smallstats\t\t%u %u\n", tasklist[i].Stat1.smallstat[0], tasklist[i].Stat1.smallstat[1]);
      printk("Stat2.smallstats\t\t%u %u\n", tasklist[i].Stat2.smallstat[0], tasklist[i].Stat2.smallstat[1]);
      printk("Stat3.smallstats\t\t%u %u\n", tasklist[i].Stat3.smallstat[0], tasklist[i].Stat3.smallstat[1]);
      printk("Stat4.smallstats\t\t%u %u\n", tasklist[i].Stat4.smallstat[0], tasklist[i].Stat4.smallstat[1]);
      printk("Stat5.smallstats\t\t%u %u\n", tasklist[i].Stat5.smallstat[0], tasklist[i].Stat5.smallstat[1]);
      printk("Stat6.smallstats\t\t%u %u\n", tasklist[i].Stat6.smallstat[0], tasklist[i].Stat6.smallstat[1]);
      printk("Hash:\t\t\t");
      for (j=0; j < SHA256_INTS; j++) { 
        printk(KERN_CONT"%x ", tasklist[i].hash[j]);
      }
      printk("\n");
      
      printk("Manager Signature:\t");
      for (j=0; j < SIGN_INTS; j++) {
        printk(KERN_CONT"%02x", tasklist[i].manager_sig[j]);
      }
      printk("\n");
	  
      printk("Inspector Signature:\t");
      for (j=0; j < SIGN_INTS; j++) {
        printk(KERN_CONT"%02x", tasklist[i].inspector_sig[j]);
      }

      printk("\nHMAC\t\t\t");
      for (j=0; j < HMAC_SIZE; j++) {
	printk(KERN_CONT"%02x", tasklist[i].Hmac[j]);
      }
      printk("\n\n");
    }
  }
  
  return 0;
}

#ifdef DISABLE_INT
/*
  Interrupt the rest of the cores
*/
static void interrupt_rest(void *data) {

  spinlock_t *lock;
  lock = data;

  while(!spin_trylock(lock)){ };
}
#endif

/*
  Debug function to configure Inspector
 */
int sendEpaConfig(struct epa_config_t *epaConfig)
{
  uint64_t addr=0; // Address of buffer that will be sent to SMM
  
  uint8_t val=INIT;
  uint16_t port=APM_CNT;
  uint64_t virt=XEN_VIRT;
  
#if (XEN_VIRT==0x01)
      addr = (unsigned long)HYPERVISOR_copy_to_xen(sizeof(struct epa_config_t), (void*)epaConfig);
#else

      memcpy(rPage, epaConfig, (sizeof(struct epa_config_t)));;
      addr = (uint64_t)rPage;
#endif

      printk("\nAddress of rPage = %Lx\n", addr);
  // Generate SMI to send config to Inspector and provide physical address of config page
  asm volatile (
                "movq %1, %%rbx; \
                 movq %3, %%rdx; \
                 outb %0, %2;\n\t" // %0 = val below, %2 = port
                :
                : "a"(val),"rbx"(addr), "Nd"(port), "rdx"(virt)
                : "rbx"
                );

  // We're back from SMM now
  return 0;

}

/*
  Send an SMI to the SMM Inspector
*/
int sendSmiBuf(void)
{
  uint64_t addr=0; // Address of buffer that will be sent to SMM
  ticks before=0, after=0;
  uint8_t val=MEASUREMENT; 
  uint16_t port=APM_CNT;
  uint64_t virt=XEN_VIRT;

#ifdef DISABLE_INT
  spinlock_t lock;
#endif
  
#if (XEN_VIRT==0x01)
    if (task_slot <= 4096/sizeof(struct task_t)) {
      addr = (unsigned long)HYPERVISOR_copy_to_xen(sizeof(struct task_t)*task_slot, (void*)tasklist);
    } else {
      addr = (unsigned long)HYPERVISOR_copy_to_xen(sizeof(struct task_t)*MAX_TASKS, (void*)tasklist);
      printk("\nWARNING - task slot too high for 4K page! Just copying MAX_TASKS");
    }
#else
    memset(rPage, 0, 4096);

    if (task_slot <= 4096/sizeof(struct task_t)) {
      memcpy(rPage, tasklist, (sizeof(struct task_t)* task_slot));
    } else {
      memcpy(rPage, tasklist, sizeof(struct task_t)*MAX_TASKS);
      printk("\nWARNING - task slot too high for 4K page! Just copying MAX_TASKS");
    }
  
    addr = (uint64_t)rPage;
#endif

#ifdef DISABLE_INT
    spin_lock_init(&lock);
    spin_lock(&lock);
    smp_call_function(interrupt_rest, &lock, 0);
    local_irq_disable();
#endif

  before = getticks();
  
  // Generate SMI to send bin to Inspector and provide physical address of bin
  asm volatile (
                "movq %1, %%rbx; \
                 movq %3, %%rdx; \
                 outb %0, %2;\n\t" // %0 = val below, %2 = port
                :
                : "a"(val),"rbx"(addr), "Nd"(port), "rdx"(virt)
                : "rbx"
		);

  // We're back from SMM now

  after = getticks();

#ifdef DISABLE_INT
    local_irq_enable();
    spin_unlock(&lock);
    //on_each_cpu(enable_nmi, NULL, 1);
#endif


  if (stat_slot < MAX_STATS) {
    binCosts[stat_slot].start = before;
    binCosts[stat_slot].end = after;
    stat_slot++;
  } else {
    printk("\nRan out of stat space!\n");
  }
  
#if defined(VERBOSE) || defined (SHOW_BIN_PERF)
  printk("SMI time: %llu clocks %llu %llu\n", after-before, after, before);
#endif
  
  // Update global bin with local bin contents
#if (XEN_VIRT==0x01)
    HYPERVISOR_copy_from_xen(sizeof(struct task_t)*MAX_TASKS, tasklist, (void*)addr);
#else
    memcpy(tasklist, rPage, (sizeof(struct task_t)*MAX_TASKS));
#endif
  printBin();
  return 0;
}

/*
 * save Stm Stats to ring0Stat proc
 */
void saveStmPerf(perf_data_entry *data, uint32_t len) {

  uint32_t i;
  int cur_slot = stat_slot - 1;

  if (cur_slot < MAX_STATS) {
    printk("\nSaving STM perf to ring0stat");
    for (i=0; i<len; i++) {
      binCosts[cur_slot].stmPerf[i].StartTimeStamp    = data[i].StartTimeStamp;
      binCosts[cur_slot].stmPerf[i].EndTimeStamp      = data[i].EndTimeStamp;
      binCosts[cur_slot].stmPerf[i].DeltaofTimeStamp  = data[i].DeltaofTimeStamp;
      binCosts[cur_slot].stmPerf[i].CpuIndex          = data[i].CpuIndex;
      binCosts[cur_slot].stmPerf[i].Reason            = data[i].Reason;
      strlcpy(binCosts[cur_slot].stmPerf[i].Token, data[i].Token, sizeof(data[i].Token));
      strlcpy(binCosts[cur_slot].stmPerf[i].StartDescription, data[i].StartDescription, sizeof(data[i].StartDescription));
      strlcpy(binCosts[cur_slot].stmPerf[i].EndDescription, data[i].EndDescription, sizeof(data[i].EndDescription));
    }
  } else {
    printk("\nRan out of stat space!\n");
  }
}


/*
 * Print STM Performance Data
 */
void printStmPerf(perf_data_entry *data, uint32_t len) {

  uint32_t i;

  for (i=0; i<len; i++) {
    printk("StmPerfData\n");
    printk(" StartTimeStamp    : %llu\n", data[i].StartTimeStamp);
    printk(" EndTimeStamp      : %llu\n", data[i].EndTimeStamp);
    printk(" DeltaofTimeStamp  : %llu\n", data[i].DeltaofTimeStamp);
    printk(" CpuIndex          : %x\n", data[i].CpuIndex);
    printk(" Reason            : %x\n", data[i].Reason);
    printk(" Token             : %s\n", data[i].Token);
    printk(" StartDesc         : %s\n", data[i].StartDescription);
    printk(" EndDesc           : %s\n", data[i].EndDescription);
  }
}


/*
 * Query STM for perf data
 * 1. allocate a dom page
 * 2. do a hypercall request for xen to query stm
 * 3. collect the data in the previously allocated page
 * 4. Print data
 */
void queryStmPerf(void)
{
  
#if (XEN_VIRT==0x01)
  uint32_t len = MAX_STM_STATS; 
  uint64_t addr = 0;
  struct page *perfPage = NULL;
  perfPage = __get_free_page(GFP_KERNEL);
  if (!perfPage) {
    printk("\nError in perfPage alloc_page");
  } else {
    memset(perfPage, 0, 4096);
    addr = perfPage;
    printk("Perfpage : %x\n", addr);
    HYPERVISOR_get_stm_perf((void*)addr);
    saveStmPerf((void*)addr, len);
    printStmPerf((void*)addr, len);
  }
  free_page(perfPage);
#endif
}


/*
  Register proc file interfaces
*/
static const struct file_operations proc_file_fops = {
  .owner   = THIS_MODULE,
  .read    = seq_read,        // EPA Frontend reads measurement results from here
  .write   = write_proc_file, // EPA Frontend writes measurement tasks to be performed to here
  .open    = ring0m_proc_open, 
  .release = single_release,
};

static const struct file_operations proc_file_fops_stats = {
  .owner   = THIS_MODULE,
  .read    = seq_read,        // EPA Frontend reads stats results from here
  .write   = write_proc_file_stats, // EPA Frontend writes 
  .open    = ring0m_proc_open_stats, 
  .release = single_release,
};

/*
  Generate a basic SMI 
*/
static inline void myoutb(uint16_t port, uint8_t val)
{
    asm volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}

/*
  Initialize the kernel module and the SMM Inspector
*/
static int __init ring0manager_init(void)
{
  static struct proc_dir_entry *procfile=NULL;
  static struct proc_dir_entry *procfileStats=NULL;
  struct epa_config_t epaConfig;
  uint8_t Aes256CbcKey[AES_KEYSIZE/8] = {0};
  uint8_t HmacKey[HMAC_KEY_LEN] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			   	   0x0b, 0x0b, 0x0b, 0x0b};
  
  printk("\nLoading ring0manager kernel module.\n");
  procfile=proc_create("ring0manager", 0666, NULL,  &proc_file_fops);
  if (procfile ==NULL) {
	printk("\nWarning, unable to create procfile");
  }
  procfileStats = proc_create("ring0stats", 0666, NULL, &proc_file_fops_stats);
  if (procfileStats == NULL) {
    printk("\nWarning, unable to create stats procfile");
    
  }
  printk("\nSizeof task_t %lu", sizeof(struct task_t));
  printk("\nMAX_TASKS = %u", MAX_TASKS);
  printk("\n-----ring0manager start session-----\n");
  memset(tasklist, 0, (sizeof(struct task_t)*MAX_TASKS));

  rPage = (struct page*)__get_free_page(GFP_KERNEL);
  if (!rPage) {
    printk("\nError doing alloc_page");
  }
  
  printk("\nGoing to configure inspector\n");
  epaConfig.HmacCreateEnable = OFF;
  epaConfig.HmacCheckEnable = OFF;
  epaConfig.AesEncryptEnable = ON;
  epaConfig.AesDecryptEnable = ON;
  epaConfig.CheckSmrrOverlapEnable = ON;
  epaConfig.InspectorUsecsCostEnable = ON;
  epaConfig.MaxMemoryHashSize = 0x1000000;
  epaConfig.MaxTasks = 14;
  memcpy(&epaConfig.InspectorSig, "INSPECTOR12345678901", SIGN_INTS * sizeof(uint32_t));
  memcpy(&epaConfig.ManagerSig,   "MANAGER1234567890123", SIGN_INTS * sizeof(uint32_t)); // fixme
  memcpy(&epaConfig.Aes256CbcKey, Aes256CbcKey, AES_KEYSIZE/8);
  memcpy(&epaConfig.HmacKey, HmacKey, HMAC_KEY_LEN);
  printk("\nSending the config...");
  sendEpaConfig(&epaConfig);
  return 0;
}

/*
  Measure time (from www.fftw.org/cycle.h) 
*/
static __inline__ ticks getticks(void)
{
  unsigned a,d;
  asm volatile("rdtsc" : "=a"(a), "=d" (d));
  return ((ticks)a | ((ticks)d) << 32);

}

/*
  Cleanup
*/
static void __exit ring0manager_exit(void)
{
  printk("-----ring0manager end session-----\n");
  remove_proc_entry("ring0manager", NULL);
  remove_proc_entry("ring0stats", NULL);
  if (rPage != NULL) {
    free_page(rPage);
    rPage = NULL;
  }
  printk("Exiting ring0manager\n");
}

/*
   Ring0 Manager -> EPA Frontend
   Provide results back to Python code, send all tasks in bin 
*/
static int ring0m_proc_show(struct seq_file *m, void *v) {
  int i=0;

  // Return all tasks in bin to Ring3 code
  for (i=0; i < task_slot; i++) {
    seq_write(m, &(tasklist[i]), sizeof(struct task_t) ); 
  }

  // Clear out stored tasks
  memset(tasklist, 0, (sizeof(struct task_t)*MAX_TASKS));
  task_slot=0;
  return 0;
}

static int ring0m_proc_show_stats(struct seq_file *m, void *v) {
  int i =0;

  printk("\nGoing to return stats to FEM. stat_slot = %u", stat_slot);
  for (i=0; i < stat_slot; i++) {
    seq_write(m, &(binCosts[i]), sizeof(struct ring0Stats) );
    printk("\nStart: %llu End: %llu", binCosts[i].start, binCosts[i].end);
  }
  stat_slot = 0;
  return 0;
}

static int ring0m_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, ring0m_proc_show, NULL);
}

static int ring0m_proc_open_stats(struct inode *inode, struct  file *file) {
  return single_open(file, ring0m_proc_show_stats, NULL);
}
 
MODULE_LICENSE("GPL"); 
module_init(ring0manager_init);
module_exit(ring0manager_exit);
