# EPA-RIMM

Welcome to the EPA-RIMM prototype code release landing page!

EPA-RIMM is a research project of the PPerfLab group under the direction of Dr. Karen Karavanic at Portland State University's Department of Computer Science.  *This material is based upon work supported by the National Science Foundation under Grant No. 1528185. Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the National Science Foundation.*

EPA-RIMM stands for Extensible, Performance-Aware Runtime Integrity Measurement Mechanism. RIMMs perform measurements during system runtime to identify deviations from the expected state. EPA-RIMM manages and performs kernel/hypervisor inspection for rootkit detection. It runs in firmware in System Management Mode (SMM) to protect itself from a potentially compromised OS. What makes our RIMM extensible and performance-aware is the way it supports a flexible measurement API and limits the amount of time spent in SMM to reduce perturbation.

EPA-RIMM is an architecture. This software is a prototype of the architecture. The prototype is developed for research purposes and is not suitable for production use. It has not been through security reviews. 

The prototype contains firmware, kernel, and application layer code. The firmware is written for the MinnowBoard open firmware platform.

* Please use the following reference for this code:  
  Brian Delgado, John Fastabend, Tejaswini Vibhute, and Karen L. Karavanic, "EPA-RIMM : An Efficient, Performance-Aware Runtime Integrity Measurement Mechanism for Modern Server Platforms" 2019 IEEE/IFIP International Conference on Dependable Systems and Networks (DSN 2019), June 2019, Portland OR.
* For documentation on building and running the lower layers of the prototype (SMM Inspector and Ring0 Manager), see the [User Guide](User-Guide-Release-20190731.pdf). 
* For documentation on using the upper layers of the prototype (Frontend Manager, Backend Manager, and Diagnosis Manager), continue reading this readme. 
* Additional work on this project can be found at: http://web.cecs.pdx.edu/~karavan/research/eparimm.html.

## Environment

#### Firmware

[EDK II](https://github.com/tianocore/edk2) (AKA EDK2 or TianoCore) is an open-source implementation of UEFI written in C. We augment it with our SMM Inspector.

The build environment for EDK II is Windows with Visual Studio 2015. Compiling with GCC may work but is untested. 

Additional dependencies for building firmware with EDK II are listed in our [User Guide](User-Guide-Release-20190731.pdf), section 3.1.

#### MinnowBoard

This document assumes you are running all components on a [MinnowBoard](<https://minnowboard.org/compare-boards/>). We used a DediProg and its accompanying software to flash the firmware.

The MinnowBoard should run Linux.

#### Python

The Diagnosis Manager (DM), Backend Manager (BEM), and Frontend Manager (FEM) are written in Python.

Python 2.7

Two additional libraries are required and can be installed via pip:

1. pycrypto (2.6.1 tested)
2. PyYAML (5.1.1 tested)

All Python requirements can be installed by using a [virtual environment](<https://virtualenv.pypa.io/en/latest/>) with `pip install -r requirements.txt`

#### KASLR and kallsyms

In order to specify a memory region to check, you need to know the start and end memory address of the kernel code. This can be found in `/proc/kallsyms` (viewed with `sudo` privileges) next to the `_stext` and `_etext` symbols. Kernel Address Space Layout Randomization (KASLR) will randomize these values on every boot. Disabling KASLR will cause them to remain static.

EPA-RIMM will work with KASLR enabled, but for ease of testing, it is useful to disable it. This avoids the need to re-provision hashes for memory Checks after each reboot. KASLR can be disabled by adding `nokaslr` to the `GRUB_CMDLINE_LINUX_DEFAULT`variable in the file `/etc/default/grub` on the monitored node. (e.g. `GRUB_CMDLINE_LINUX_DEFAULT="quiet splash nokaslr"`). Then type `sudo update-grub` and reboot to make it take effect. 

## SMM Inspector

The SMM Inspector is written in C. It is added to the EDK II package, which must then be built and flashed to a MinnowBoard. Please follow the instructions in Section 3 of the [User Guide](User-Guide-Release-20190731.pdf).

The build environment for the MinnowBoard firmware is Windows with Visual Studio 2015. Compiling with GCC may work but is untested. You will need a MinnowBoard, of course. 

## Ring0 Manager

The EPA-RIMM design specifies a Host Communications Manager (HCM). The MinnowBoard prototype uses an in-band kernel module--the Ring0 Manager.

To start the Ring0 Manager, navigate to [*Ring0-Manager/*](Ring0-Manager/) and run `sudo ./reloadDriver.sh`

Note: Read the output. Getting a few "warnings" or "notes" is not indicative of a problem, but follow the instructions if there is a message about needing to install a package.

## Frontend Manager

The FEM and the Ring0 Manager together comprise the prototype's HCM.

Open [*epastack/frontend/frontendConfig.py*](epastack/frontend/frontend.py) and change both `BACKEND_SERVER` and `THIS_HOST`  to your machine name (instead of `epa-vm`). `PROCFILE_NAME` should be `/proc/ring0manager`.

To start the FEM, from root directory (the one containing *epastack/*):

`python femstart.py`

To exit the FEM, use `ctrl-c`.

This wrapper provides logging in the FEM, as well as allows it to import files from elsewhere in the package.

When started with *femstart.py*, the FEM outputs logs to *frontend_manager.log* in the root directory.

Note: Don't be confused if you see a reference to the "Host-side Inspector". This is a developer's module not presently included in release.

## Backend Manager

Open [*epastack/backend/backendConfig.py*](epastack/backend/backendConfig.py) and change `DEFAULT_NODELIST` and `DM_HOST` to your machine name (instead of `epa-vm`).

To start the BEM, from the root directory (the one containing *epastack/*:

`python bemstart.py`

To exit the BEM, press *Enter*.

The BEM receives Check requests from the DM. As outlined in the paper, it decomposes Checks into Tasks that take a certain amount of time to run, then schedules the Tasks on a given FEM. It relays results from the FEM back to the DM.

The BEM is ultimately instantiated as a class and has many configurable parameters, though these have not yet been exported to CLI arguments. This is planned for future development.

## Diagnosis Manager

Open [*epastack/diagmgr/dmConfig.py*](epastack/diagmgr/dmConfig.py) and modify `SEND_HOSTS` to send to your machine name (instead of `epa-vm`). Note: If you change configuration after running the module, be sure to clean the respective .json files or the new config won't be picked up.

To start the DM, from root directory (the one containing *epastack/*):

`python dmterm.py [-s]`

* `-s`, `--start`
  * This flag starts socket listeners for default hosts immediately. Otherwise, socket listeners must be started manually. Manual start might be useful if the user wants to specify
    hosts once the *dmterm* is running.

The DM Terminal parses a number of different commands. Once the dmterm is running, type `help` to list them all. They are reproduced here for convenience. Note that typing each of these commands without arguments will print out a list of arguments expected for the given command. Some of this functionality is "in beta" and is scheduled for improvement:

    ls :  list all checks. [-c] list known hosts
    add :  [-c] add a check
    delcheck :  delete a check
    schedule :  send a check to the bem
    help :  list available commands
    serverstart :  start one or more servers by hostname. serverstart [HOSTNAME]
    serverstop :  halt one or more servers by hostname. serverstop [HOSTNAME]
    serverstartall :  start servers for all known hosts
    serverstopall :  stop all active servers
    ping :  check for reply from a known host. ping [HOSTNAME]
    addhost :  add a known host. addhost [HOSTNAME] [PORT]
    exit :  exit the program

The DM outputs logs to *diag_mgr.log* in the root directory.

## Quickstart

1. Build the SMM Inspector and flash the firmware (ok, this part isn't really "quick")
2. (optional) Turn off KASLR
3. Start the Ring0 manager, FEM, BEM, and DM
4. Within *dmterm.py*
   1. Start the server (if you didn't already with the `-s` argument)
      `serverstartall`
   2. Add a check. Try this one:
      `add -c mem 0 once HASH_MEM_VIRT NONE 0xffffffff81000000 4096 med`
      (Note that `0xffffffff81000000` in this example represents the start address of the kernel's text region found by the `_stext` label in `/proc/kallsyms`)
   3. Run the check
      `enqueue <BEM machine name> mem 0`
      You should see the BEM printing debug info. When it's done...
   4. View the results
      `ls`

Other Checks you might try:

* `add -c cr0 0 once CHECK_REG CR0_REG 0 8 med` 
* `add -c cr3 0 once CHECK_REG CR3_REG 0 8 med`
    * Note: This Check's results will change from time to time depending on running processes!
* `add -c cr4 0 once CHECK_REG CR4_REG 0 4 med`
* `add -c SmrrBase 0 once CHECK_MSR 0x1f2 0 4 med`
* `add -c DynamicTsc 0 once CHECK_MSR 0x10 0 8 med` 
    * Note: This Check's results will change on each measurement!

## EPA-RIMM-Xen

This prototype supports Xen and uses Intel's SMI Transfer Monitor (STM).

EPA-RIMM and EPA-RIMM-Xen use the same software stack. The code path in the SMM Inspector is determined at runtime, and none of the other layers (HCM, BEM, or DM) differ. 

The reference implementation of STM is available at https://github.com/jyao1/STM. 

Building the EPA-RIMM-Xen prototype requires modifying the Linux, Xen, and STM source. Patches for these systems are located in the [*xenStmPatches/*](xenStmPatches/) directory along with instructions on how to apply them. 