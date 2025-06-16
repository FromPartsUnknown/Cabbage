# Cabbage: Solaris Rootkit Detection Tool
![Solaris 10](https://img.shields.io/badge/OS-Solaris_10-orange.svg)


## Overview

Cabbage is a simple python-based wrapper designed to automate and simplify post-mortem analysis of **Solaris 10** kernel crash dumps. Cabbage leverages the `mdb` (Modular Debugger), a general purpose debugging tool for Solaris, to analyse Solaris 10 crash dumps and  uncover evidence of rootkits and malicious activity. 

When a host is suspected of being compromised a critical step is to preserve evidence. For a Solaris 10 system this can involve generating a live crash dump and collecting the corresponding kernel core and object file. Cabbage aids in the analyse these artefacts by interacting directly with the Modular Debugger `mdb` and automates commands to detect Kernel integrity issues. 

## Features

Cabbage currently provides the following analysis capabilities for Solaris 10 images:

1.  **Route Cache Analysis (`--route-cache`)**:
    *   Dumps the Kernel's IP route cache using `::ire` via `mdb`.
    *   This helps identify recent and active and historic network communications potentially revealing connections to C2 servers or other malicious hosts.

2.  **Syscall Table Integrity Check (`--syscall-diff`)**:
    *   Iterates through the in-memory `sysent32` (syscall table), and for each entry, compares the in-memory table value against the table value from the object file location corresponding to the memory address.
    *   Discrepancies indicate that the syscall entry has been hooked or patched. This is a common technique used by rootkits on Solaris to hide processes, files, or network connections.

3.  **Kernel Function Integrity Check (`--func-addr-diff`)**:
    *   Obtains a list of all kernel functions from the Kernel symbol table (`::nm -t func`).
    *   For each function, compare 16 bytes of its in-memory kernel function against 16 bytes from the object file location corresponding to the given kernel function.
    *   Differences can indicate that arbitrary kernel functions have been modified, a indication of sophisticated kernel-level rootkits attempting to alter system behavior or maintain persistence.

4. **Executable Path List (`--exec-path`)**: 
    *  Obtains a list of executable paths for all scheduled threads at time of core dump.
    * To verify the integrity of each executable identified:
        * Obtain the executable binary from compromised system
        * On a trusted Solaris system with unmodified package metadata run: '/usr/sbin/pkgchk -l -p /full/path/to/executable'

## Prerequisites

1.  **A Kernel Core Dump and Image:** Generated as described below (e.g., `vmcore.0` and `unix.0` from a Solaris 10 system).
2.  **Python 2.5.x:** The script is specifically designed for this Python version, common on older Solaris 10 environments.
3.  **`mdb` for Solaris 10:** The Solaris 10 Modular Debugger must be available on the analysis system. The behavior of `mdb` can differ between Solaris versions, and this tool assumes Solaris 10 `mdb` behavior.

## Generating a Crash Dump on Solaris 10 (Live System)

On a live (running) Solaris 10 system, the `savecore -L` command can be used to generate a Kernel crash dump. This command write a snapshot of the running kernel's memory and a copy of the kernel namelist to disk.

**Precautions**

*   **Disk Space:** Ensure there is sufficient free disk space in the directory configured for crash dumps (usually `/var/crash/`). A kernel dump can be as large as the system's physical RAM. Use `df -h /var/crash` (or the relevant path) to check. If possible, write the crash dump to a partition not used to store OS files (avoid /). 
*   **System Impact:** Running `savecore -L` on a live system will consume system resources (CPU, I/O) and can take a significant amount of time especially on systems with large amounts of RAM. The system will likely be sluggish or unresponsive during this period. 

**Steps to Generate the Crash Dump:**

1.  **Check Dump Configuration:**
    You can view the current crash dump configuration using `dumpadm`. This will show you the configured dump device and save directory.
    ```bash
    dumpadm
    ```
    The "Savecore directory" is where `savecore -L` will place the dump. It's often `/var/crash/$(hostname)`.

2. **Configure Crash Dump Location (if required):**
   Change the savecore directory.
   ```bash
    dumpadm -s /storage/crash/solaris
    ```

3.  **Verify Disk Space:**
    Check available disk space in the Savecore directory.
    ```bash
    df -h /storage/crash/solaris
    ```
    If space is insufficient, `savecore` may fail or truncate the dump.

4.  **Execute `savecore -L`:**
    Run the command to dump the live kernel:
    ```bash
    savecore -L
    ```

5.  **Locate the Dump Files:**
    Once `savecore -L` completes, navigate to the Savecore directory (e.g., `/var/crash/$(hostname)`). You should find two key files:
    *   `unix.X`: A copy of the kernel executable that was running.
    *   `vmcore.X`: The kernel memory image (the actual core dump).
    Where `X` is a number (e.g., `unix.0`, `vmcore.0`). `savecore` increments this number for subsequent dumps. You'll typically want the highest numbered pair, as these will be the most recent.

6. **Transferring Files for Offline Analysis:**

   Once `unix.X` and `vmcore.X` are generated, you need to securely transfer **both** files to your analysis machine where you will run Cabbage.

## Usage

Run the script from the command line using `python` (or the appropriate Python 2.5 interpreter name on your system), providing paths to the kernel image and core file obtained from the Solaris 10 system.

```bash
python cabbage.py -k /path/to/unix.X -c /path/to/vmcore.Y [options]
```
