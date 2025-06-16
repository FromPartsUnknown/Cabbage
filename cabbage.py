import subprocess
from optparse import OptionParser

class MDBCommand:
    def __init__(self, image_path="/dev/ksyms", core_path="/dev/kmem"):
        self._mdb_command = ["/usr/bin/mdb", "-k", image_path, core_path]

    def send_cmd(self, command, verbose=False):
        cmd = command + "; ::quit\n"
        if verbose:
            print("[*] Sending command to mdb: %s" % cmd.strip())

        try:
            process = subprocess.Popen(
                self._mdb_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False
            )
            stdout, stderr = process.communicate(cmd)
            if process.returncode != 0:
                print("[-] MDB failed with return code %d" % process.returncode)
                print("[-] MDB stderr: %s" % (stderr))
                raise RuntimeError("MDB process failed")

            output = []
            for line in stdout.splitlines():
                if verbose:
                    print(line)
                if line == '':
                    break
                output.append(line + '\n')

            return output
        except OSError as e:
            print("[-] OS Error: %s: %s" % (self._mdb_command, e))
            raise
        except Exception as e:
            print("[-] Unexpected error: %s" % e)
            raise

class DebugAgent:
    def __init__(self, mdb):
        self._mdb = mdb
    
    def print_route_cache_entries(self):
        print("[*] Route Cache Entries")
        print("%-20s %-25s %-15s %-15s %10s %10s" % ("Address", "Creation Date", "Source IP", "Dest IP", "Out Pkts", "In Pkts"))
        print("-" * 100)
        output = self._mdb.send_cmd("::ire")
        for line in output[2:]:
            disp_entry = []
            output = line.strip().split()
            disp_entry.append(output[0])
            if disp_entry[0] == '0':
                continue
            disp_entry.append(output[1])
            disp_entry.append(output[2])
            output = self._mdb.send_cmd("%s::print ire_t ire_create_time ire_ob_pkt_count ire_ib_pkt_count" % disp_entry[0])
            output = [o.strip() for o in output]
            values = [item.split('=')[1].strip() for item in output]
            [disp_entry.append(v) for v in values]
            disp_entry[4] = int(disp_entry[4], 16)
            disp_entry[5] = int(disp_entry[5], 16) 
            print("%-20s %-25s %-15s %-15s %10d %10d" % 
                (disp_entry[0], disp_entry[3], disp_entry[1], disp_entry[2], disp_entry[4], disp_entry[5]))

    def get_func_address_list(self):
        addr_list = []
        output = self.get_symbol_list()
        for line in output:
            address = line.split('|')[0]
            addr_list.append(address)
        return addr_list

    def join_lines(self, output):
        i = 0
        processed_lines = []
        while i < len(output):
            line = output[i]
            if len(line) == 66 and line[-2] == '|':
                if i + 1 < len(output):
                    line = line.rstrip('\n') + output[i + 1]
                    i += 1 
            processed_lines.append(line)
            i += 1     
        return processed_lines        

    def get_symbol_list(self):
        output = self._mdb.send_cmd("::nm -t func")
        return self.join_lines(output[1:])
    
    def diff_address(self, address, verbose):
        cmd_addr_mem  = "%s::dump -u -q -g 4 -n 14 -w 4 -t" % (str(address))
        cmd_addr_disk = "%s::dump -u -q -g 4 -n 14 -w 4 -f -t" % (str(address))
        val = self._mdb.send_cmd(cmd_addr_mem)
        out_mem = val[2].strip()
        val = self._mdb.send_cmd(cmd_addr_disk)
        out_disk = val[2].strip()
        if verbose:
            print("address: %-10s\nMem:  [%-25s]\nDisk: [%-25s]" % (address, out_mem, out_disk))
        if out_mem != out_disk:
            print("[!] Modification Detected! Address: %s:\n[MEM:  %s]\n[DISK: %s]\n" % (address, out_mem, out_disk))
            return True
        return False

    def print_thread_exec_path(self, verbose):
        print("[*] Executable path for all scheduled threads at time of core dump:")
        cmd = "::walk thread | ::print kthread_t t_procp | ::print proc_t p_exec | ::vnode2path"
        output = self._mdb.send_cmd(cmd)
        output = list(set(o.strip() for o in output))
        for o in output:
            if o == '/':
                continue
            print(o)
        print("[*] To verify the integrity of each executable identified:\n\t1. Obtain executable binary from compromised system\n\t2. On a trusted Solaris system with unmodified package metadata run: '/usr/sbin/pkgchk -l -p /full/path/to/executable'")
             
    def diff_address_list(self, verbose=False):
        print("[*] Building a list of all functions from symbol list")
        addr_list = self.get_func_address_list()
        print("[*] Comparing in-memory function address bytes to disk bytes. This will take a long time...")
        for address in addr_list:
            self.diff_address(address, verbose)
        print("[*] Done")
                
    def diff_sysent32(self, verbose=False):
        print("[*] Comparing in-memory syscall table to disk syscall table...")
        i = 0
        while i < 256:
            cmd_sysent_mem  = "sysent32+(%d*0x20)::dump -n 4" % (i)
            cmd_sysent_disk = "sysent32+(%d*0x20)::dump -f -n 4" % (i)
            val  = self._mdb.send_cmd(cmd_sysent_mem)
            out_mem = val[1].strip()
            val = self._mdb.send_cmd(cmd_sysent_disk)
            out_disk = val[1].strip()
            if verbose:
                print("SysEnt: %-5d\nMem:  [%-25s]\nDisk: [%-25s]" % (i, out_mem, out_disk))
            if out_mem != out_disk:
                print("[!] Modification Detected! - sysent32 offset %d\n[MEM:  %s]\n[DISK: %s]" % (i, out_mem, out_disk))
            i += 1
        print("[*] Done")

def main():
    parser = OptionParser()
    parser.add_option("-c", "--core-file",    dest="core_file",    help="Path to kernel core file, eg. /storage/var/crash/vmcore.0")
    parser.add_option("-k", "--image-file",   dest="image_file",   help="Path to kernel object file, eg. /storage/var/crash/unix.0")
    parser.add_option("-v", "--verbose",      dest="verbose",      action="store_true", default=False)
    parser.add_option("-r", "--route-cache",  dest="route_cache",  action="store_true", default=False, help="Print route cache table")
    parser.add_option("-e", "--exec-path",  dest="exec_path",  action="store_true", default=False, help="Print a list of executable paths for all scheduled threads at time of dump. You should check the integrity of each executable with pkgchk -l")
    parser.add_option("-s", "--syscall_diff", dest="syscall_diff", action="store_true", default=False, help="Compare in-memory values of all syscall entries to on-disk syscall entries")
    parser.add_option("-a", "--func_addr_diff", dest="func_addr_diff", action="store_true", default=False, help="Compare in-memory 16 byte value of all kernel functions to on-disk kernel function values. Function list generated from symbol table")
    (options, args) = parser.parse_args()

    if not options.core_file or not options.image_file:
        parser.error("Both --core-file and --image-file are required.")
        
    if not (options.route_cache or options.syscall_diff or options.func_addr_diff or options.exec_path):
        print("[-] No action specified.\n")
        parser.print_help()
        exit(1)
   
    try:
        mdb = MDBCommand(options.image_file, options.core_file)
        dbg = DebugAgent(mdb)
        if options.exec_path:
            dbg.print_thread_exec_path(verbose=options.verbose)
        if options.route_cache:
            dbg.print_route_cache_entries()
        if options.syscall_diff:
            dbg.diff_sysent32(verbose=options.verbose)
        if options.func_addr_diff:
            dbg.diff_address_list(verbose=options.verbose)
    except KeyboardInterrupt:
        print("[*] Exiting due to user interrupt (Ctrl+C)")
        exit(1)
        

if __name__ == "__main__":
    main()
