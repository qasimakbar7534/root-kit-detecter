import os
import subprocess
import hashlib

# ======= 1. Check for hidden files in /proc ========
def check_hidden_processes():
    print("[*] Checking for hidden processes...")
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    real_pids = subprocess.getoutput("ps -e -o pid=").split()
    
    hidden = set(pids) - set(real_pids)
    if hidden:
        print("[!] Hidden processes detected:", hidden)
    else:
        print("[+] No hidden processes detected.")

# ======= 2. Check for suspicious kernel modules ========
def check_kernel_modules():
    print("[*] Checking for suspicious kernel modules...")
    lsmod_output = subprocess.getoutput("lsmod")
    if not lsmod_output:
        print("[!] Unable to list kernel modules (maybe hooked lsmod?).")
        return

    for line in lsmod_output.splitlines()[1:]:
        module = line.split()[0]
        if module.startswith("root") or module.startswith("rk"):
            print("[!] Suspicious kernel module found:", module)

# ======= 3. Check if 'ps' or 'ls' binaries are altered ========
def check_binary_integrity():
    print("[*] Checking integrity of common binaries...")
    known_hashes = {
        "/bin/ls": "e2a9c8f6f5f5e1a888d1be7e0cfb84f3",
        "/bin/ps": "f51e2f6e4c2ad8e0ee53aeab9c321d7d"
    }
    
    for binary, known_md5 in known_hashes.items():
        if not os.path.exists(binary):
            print(f"[!] {binary} does not exist!")
            continue
        with open(binary, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            if md5_hash != known_md5:
                print(f"[!] {binary} hash mismatch! Possible tampering.")
            else:
                print(f"[+] {binary} looks OK.")

# ======= 4. Scan /dev for suspicious entries ========
def scan_dev_entries():
    print("[*] Scanning /dev for suspicious entries...")
    suspicious = []
    for root, dirs, files in os.walk("/dev"):
        for name in files:
            if "rootkit" in name.lower() or "rk" in name.lower():
                suspicious.append(os.path.join(root, name))
    if suspicious:
        print("[!] Suspicious /dev entries found:", suspicious)
    else:
        print("[+] /dev looks clean.")

# ======= MAIN ========
if __name__ == "__main__":
    print("=== Basic Rootkit Detection Script (Linux) ===\n")
    check_hidden_processes()
    print()
    check_kernel_modules()
    print()
    check_binary_integrity()
    print()
    scan_dev_entries()
