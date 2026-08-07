#!/usr/bin/env python3

import socket
import argparse
import threading
import time
from queue import Queue, Empty

# a handful of well-known ports so the output actually means something
COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
   110: "pop3",
   139: "netbios",
   143: "imap",
   443: "https",
   445: "smb",
   993: "imaps",
   995: "pop3s",
  1433: "mssql",
  3306: "mysql",
  3389: "rdp",
  5432: "postgres",
  5900: "vnc",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
}


# lock so the threads don't scramble each other's output lines
print_lock = threading.Lock()

 # shared state. not the prettiest but fine for a script this size.
open_ports = []
scanned = 0

def resolve_host(host):
        # work for both a hostname and an ip address
        try:
           return socket.gethostbyname(host)
        except socket.gaierror:
            return None

def grab_banner(sock):
   # a lot of service (ssh, ftp, smtp..) announce themselves the moment
   # you connect, so just read whatever come back first.
   try:
       sock.settimeout(1.5)
       data = sock.recv(1024)
       return data.decode("utf-8", errors="ignore").strip()
   except Exception:
        return ""

def scan_port(ip, port, timeout):
       global scanned       
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       s.settimeout(timeout)

          # connect_ex return 0 on success instead of raising, which is nicer here
       result = s.connect_ex((ip, port))

       if result == 0:
            banner = grab_banner(s)
            name   = COMMON_PORTS.get(port, "unknown")
            open_ports.append((port, name, banner))

            with print_lock:
                line = "[+] {:>5}/tcp open {}".format(port, name)
                if banner:
                  # banners can be multi-line junk, so trim hard
                   clean = banner.replace("\n", " ").replace("\r", " ")
                   line += "  -> " + clean[:55]
                print(line)
 
       s.close()

       with print_lock:
            scanned += 1


def worker(ip, timeout, q):
     # keep pulling ports off the queue untill it runs dry
     while True:
       try:
          port = q.get_nowait()
       except Empty:
          break
       scan_port(ip, port, timeout)
       q.task_done()


def parse_ports(port_arg):
    # handles "80" , "1-1024", "22,80,443", and mixes like "22,80,8000-8100"
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if not part:
           continue
        if "-" in part:
          start, end = part.split("-")
          ports.update(range(int(start), int(end) + 1))
        else:
          ports.add(int(part))

        # quietly drop anything out of range intead of blowing up later
    return sorted(p for p in ports if 0 < p <65536)

def save_result(path, host, ip):
      # dump the port to a file if the the user asked for it
    with open(path, "w") as f:
        f.write("Scan result for {} ({})\n".format(host, ip))
        f.write("-" * 40 + "\n")
        for port, name,  banner in sorted(open_ports):
           f.write("{}/tcp\t{}\n".format(port, name))
           if banner:
              f.write("      banner: {}\n".format(banner[:120]))
    print("Saved result to {}". format(path))


def main():
    parser = argparse.ArgumentParser(
             description="A small threaded TCP port scanner."

    )
    parser.add_argument("host", help="target hostname or IP")
    parser.add_argument("-t", "--threads", type=int, default=100,
                                help="number of threads (default: 100)")
    parser.add_argument("-p", "--ports", default="1-1024",
                          help="ports e.g. 22,80,443 or 1-1024 (defailt: 1-1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                                    help="socket timeout in second (default: 0.5)")
    parser.add_argument("-o", "--output", help="save open ports to the file")
    args  = parser.parse_args()


    ip = resolve_host(args.host)
    if ip is None:
        print("Could not resolve '{}'. check the name and try again HOney.".format(args.host))
        return

    ports = parse_ports(args.ports)
    if not ports:
        print("No valid ports to scan.")
        return

    print("Scanning {} ({})".format(args.host, ip))
    print("Port: {} Threads: {} Timeout: {}s".format(
        len(ports), args.threads, args.timeout))
    print("-" * 50)

    start = time.time()

        #load every port we want to check into the queue
    q=Queue()
    for port in ports:
        q.put(port)


    # no point spinning up more threads than there are ports
    thread_count = min(args.threads, len(ports))
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(ip, args.timeout, q))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
          # let people bail out cleanly with ctrl+c
        print("\nStopped by user after {} ports.".format(scanned))
        return

    elapsed =  time.time() - start
    print("-" * 50)
 
        # the line output above is out of order because of threading, so print
        # a clean sorted list at the end
    if open_ports:
        print("Open port:")
        for port, name, _ in sorted(open_ports):
               print(" {:>5}/tcp {}".format(port, name))
        print("\nDone. {} open port(s) out of {} scanned in {:.1f}s.".format(
            len(open_ports), scanned, elapsed))

            
    else:
        print("Done. No ports found ({} scanned) in {:.1f}s.".format(
                scanned, elapsed))

    if args.output and open_ports:
           save_result(args.output, args.host, ip)

if __name__ == "__main__":
    main()