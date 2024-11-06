import socket
import threading
from scapy.all import IP, TCP, sr1

def grab_banner(sock):
    try:
        sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = sock.recv(1024)
        return banner.decode().strip()
    except:
        return "Unknown"
        
def os_detection(host, port):
    syn = IP(dst=host)/TCP(dport=port, flags='S')
    syn_ack = sr1(syn, timeout=1, verbose=0)
    if syn_ack:
        options = syn_ack.getlayer(TCP).options
        os_info = "Unknown OS"
        if options:
            for opt in options:
                if opt[0] == 'MSS':
                    mss = opt[1]
                    if mss == 1460:
                        os_info = "Linux (Kernel 2.4 or 2.6)"
                    elif mss ==1360:
                        os_info = "FreeBSD"
                    elif mss == 1380:
                        os_info = "Windows"
                    else:
                        os_info = f"Unknown OS, MSS={mss}"
    
            print(f"{host}: may be running {os_info} OS")
    else:
        print(f"{host}: No response for OS detection")
    
def scan_ports(host, ports):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"
            socket.setdefaulttimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(sock)
                print(f'Port {port}: Open, Running: {banner}, Service: {service}')
                os_detection(host,port)
    sock.close()



if __name__ == "__main__":
    t1PortRange = range(1, 150)
    t2PortRange = range(151, 300)
    t3PortRange = range(301, 600)
    t4PortRange = range(601, 750)
    t5PortRange = range(751, 900)
    t6PortRange = range(901, 1025)
    target = input("Enter the target IP address or hostname: ")
    print(f'Scanning ports on {target}...')
    t1 = threading.Thread(target=scan_ports,args=(target,t1PortRange))
    t2 = threading.Thread(target=scan_ports,args=(target,t2PortRange))
    t3 = threading.Thread(target=scan_ports,args=(target,t3PortRange))
    t4 = threading.Thread(target=scan_ports,args=(target,t4PortRange))
    t5 = threading.Thread(target=scan_ports,args=(target,t5PortRange))
    t6 = threading.Thread(target=scan_ports,args=(target,t6PortRange))
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    t6.start()
    #scan_ports(target)
