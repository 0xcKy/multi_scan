#!/usr/bin/python

import socket
import sys
import argparse
import ipaddress
import re
import threading
from pythonping import ping
from queue import Queue

parser = argparse.ArgumentParser() #cria parser
exclusive = parser.add_mutually_exclusive_group() #cria grupo de parser exclusivos
parser.add_argument("IP", type=str, help="destination IP")
parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
exclusive.add_argument("-p", "--portscan", action="extend", nargs="+", type=str, help="list of ports to scan")
exclusive.add_argument("-ps", "--ping", type=str, help="ping subnet for active hosts. Use CIDR /#")
exclusive.add_argument("-cp", "--complete", action="store_true", help="scan all ports")
exclusive.add_argument("-wi", "--whois", action="store_true", help="whois on IP or domain")
exclusive.add_argument("-f", "--ftp", action="store_true", help="test for ftp bruteforce")
parser.add_argument("--wordlist", type=str, help="wordlist to use")
parser.add_argument("--user", type=str, help="username to test")
parser.add_argument("--port", type=str, help="port to test")
parser.add_argument("--threads", type=str, help="number of threads to use")
argumento = parser.parse_args()

class color:
    BOLD = '\033[1m'
    BLUE = '\033[34m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    END = '\033[0m'

banner = (f"""{color.BOLD}

              .__   __  .__                                  
  _____  __ __|  |_/  |_|__|      ______ ____ _____    ____  
 /     \|  |  \  |\   __\  |     /  ___// ___\\__  \  /    \ 
|  Y Y  \  |  /  |_|  | |  |     \___ \\  \___ / __ \|   |  \
|__|_|  /____/|____/__| |__|____/____  >\___  >____  /___|  /
      \/                  /_____/    \/     \/     \/     \/

{color.END}
""")

print (banner)

#cria scan de portas usando os argumentos recebidos
def port_scan():
    for i in argumento.portscan:
        inteiro = int(i)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4) #define um timeout caso a porta nao responda
        resultado = s.connect_ex((argumento.IP,inteiro))
        try:
            if (resultado == 0):
                #caso o resultado seja zero (porta aberta), porem a var versao nao recebe nada do host destino, sera mostrado como time out
                #versao = s.recv(1024)
                #print("Version: %s" %versao.decode('utf-8'))
                print ("\n[+] %s @ %d" %(argumento.IP,inteiro))
                print ("[%d open] " %inteiro)
                s.close()
            elif(argumento.verbose):
                print ("\n[+] %s @ %d" %(argumento.IP,inteiro))
                s.close()
                print ("\n[closed]")
        except:
            print ("\n[timed out]")
            continue #continua o script em caso de erro

def complete_scan():

    destino = argumento.IP
    START_PORT = 1
    END_PORT = 65535
    TIMEOUT = 1  # Timeout para tentativa de conexão em segundos
    if argumento.threads:
        THREADS = int(argumento.threads)
    else:
        THREADS = 100  # Número de threads paralelas

    port_queue = Queue()
    open_ports = []

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            result = s.connect_ex((destino, port))
            if result == 0:
                open_ports.append(port)
                print ("\n[+] [%d open] @ %s" %(port,destino))
            s.close()
        except Exception as e:
            pass
        finally:
            if argumento.verbose:
                print(f"\r{color.YELLOW}[+] testing port {port} of {END_PORT}{color.END}", end='')

    def worker():
        while not port_queue.empty():
            port = port_queue.get()
            scan_port(port)
            port_queue.task_done()

    def inicia():
        # Preenche a fila com todas as portas a serem verificadas
        for port in range(START_PORT, END_PORT + 1):
            port_queue.put(port)

        # Cria e inicia as threads
        threads = []
        for _ in range(THREADS):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        # Aguarda todas as threads terminarem
        for thread in threads:
            thread.join()

        # Exibe os resultados finais
        if open_ports:
            print(f"\n[+] open ports @ {destino}: {color.GREEN}{sorted(open_ports)}{color.END}")
        else:
            print(f"\n{color.RED}[+] no open ports @ {destino}{color.END}")

    if __name__ == '__main__':
        inicia()

def ping_scan():
    try:
        corte = argumento.IP.split('.')
        rede = ipaddress.IPv4Network(str(".".join(corte[0:3]))+".0"+ argumento.ping)
        for addr in rede:
           if argumento.verbose:
               print(addr)
           resposta = ping(str(addr), timeout = 0.2, count = 1, interval = 0.1)
           if resposta.success():
               print ("ICMP return from %s" %(addr))
    except KeyboardInterrupt:
       print ("\n[+] Exiting")
    except PermissionError:
       print ("\n[+] This option requires root privileges")
    except Exception:
       print ("\n[+] Wrong argument or value")

def whois():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("whois.iana.org",43))
        s.send(str.encode(sys.argv[1]+"\r\n"))
        refer = re.search(r"whois\.\D+\.\w+", str(s.recv(1024))) #o r antes da string informa ao python que eh uma raw string, evitando erro de alerta
        s.close()

        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.connect((str(refer.group()),43))
        s2.send(str.encode(sys.argv[1]+"\r\n"))
        final = s2.recv(1024)

        try:
            print (var.decode("utf-8"))
        except UnicodeDecodeError:
            print (var.decode("latin-1"))
    except KeyboardInterrupt:
       print ("\n[+] Exiting")


def ftpbrute():
    try:
        if (argumento.wordlist and argumento.user and argumento.port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((argumento.IP,int(argumento.port)))
            print ("[+] Conectando ao servidor...")
            print ("[+] Banner = " + (s.recv(1024)).decode('utf-8'))
            s.close()
            print ("[+] Testando  user %s\n" %argumento.user)
            with open(argumento.wordlist) as f:
                for senha in f:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((argumento.IP,int(argumento.port)))
                    s.send(("USER " + argumento.user + "\r\n").encode('utf-8'))
                    s.recv(1024).decode('utf-8')
                    print ("[+] Enviando senha %s" %senha.strip())
                    s.send(("PASS " + senha.strip() + "\r\n").encode('utf-8'))
                    resposta = (s.recv(1024)).decode('utf-8').strip()
                    if re.search('230', resposta):
                        print ("[+] Senha encontrada -> %s = %s" %(senha.strip(),resposta))
                        s.close()
                        break
                    else:
                        s.close()
        else:
            print ("[+] Missing arguments. Use -w (wordlist), -u (username) and -pt (port)")
    except ConnectionRefusedError:
        print ("[+] Connection Refused")
    except KeyboardInterrupt:
        print ("\n[+] Exiting")

if __name__ == '__main__':
    if argumento.portscan:
        port_scan()
    elif argumento.ping:
        ping_scan()
    elif argumento.complete:
        complete_scan()
    elif argumento.whois:
        whois()
    elif argumento.ftp:
        ftpbrute()
    else:
        print ("[+] Select an argument. Use -h for help menu")
