import nmap
import socket
import random
import string
import codecs
import fcntl
import struct
import os, ssl, sys, json, argparse, re
from datetime import datetime
from OpenSSL import crypto
from socket import gethostname, gethostbyname, getfqdn
from simplejson import dumps
from collections import OrderedDict
from subprocess import Popen, PIPE
from netaddr import *

from pkg_resources import resource_filename

from scapy.all import *
from threading import Thread, Event
from time import sleep

#https://www.cybrary.it/0p3n/sniffing-inside-thread-scapy-python/
class Sniffer(Thread):
    def  __init__(self, target, interface="eth0"):
        super(Sniffer, self).__init__()

        self.generics = OrderedDict()
        self.target = target
        self.daemon = True

        self.socket = None
        self.interface = interface
        self.stop_sniffer = Event()

    def run(self):
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter="host %s" % self.target
        )

        sniff(
            opened_socket=self.socket,
            prn=self.parse_packet,
            stop_filter=self.should_stop_sniffer
        )

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super(Sniffer, self).join(timeout)
        return self.generics

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def parse_packet(self, pkt):
        if Raw in pkt and IP in pkt and TCP in pkt:
            data = pkt[Raw].load
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if src == self.target or dst == self.target:
                if src == self.target:
                    key = sport
                    session = dport
                    direction = 'answer'
                elif dst == self.target:
                    key = dport
                    session = sport
                    direction = 'probe'
                else:
                    return

                if key not in self.generics:
                    self.generics[key] = OrderedDict()

                if session not in self.generics[key]:
                    self.generics[key][session] = OrderedDict()

                if session in self.generics[key]:
                    if direction == 'probe':
                        if data not in self.generics[key][session]:
                            self.generics[key][session][data] = []
                    else:
                        if len(self.generics[key][session].keys()):
                            last_probe = self.generics[key][session].keys()[-1]
                        else:
                            last_probe = 'Null Probe'
                        if last_probe not in self.generics[key][session]:
                            self.generics[key][session][last_probe] = []
                        self.generics[key][session][last_probe].append(data)

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))


class ImposterService(object):
    """docstring for ImposterService"""
    def __init__(self, mirrorHost, port, protocol, details):
        super(ImposterService, self).__init__()
        self.mirrorHost = mirrorHost
        self.port = port
        self.portCollision = False
        self.protocol = protocol
        self.details = details
        self.certDir = '/etc/opencanaryd/ssl'
        self.banner = None
        self.probes = None
        self.ssl = None
        self.certCloned = False
        self.name = None
        self.serverHeader = None
        self.type = 'opencanary'
        self.options = {}
        self.parseNmapResults()

    def parseNmapResults(self):
        serviceMap = [(['proxy'], 'httpproxy'),
                    (['vnc'], 'vnc'),
                    (['http'], 'mitm'),
                    (['tftp'], 'tftp'),
                    (['ftp'], 'ftp'),
                    (['ms-sql'], 'mssql'),
                    (['mysql'], 'mysql'),
                    #(['netbios', 'microsoft-ds'], 'samba'),
                    (['netbios', 'microsoft-ds'], 'generictcp'),
                    (['ntp'], 'ntp'),
                    #(['ms-wbt', 'rdp'], 'rdp'),
                    (['sip'], 'sip'),
                    (['ssh'], 'ssh'),
                    (['snmp'], 'snmp'),
                    (['telnet'], 'telnet')
                    ]


        httpBlacklist = {'product': 'Microsoft HTTPAPI httpd'}


        for nmapServiceNames, potServiceName in serviceMap:
            if [x for x in nmapServiceNames if x in self.details['name']]:
                if x == 'http':
                    for key, val in httpBlacklist.iteritems():
                        if key in self.details and self.details[key] == val:
                            self.name = 'generictcp'

                if not self.name:
                    self.name = potServiceName
                    if self.name == 'mitm':
                        self.type = 'reverseproxy'

        if not self.name:
            if self.protocol == 'tcp':
                self.name = 'generictcp'
            else:
                self.name = 'genericudp'

        if 'script' in self.details:
            self.banner = self.details['script'].get('banner', None)
            self.ssl = self.details['script'].get('ssl-cert', None)
            self.headers = self.details['script'].get('http-headers', None)

            if self.headers:
                serverHeaderMatch = re.search('Server: (?P<serverHeader>.+)', self.headers)
                if serverHeaderMatch:
                    self.serverHeader = serverHeaderMatch.groupdict()['serverHeader']

        if 'probes' in self.details:
            self.probes = self.details['probes']

        if self.ssl:
             self.mirrorCertificate()


    def adjustSubjectIssuerCNs(self, mirrorx509):
        # Check for self signed certificate and recreate self sign while maintaining target mirror cert domain and target issuer domain
        mirrorCertSubjectCN = mirrorx509.get_subject().CN
        mirrorCertIssuerCN = mirrorx509.get_issuer().CN

        newSubjectCN = mirrorCertSubjectCN
        newIssuerCN = mirrorCertIssuerCN

        try:
            mirrorHostname = self.mirrorHost.split('.', 1)

            if mirrorHostname.lower() in mirrorCertSubjectCN.lower():
                if mirrorCertSubjectCN.isupper():
                    newSubjectCN = mirrorCertSubjectCN.replace(mirrorHostname.upper(), gethostbyname().upper())
                else:
                    newSubjectCN = mirrorCertSubjectCN.replace(mirrorHostname.lower(), gethostbyname().lower())

            if mirrorHostname.lower() in mirrorCertIssuerCN.lower():
                if mirrorCertSubjectCN.isupper():
                    newIssuerCN = mirrorCertIssuerCN.replace(mirrorHostname.upper(), gethostbyname().upper())
                else:
                    newIssuerCN = mirrorCertIssuerCN.replace(mirrorHostname.lower(), gethostbyname().lower())
        except:
            return newSubjectCN, newIssuerCN
        return newSubjectCN, newIssuerCN


    def mirrorCertificate(self, keyLength=2048):
        certFile = "%s_%s.crt" % (self.name, self.port)
        keyFile = "%s_%s.key" % (self.name, self.port)

        try:
            mirrorCert = ssl.get_server_certificate((self.mirrorHost, int(self.port)), ssl_version=ssl.PROTOCOL_SSLv23)
        except:
            return

        mirrorx509 = crypto.load_certificate(crypto.FILETYPE_PEM, mirrorCert)

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, keyLength)

        # create a self-signed cert
        cert = crypto.X509()
        cert.set_subject(mirrorx509.get_subject())
        cert.set_issuer(mirrorx509.get_issuer())
        cert.set_serial_number(mirrorx509.get_serial_number())
        cert.set_notBefore(mirrorx509.get_notBefore())
        cert.set_notAfter(mirrorx509.get_notAfter())
        cert.set_version(mirrorx509.get_version())
        cert.set_pubkey(k)

        newSubjectCN, newIssuerCN = self.adjustSubjectIssuerCNs(mirrorx509)
        cert.get_subject().CN = newSubjectCN
        cert.get_issuer().CN = newIssuerCN

        cert.sign(k, mirrorx509.get_signature_algorithm())

        if not os.path.exists(self.certDir):
            os.mkdir(self.certDir)

        self.certFilePath = os.path.join(self.certDir, certFile)
        self.keyFilePath = os.path.join(self.certDir, keyFile)

        open(self.certFilePath, "wt").write( crypto.dump_privatekey(crypto.FILETYPE_PEM, k) + '\n' + \
                                             crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        if os.path.exists(self.certFilePath):
            self.certCloned = True


    def getOpenCanaryConf(self):
        conf = {self.name + '.enabled': True}

        if self.name == 'http':
            conf['http.skin.list'] = [{"desc": "Plain HTML Login",
                                       "name": "basicLogin"},
                                      {"desc": "Synology NAS Login",
                                       "name": "nasLogin"}]
        if self.name == 'httpproxy':
            conf['httpproxy.skin.list'] = [{"desc": "Squid",
                                            "name": "sguid"},
                                           {"desc": "Microsoft ISA Server Web Proxy",
                                            "name": "ms-isa"}]
        if self.name == 'telnet':
            conf['telnet.honeycreds'] = [{"username": "admin",
                                          "password": "$pbkdf2-sha512$19000$bG1NaY3xvjdGyBlj7N37Xw$dGrmBqqWa1okTCpN3QEmeo9j5DuV2u1EuVFD8Di0GxNiM64To5O/Y66f7UASvnQr8.LCzqTm6awC8Kj/aGKvwA"},
                                         {"username": "admin",
                                          "password": "admin1"}]

        return conf


    def getOpenCanaryInstance(self):
        instance = {self.name + '.port': self.port,
                    self.name + '.banner': self.banner,
                    self.name + '.probes': self.probes}

        if self.name == 'ssh':
            instance['ssh.version'] = self.banner
        elif self.name == 'http':
            instance['http.skin'] = 'nasLogin'
        elif self.name == 'httpproxy':
            instance['httpproxy.skin'] = 'squid'
        elif self.name == 'telnet':
            instance

        return instance


    def setReverseProxyConf(self):
        app = '%s_%s' % (self.name, self.port)

        if self.ssl:
            scheme = 'https'
        else:
            scheme = 'http'

        if self.ssl and self.certCloned:
            certs = 'certs:\n    - %s\n' % self.certFilePath
            certArg = '--cert /etc/opencanaryd/ssl/mitm_%s.crt' % self.port
        else:
            certs = ''
            certArg = ''

        if self.serverHeader:
            serverHeader = '--setheader :~q:Server:%s' % gethostname()
        else:
            serverHeader = ''

        self.options['args'] = '-p %s -R %s://%s:%s --insecure --replace :h:%s:%s %s %s > /var/log/opencanary/mitm_%s.log 2>&1 &' % (self.port, scheme, self.mirrorHost, self.port, self.mirrorHost, gethostname(), serverHeader, certArg, self.port)

        rProxy = '''port: %s
reverse: %s://%s:%s/
%s''' % (self.port, scheme, self.mirrorHost, self.port, certs)

        confPath = '/etc/opencanaryd/%s.conf' % (app)

        if os.path.exists(confPath):
            os.rename(confPath, confPath + '.bak')

        with open(confPath, 'w') as fname:
            fname.write(rProxy)



class Imposter(object):
    """Enumerate ports and services on mirror host and generates opencanary configs as well as mitm reverse proxy configs"""
    def __init__(self, mirrorHost, mirrorMac='', iface='eth0', force=False):
        super(Imposter, self).__init__()
        self.mirrorHost = mirrorHost
        self.mirrorMac = mirrorMac
        self.mirrorIP = gethostbyname(self.mirrorHost)
        self.iface = iface
        self.mirrorHostLive = False
        self.services = []
        self.__config = None
        self.setListeningPorts()


    def setListeningPorts(self):
        ports = runBash("sudo netstat -tlnp | egrep -i 'listen\s' | egrep '0\.0\.0\.0:' | egrep -v 'python|mitmdump' | awk '{print $4}' | cut -d ':' -f 2").read().splitlines()
        self.portsListening = [int(x) for x in ports]


    def loadOpenCanaryDefaults(self):
        defaultPath = '/etc/opencanaryd/default.json'
        try:
            with open(defaultPath, "r") as fname:
                print("[-] Loading default config file: %s" % defaultPath)
                self.__config = json.load(fname)
                return
        except IOError as e:
            print("[-] Failed to open %s for reading (%s)" % (defaultPath, e))
        except Exception as e:
            print("[-] An error occured loading %s (%s)" % (defaultPath, e))


    def updateOpenCanaryConf(self):
        if self.mirrorHostLive:
            self.loadOpenCanaryDefaults()

            for service in [x for x in self.services if not x.portCollision if x.type == 'opencanary']:
                self.__config.update(service.getOpenCanaryConf())

                instances = '%s.instances' % service.name
                if instances not in self.__config:
                    self.__config[instances] = []

                self.__config[instances].append(service.getOpenCanaryInstance())

            if os.path.exists('/etc/opencanaryd/opencanary.conf'):
                os.rename('/etc/opencanaryd/opencanary.conf', '/etc/opencanaryd/opencanary.conf.bak')

            with open('/etc/opencanaryd/opencanary.conf', 'w') as fname:
                json.dump(self.__config, fname, sort_keys=True, indent=4, separators=(',', ': '))


    def scanMirrorHost(self, ports=None, arguments='-sV -Pn --script banner --script ssl-cert --script http-headers'):
        ps = nmap.PortScanner()

        # Setup sniffing thread to watch nmap scan
        sniffer = Sniffer(self.mirrorIP, self.iface)
        sniffer.start()

        # run scan, capturing packets from sniffer thread
        self.nmap = ps.scan(hosts=self.mirrorHost, ports=ports, arguments=arguments)
        
        # Join sniffer thread, killing the sniffing session
        generics = sniffer.join(2.0)

        # Ensure sniffer is dead and close socket
        if sniffer.isAlive():
            sniffer.socket.close()

        self.probe_mapping = OrderedDict()

        # set probe to response mapping
        for port in generics:
            self.probe_mapping[port] = OrderedDict()
            for session in generics[port]:
                for probe in generics[port][session]:
                    for answer in generics[port][session][probe]:
                        self.probe_mapping[port][probe.__repr__().strip("'")] = answer.__repr__().strip("'")

        # remove probes with null response
        for port in self.probe_mapping.keys():
            for probe in self.probe_mapping[port].keys():
                if not self.probe_mapping[port][probe]:
                    del(self.probe_mapping[port][probe])

        if self.mirrorIP in self.nmap['scan']:
            self.nmapResults = self.nmap['scan'][self.mirrorIP]

            if self.nmapResults['status']['state'] == 'up':
                self.mirrorHostLive = True
                if 'tcp' in self.nmapResults:
                    for port, details in self.nmapResults['tcp'].iteritems():
                        if port in self.probe_mapping:
                            details['probes'] = self.probe_mapping[port]
                        if details['state'] != 'filtered':
                            self.services.append(ImposterService(self.mirrorHost, port, 'tcp', details))
                            if port in self.portsListening:
                                self.services[-1].portCollision = True
                if 'udp' in self.nmapResults:
                    for port, details in self.nmapResults['udp'].iteritems():
                        if details['state'] != 'filtered':
                            self.services.append(ImposterService(self.mirrorHost, port, 'udp', details))
                            if port in self.portsListening:
                                self.services[-1].portCollision = True


    def updateReverseProxyConf(self):
        if self.mirrorHostLive:
            for service in [x for x in self.services if not x.portCollision if x.type == 'reverseproxy']:
                service.setReverseProxyConf()


    def updateT1000(self):
        if self.mirrorHostLive:
            t1000Config = {'target': self.mirrorHost,
                            'mac': self.mirrorMac}
            for service in self.services:
                if not service.portCollision:
                    t1000Config[service.port] = {'port': service.port,
                                                'name': service.name,
                                                'type': service.type,
                                                'options': service.options}

            with open('/etc/opencanaryd/t1000.conf', 'w') as fname:
                json.dump(t1000Config, fname, sort_keys=True, indent=4, separators=(',', ': '))


    def updateSamba(self):
        if self.mirrorHostLive:
            if 445 in [service.port for service in self.services]:
                runBash('sudo update-rc.d smbd defaults')
                runBash('sudo service smbd start')
            else:
                runBash('sudo service smbd stop')
                runBash('sudo update-rc.d -f smbd remove')


# https://github.com/clong/detect-responder
class Respondered(object):

    def __init__(self):
        self.events = []

    def gen_event(self):
        event = {}
        event['event_time'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        event['node_hostname'] = socket.getfqdn()
        event['node_ip'] = socket.gethostbyname(socket.gethostname())
        event['dst_host'] = event['node_ip']
        event['logtype'] = 'RESPONDERED'
        event['logdata'] = {}
        return event

    # Send a LLMNR request for WPAD to Multicast
    def query_llmnr(self, query, length):
        # Configure the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.settimeout(2)
        sock.bind(('0.0.0.0', 0))

        # Configure the destination address and packet data
        mcast_addr = '224.0.0.252'
        mcast_port = 5355

        if query == "random":
            query = ''.join(random.choice(string.lowercase) for i in range(16))
        llmnr_packet_data = "\x31\x81\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + chr(length) + query + "\x00\x00\x01\x00\x01"

        # Send the LLMNR query
        sock.sendto(llmnr_packet_data, (mcast_addr, mcast_port))

        event = self.gen_event()
        event['dst_port'] = 5355

        # Check if a response was received
        while 1:
            try:
                resp = sock.recvfrom(1024)
                # If a response was received, parse the results into an event
                if resp:
                    event["logdata"] = {"msg": "Poisoned Response Received - LLMNR"}
                    event['src_ip'] = str(resp[1][0])
                    event['src_port'] = str(resp[1][1])
                    event['logdata']["responder_ip"] = str(resp[1][0])
                    event['logdata']["query"] = query
                    event['logdata']["response"] = str(resp[0][13:(13+length)])
                    event['logdata']["DATA"] = codecs.escape_encode(resp[0])
                    event['logdata']["protocol"] = "llmnr"
                    sock.close()
                    self.events.append(event)
                    break
            # If no response, wait for the socket to timeout and close it
            except socket.timeout:
                sock.close()
                break


    def decode_netbios_name(self, nbname):
        """
        Return the NetBIOS first-level decoded nbname.
        https://stackoverflow.com/questions/13652319/decode-netbios-name-python
        """
        if len(nbname) != 32:
            return nbname
        l = []
        for i in range(0, 32, 2):
            l.append(chr(((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i+1]) - 0x41) & 0xf)))
        return ''.join(l).split('\x00', 1)[0]

    def get_broadcast_addresses(self):

        with open('/etc/opencanaryd/t1000.broadcasts') as inFile:
            return [x.strip() for x in inFile.read().strip().splitlines()]


    def query_nbns(self, query):
        # Configure the socket
        
        for broadcast_address in self.get_broadcast_addresses():

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            sock.bind(('0.0.0.0', 0))

            port = 137
            if query == "WPAD":
                # Format WPAD into NetBIOS query format
                nbns_query = "\x46\x48\x46\x41\x45\x42\x45\x45\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x41\x41"
            else:
                # Create a query consisting of 16 random characters
                query = ''.join(random.choice(string.lowercase) for i in range(16))
                # Encode the query in the format required by NetBIOS
                nbns_query = ''.join([chr((ord(c)>>4) + ord('A')) + chr((ord(c)&0xF) + ord('A')) for c in query])

            # Send the NBNS query
            sock.sendto("\x87\x3c\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20" + nbns_query + "\x00\x00\x20\x00\x01", (broadcast_address, port))


            event = self.gen_event()
            event['dst_port'] = 137

            # Check if a response was received
            while 1:
                try:
                    resp = sock.recvfrom(1024)
                    # If a response was received, parse the results into a event
                    if resp:
                        event["logdata"] = {"msg": "Poisoned Response Received - NBNS"}
                        event['src_ip'] = str(resp[1][0])
                        event['src_port'] = str(resp[1][1])
                        event['logdata']["responder_ip"] = str(resp[1][0])
                        event['logdata']["query"] = str(query).strip()
                        event['logdata']["response"] = self.decode_netbios_name(str(resp[0][13:45])).strip()
                        event['logdata']["DATA"] = codecs.escape_encode(resp[0])
                        event['logdata']["protocol"] = "nbns"
                        event['logdata']["broadcast"] = broadcast_address
                
                        # Convert the NetBIOS encoded response back to the original query
                        self.events.append(event)
                        sock.close()
                        break
                # If no response, wait for the socket to timeout and close it
                except socket.timeout:
                    sock.close()
                    break

    def logStart(self):
        event = self.gen_event()
        event["logdata"] = {"msg": "Respondered running!!!"}
        with open('/var/log/opencanary/respondered.log', 'a') as log:
            log.write(json.dumps(event, sort_keys=True) + '\n')
            log.flush()


    def logResults(self):
        with open('/var/log/opencanary/respondered.log', 'a') as log:
            log.write('\n'.join([json.dumps(event, sort_keys=True) for event in self.events]))
            log.flush()
            event = self.gen_event()
            event["logdata"] = {"msg": "Respondered finished!!!"}
            log.write(json.dumps(event, sort_keys=True) + '\n')
            log.flush()


    def generate(self):
        self.logStart()
        self.query_llmnr("wpad", 4)
        self.query_llmnr("random", 16)
        self.query_nbns("WPAD")
        self.query_nbns("random")
        self.logResults()



def runBash(cmd, lstdout=False, lstderr=True):
    p = Popen(cmd, shell=True, stdout=PIPE)
    out = p.stdout
    err = p.stderr
    
    if lstdout and out:
        log.info(out.read().strip())
    if lstderr and err:
        log.error(err.read().strip())
        
    p.wait()
        
    return out


def processArgs():
    parser = argparse.ArgumentParser(description='T-1000, automatic polymorphic low-interaction honeypot', prog='t1000')
    
    parser.add_argument('--scan', action='store_true', help='Perform scan on impersonation target.')
    parser.add_argument('--forcerand', action='store_true', help='Force a random impersonation target. Ignores target option and conf target when set.')
    parser.add_argument('--iface', nargs=1, help='Interface to sniff during scan.')
    parser.add_argument('--target', nargs=1, metavar='<hostname>', help="Target to impersonate, overwrites config.")
    parser.add_argument('--patrol', action='store_true', help='Check impersonation services against listening ports. Bounce services as needed.')
    parser.add_argument('--respondered', action='store_true', help='query for responder detction (LLMNR and NetBIOS Responder Detection)')
    parser.add_argument('--kill', action='store_true', help='Stop all honey services.')
    parser.add_argument('--conf', nargs=1, metavar='<conf path>', help='Configuration file to scan and watch services')
    parser.add_argument('--cron', action='store_true', help='prints recommended cron entry.')

    return parser.parse_args()


def loadT1000Config(confPath):
    try:
        with open(confPath, "r") as fname:
            print("[-] Loading t1000 config file: %s" % confPath)
            return json.load(fname)
    except IOError as e:
        print("[-] Failed to open %s for reading (%s)" % (confPath, e))
        return {}
    except Exception as e:
        print("[-] An error occured loading %s (%s)" % (confPath, e))
        return {}


def getIPAddress(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def getNetCIDR(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return IPNetwork('0.0.0.0/%s' % socket.inet_ntoa(fcntl.ioctl(s, 35099, struct.pack('256s', ifname))[20:24])).prefixlen

def ipInBlacklist(ip):
    if os.path.exists('/etc/opencanaryd/t1000.blacklist'):
        blacklist = []
        with open('/etc/opencanaryd/t1000.blacklist') as blacklistFile:
            blacklist = blacklistFile.read().strip().splitlines()

        for blackip in blacklist:
            if '-' in blackip:
                start, end = blackip.split('-')
                if IPAddress(ip) in iter_iprange(start, end):
                    return True
            else:
                if IPAddress(ip) == IPAddress(blackip):
                    return True
    return False


def aquireRandomTarget(iface):
    ip = getIPAddress(iface)
    cidr = getNetCIDR(iface)

    ps = nmap.PortScanner()

    nmapResults = ps.scan(hosts='%s/%d' % (ip, cidr), arguments='-sn')

    primaryList = []
    secondaryList = []

    for targetip, host in nmapResults['scan'].items():
        if targetip != ip and not ipInBlacklist(targetip):
            if host['status']['state'] == 'up':
                if 'hostname' not in host or not host['hostname']:
                    secondaryList.append((targetip, host['addresses']['mac']))
                elif host['status']['reason'] == 'conn-refused':
                    secondaryList.append((host['hostname'], host['addresses']['mac']))
                elif int(targetip.split('.')[-1]) < 20:
                    secondaryList.append((host['hostname'], host['addresses']['mac']))
                else:
                    primaryList.append((host['hostname'], host['addresses']['mac']))
            else:
                if host['hostname']:
                    secondaryList.append((host['hostname'], host['addresses']['mac']))
                else:
                    secondaryList.append((targetip, host['addresses']['mac']))

    if primaryList:
        return random.choice(primaryList)
    elif secondaryList:
        return random.choice(secondaryList)
    else:
        return ('localhost', '')


def patrolServices(conf):

    opencanaryRestart = False

    mitmdumpRestart = False

    listeningPorts = runBash("netstat -na | egrep -i 'listen\s' | egrep '0\.0\.0\.0:' | cut -d ':' -f2 | awk '{print($1}'").read().splitlines()

    for servicePort, serviceDetails in conf.iteritems():
        if servicePort != 'target' and servicePort not in listeningPorts:
            if serviceDetails['type'] == 'opencanary':
                opencanaryRestart = True
            elif serviceDetails['type'] == 'reverseproxy':
                mitmdumpRestart = True

    if opencanaryRestart:
        runBash('/usr/local/bin/opencanaryd --stop; /usr/local/bin/opencanaryd --start')

    if mitmdumpRestart:
        runBash('sudo killall -9 mitmdump')

        for servicePort, serviceDetails in conf.iteritems():
            if servicePort != 'target' and serviceDetails['type'] == 'reverseproxy':

                if servicePort > 1024:
                    mitmdumpCommand = ['/usr/local/bin/mitmdump']
                else:
                    mitmdumpCommand = ['/usr/bin/sudo', '/usr/local/bin/mitmdump']

                mitmdumpCommand.extend(serviceDetails['options']['args'].split())
                print("[-] mitmdump command: %s" % (mitmdumpCommand))

                os.system(' '.join(mitmdumpCommand))


def killServices():
    runBash('/usr/local/bin/opencanaryd --stop; /usr/local/bin/opencanaryd --start')
    runBash('sudo killall -9 mitmdump')
    runBash('sudo service smbd stop')


def main():

    options = processArgs()

    if options.cron:
        print('%s /usr/local/bin/t1000.py --patrol --conf /etc/opencanaryd/t1000.conf' % (sys.executable))

    if options.respondered:
        respondered = Respondered()
        respondered.generate()
        exit()
    
    if options.conf:
        conf = loadT1000Config(options.conf[0])

        if 'target' in conf:
            confTarget = conf['target'].lower()
        else:
            confTarget = ''

        if 'mac' in conf:
            mac = conf['mac']
        else:
            mac = ''
    else:
        conf = {}
        confTarget = ''
        mac = ''

    if options.target:
        optTarget = options.target[0].lower()
    else:
        optTarget = ''

    if options.iface:
        iface = options.iface[0]
    else:
        iface = 'eth0'


    if options.scan:

        if optTarget == 'custom' or confTarget == 'custom':
            print('Error: target set to custom, scan is not applicable.')
            exit()
        elif options.forcerand:
            hostname, mac = aquireRandomTarget(iface)
        elif optTarget == 'random_rotating':
            hostname, mac = aquireRandomTarget(iface)
        elif optTarget == 'random_sticky':
            if confTarget == 'localhost' or not confTarget:
                hostname, mac = aquireRandomTarget(iface)
            else:
                hostname = confTarget
        elif optTarget == 'random':
            hostname = 'localhost'
        elif optTarget:
            hostname = optTarget
        elif confTarget:
            hostname = confTarget
        else:
            print('Error: scan requires a configuration file with target (--conf), a cli target (--target), or forced random host (--forcerand)')
            exit()

        killServices()

        imp = Imposter(hostname, mac, iface)

        imp.scanMirrorHost()

        imp.updateOpenCanaryConf()

        imp.updateReverseProxyConf()

        imp.updateT1000()

        #imp.updateSamba()
        

    if options.patrol:
        if conf:
            patrolServices(conf)
        else:
            print('Error: patrol requires a configuration file, use --conf')

    if options.kill:
        killServices()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()

