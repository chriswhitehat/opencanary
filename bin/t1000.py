import nmap
import os, ssl, sys, json, argparse, re
from OpenSSL import crypto
from socket import gethostname, gethostbyname, getfqdn
from simplejson import dumps
from collections import OrderedDict
from subprocess import Popen, PIPE

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
        super().join(timeout)
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
    def __init__(self, mirrorHost, force=False):
        super(Imposter, self).__init__()
        self.mirrorHost = mirrorHost
        self.mirrorIP = gethostbyname(self.mirrorHost)
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
                print "[-] Loading default config file: %s" % defaultPath
                self.__config = json.load(fname)
                return
        except IOError as e:
            print "[-] Failed to open %s for reading (%s)" % (defaultPath, e)
        except Exception as e:
            print "[-] An error occured loading %s (%s)" % (defaultPath, e)


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
        sniffer = Sniffer(self.mirrorIP)
        sniffer.run()

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
                        self.probe_mapping[port][probe.__repr__()] = answer.__repr__()

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
            t1000Config = {'target': self.mirrorHost}
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
    parser.add_argument('--target', nargs=1, metavar='<hostname>', help="Target to impersonate, overwrites config.")
    parser.add_argument('--patrol', action='store_true', help='Check impersonation services against listening ports. Bounce services as needed.')
    parser.add_argument('--kill', action='store_true', help='Stop all honey services.')
    parser.add_argument('--conf', nargs=1, metavar='<conf path>', help='Configuration file to scan and watch services')
    parser.add_argument('--cron', action='store_true', help='prints recommended cron entry.')

    return parser.parse_args()


def loadT1000Config(confPath):
    try:
        with open(confPath, "r") as fname:
            print "[-] Loading t1000 config file: %s" % confPath
            return json.load(fname)
    except IOError as e:
        print "[-] Failed to open %s for reading (%s)" % (confPath, e)
    except Exception as e:
        print "[-] An error occured loading %s (%s)" % (confPath, e)


def aquireRandomTarget(conf):
    return 'localhost'

def patrolServices(conf):

    opencanaryRestart = False

    mitmdumpRestart = False

    listeningPorts = runBash("netstat -na | egrep -i 'listen\s' | egrep '0\.0\.0\.0:' | cut -d ':' -f2 | awk '{print $1}'").read().splitlines()

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
                print "[-] mitmdump command: %s" % (mitmdumpCommand)

                os.system(' '.join(mitmdumpCommand))


def killServices():
    runBash('/usr/local/bin/opencanaryd --stop; /usr/local/bin/opencanaryd --start')
    runBash('sudo killall -9 mitmdump')
    runBash('sudo service smbd stop')


def main():

    options = processArgs()

    if options.cron:
        print('%s /usr/local/bin/t1000.py --patrol --conf /etc/opencanaryd/t1000.conf' % (sys.executable))

    if options.conf:
        conf = loadT1000Config(options.conf[0])
    else:
        conf = None

    if options.scan and (options.target or conf):

        if options.target:
            hostname = options.target[0].lower()
        else:
            hostname = conf['target'].lower()

        if hostname == 'custom':
            print('Error: target set to custom, scan is not applicable.')
            exit()

        if hostname == "random":
            hostname = aquireRandomTarget(conf)

        killServices()

        imp = Imposter(hostname)

        imp.scanMirrorHost()

        imp.updateOpenCanaryConf()

        imp.updateReverseProxyConf()

        imp.updateT1000()

        #imp.updateSamba()
    else:
        print('Error: scan requires a configuration file (--conf) or a target (--target)')

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

