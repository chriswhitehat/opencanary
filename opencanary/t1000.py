import nmap
import os, ssl, sys, json
from OpenSSL import crypto
from socket import gethostname, gethostbyname
from simplejson import dumps
from collections import OrderedDict

from pkg_resources import resource_filename


class ImposterService(object):
    """docstring for ImposterService"""
    def __init__(self, mirrorHost, port, protocol, details, certDir='/etc/nginx/ssl/'):
        super(ImposterService, self).__init__()
        self.mirrorHost = mirrorHost
        self.port = port
        self.protocol = protocol
        self.details = details
        self.certDir = certDir
        self.banner = None
        self.ssl = None
        self.name = None
        self.type = 'opencanary'
        self.parseNmapResults()

    def parseNmapResults(self):
        serviceMap = [(['proxy'], 'httpproxy'),
                    (['http'], 'nginx'),
                    (['tftp'], 'tftp'),
                    (['ftp'], 'ftp'),
                    (['ms-sql'], 'mssql'),
                    (['mysql'], 'mysql'),
                    #(['netbios', 'microsoft-ds'], 'samba'),
                    (['netbios', 'microsoft-ds'], 'generictcp'),
                    (['ntp'], 'ntp'),
                    (['ms-wbt', 'rdp'], 'rdp'),
                    (['sip'], 'sip'),
                    (['ssh'], 'ssh'),
                    (['snmp'], 'snmp'),
                    (['telnet'], 'telnet'),
                    (['vnc'], 'vnc')
                    ]

        for nmapServiceNames, potServiceName in serviceMap:
            if [x for x in nmapServiceNames if x in self.details['name']]:
                self.name = potServiceName
                if self.name == 'nginx':
                    self.type = 'reverseproxy'
                break

        if not self.name:
            if self.protocol == 'tcp':
                self.name = 'generictcp'
            else:
                self.name = 'genericudp'

        if 'script' in self.details:
            self.banner = self.details['script'].get('banner', None)
            self.ssl = self.details['script'].get('ssl-cert', None)

        if self.ssl:
            self.mirrorCertificate()


    def mirrorCertificate(self, keyLength=2048):
        certFile = "%s_%s.crt" % (self.name, self.port)
        keyFile = "%s_%s.key" % (self.name, self.port)

        try:
            mirrorCert = ssl.get_server_certificate((self.mirrorHost, int(self.port)), ssl_version=ssl.PROTOCOL_SSLv23)
        except:
            return
            
        mirrorx509 = crypto.load_certificate(crypto.FILETYPE_PEM, mirrorCert)
        mirrorSubject = mirrorx509.get_subject().get_components()

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
        cert.get_subject().CN = gethostname()
        cert.sign(k, mirrorx509.get_signature_algorithm())

        self.certFilePath = os.path.join(self.certDir, certFile)
        self.keyFilePath = os.path.join(self.certDir, keyFile)

        open(self.certFilePath, "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(self.keyFilePath, "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


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
                    self.name + '.banner': self.banner}

        if self.name == 'ssh':
            instance['ssh.version'] = self.banner
        elif self.name == 'http':
            instance['http.skin'] = 'nasLogin'
        elif self.name == 'httpproxy':
            instance['httpproxy.skin'] = 'squid'
        elif self.name == 'telnet':
            instance           

        return instance
            

class Imposter(object):
    """Enumerate ports and services on mirror host and generates opencanary configs as well as nginx reverse proxy configs"""
    def __init__(self, mirrorHost, force=False):
        super(Imposter, self).__init__()
        self.mirrorHost = mirrorHost
        self.mirrorIP = gethostbyname(self.mirrorHost)
        self.services = []
        self.__config = None

    def loadOpenCanaryDefaults(self):
        try:
            with open('/etc/opencanaryd/default.json', "r") as fname:
                print "[-] Loading default config file: /etc/opencanaryd/default.json"
                self.__config = json.load(fname)
                return
        except IOError as e:
            print "[-] Failed to open %s for reading (%s)" % (fname, e)
        except ValueError as e:
            print "[-] Failed to decode json from %s (%s)" % (fname, e)
            subprocess.call("cp -r %s /var/tmp/config-err-$(date +%%s)" % fname, shell=True)
        except Exception as e:
            print "[-] An error occured loading %s (%s)" % (fname, e)
        

    def updateOpenCanaryConf(self):

        self.loadOpenCanaryDefaults()

        for service in [x for x in self.services if x.type == 'opencanary']:
            self.__config.update(service.getOpenCanaryConf())

            instances = '%s.instances' % service.name
            if instances not in self.__config:
                self.__config[instances] = []

            self.__config[instances].append(service.getOpenCanaryInstance())

        if os.path.exists('/etc/opencanaryd/opencanary.conf'):
            os.rename('/etc/opencanard/opencanary.conf', '/etc/opencanard/opencanary.conf.bak')

        with open('/etc/opencanaryd/opencanary.conf', 'w') as fname:
            json.dump(self.__config, fname, sort_keys=True, indent=4, separators=(',', ': '))


    def scanMirrorHost(self, ports='1-65535', arguments='-sV -Pn -T5 --script banner --script ssl-cert'):
        ps = nmap.PortScanner()
    
        self.nmap = ps.scan(hosts=self.mirrorHost, ports=ports, arguments=arguments)
        if self.mirrorIP in self.nmap['scan']:
            self.nmapResults = self.nmap['scan'][self.mirrorIP]

            if self.nmapResults['status']['state'] == 'up':
                self.mirrorHostLive = True
                if 'tcp' in self.nmapResults:
                    for port, details in self.nmapResults['tcp'].iteritems():
                        if details['state'] != 'filtered':
                            self.services.append(ImposterService(self.mirrorHost, port, 'tcp', details))
                if 'udp' in self.nmapResults:
                    for port, details in self.nmapResults['udp'].iteritems():
                        if details['state'] != 'filtered':
                            self.services.append(ImposterService(self.mirrorHost, port, 'udp', details))


    def generateReverseProxyConf(self):
        ''''''


def main():

    if len(sys.argv) < 2 or not sys.argv[1]:
        print('Error: missing argument - %s' % sys.argv)
        exit()

    imp = Imposter(sys.argv[1])

    imp.scanMirrorHost()

    print(imp.updateOpenCanaryConf())


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()
