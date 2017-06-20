import nmap
import os, ssl
from OpenSSL import crypto
from socket import gethostname


class ImposterService(object):
    """docstring for ImposterService"""
    def __init__(self, mirrorHost, port, protocol, details, certDir='/etc/nginx/ssl/'):
        super(ImposterService, self).__init__()
        self.mirrorHost = mirrorHost
        self.port = port
        self.protocol = protocol
        self.details = details
        self.certDir = certDir
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
                    (['netbios', 'microsoft-ds'], 'samba'),
                    (['ntp'], 'ntp'),
                    (['rdp'], 'rdp'),
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
                    self.type = 'loadbalance'
                break

        if not self.name:
            if self.protocol == 'tcp':
                self.name = 'generictcp'
            else:
                self.name = 'genericudp'

        if 'script' in self.details:
            self.banner = self.details.get('banner', None)
            self.ssl = self.details.get('ssl-cert', None)

        if self.ssl:
            self.mirrorCertificate()


    def mirrorCertificate(self, keyLength=2048):
        certFile = "%s_%s.crt" % (self.name, self.port)
        keyFile = "%s_%s.key" % (self.name, self.port)

        mirrorCert = ssl.get_server_certificate((self.mirrorHost, int(self.port)), ssl_version=ssl.PROTOCOL_TLSv1)
        mirrorx509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, mirrorCert)
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

        self.certFilePath = os.path.join(certDir, certFile)
        self.keyFilePath = os.path.join(certDir, keyFile)

        open(self.certFilePath, "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(self.keyFilePath, "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


    def getOpenCanaryConf(self):
        conf = {self.name + '.enabled': True}

    def getOpenCanaryInstance(self):
        instance = {self.name + '.port': self.port,
                    self.name + '.banner': self.banner}

        if self.name == 'ssh':
            instance[self.name + '.version'] = self.banner

        return instance
            

class Imposter(object):
    """Enumerate ports and services on mirror host and generates opencanary configs as well as nginx loadbalancing configs"""
    def __init__(self, mirrorHost, force=False):
        super(Imposter, self).__init__()
        self.mirrorHost = mirrorHost
        self.servcies = []
        

    def scanMirrorHost(self):
        ps = nmap.PortScanner()
    
        self.nmapResults = ps.scan(hosts=self.mirrorHost, ports='1-65535', arguments='-sV -T5 --script banner --script ssl-cert')['scan'][self.mirrorHost]

        if nmapResults['status']['state'] == 'up':
            self.mirrorHostLive = True
            for port, details in self.nmapResults['tcp'].iteritems():
                self.services.append(ImposterService(self.mirrorHost, port, 'tcp', details))

            for port, details in self.nmapResults['udp'].iteritems():
                self.services.append(ImposterService(self.mirrorHost, port, 'udp', details))


    def generateOpenCanaryConf(self):
        opencanaryConf = {}
        for service in [x for x in self.servcies if x.type == 'opencanary']:
            opencanaryConf['%s.enabled' % service.name] = 'true'

            instances = '%s.instances' % service.name
            if instances not in opencanaryConf:
                opencanaryConf[instances] = []

            opencanaryConf[instances].append(service.getOpenCanaryInstance)


'''
def addService(services, host, service, port, details):
    instances = '%s.instances' % service
    if instances not in services:
        services[instances] = []
    
    services[instances].append = {service + '.port': port}    

    if 'script' in details:
        if 'banner' in details['script']:
            services[instances][-1][service + '.banner'] = details['script']['banner']


def addLoadBalance(loadBalancers, host, port, details):
    if 'script' in details:
        if 'ssl-cert' in details['script']:
            mirrorCertificate(certDir, appName, mirrorHost, port)
'''
