import codecs
from opencanary.modules import CanaryService

from twisted.protocols.policies import TimeoutMixin
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

class MiniTCP(Protocol, TimeoutMixin):

    def __init__(self):
        self._busyReceiving = False
        self.prompts = 0
        self._buffer = ""

    def connectionMade(self):
        logdata={'msg': 'Connection Made'}
        self.factory.log(logdata, transport=self.transport)
        if 'Null Probe' in self.factory.probes:
            self.transport.write(self.factory.probes['Null Probe'])
            logdata = {'msg': 'Null Probe Response', 'DATA': self.factory.probes['Null Probe'].strip("\r\n\x00")}
            self.factory.log(logdata, transport=self.transport)

    def dataReceived(self, data):
        self._buffer += data
        self.resetTimeout()

        if self._busyReceiving:
            return

        try:
            self._busyReceiving = True

            for probe, response in self.factory.probes.items():
                logdata = {'msg': 'Probe', 'DATA': probe.strip("\r\n\x00")}
                self.factory.log(logdata, transport=self.transport)
                logdata = {'msg': 'Buffer', 'DATA': self._buffer.strip("\r\n\x00")}
                self.factory.log(logdata, transport=self.transport)
                if probe in self._buffer.__repr__():
                    logdata = {'msg': 'Probe Recieved', 'DATA': self._buffer.strip("\r\n\x00")}
                    self.factory.log(logdata, transport=self.transport)
                    self.transport.write(response)
                    logdata = {'msg': 'Probe Response', 'DATA': response.strip("\r\n\x00")}
                    self.factory.log(logdata, transport=self.transport)
        finally:
            self._busyReceiving = False

    def timeoutConnection(self):
        self.transport.abortConnection()

                
class CanaryGenericTCP(Factory, CanaryService):
    NAME = 'generictcp'
    protocol = MiniTCP

    def __init__(self, config=None, logger=None, instanceParams={}):
        CanaryService.__init__(self, config=config, logger=logger)

        if instanceParams:
            self.port = int(instanceParams['generictcp.port'])
            self.probes = instanceParams['generictcp.probes']
        else:
            self.port = int(config.getVal('generictcp.port', default=161))
            self.probes = config.getVal('generictcp.probes', {})
        self.logtype = logger.LOG_GENERIC_TCP
        self.listen_addr = config.getVal('device.listen_addr', default='')

        if self.probes:
            for probe, response in self.probes.items():
                self.probes[probe] = codecs.escape_decode(response)[0]

    def getService(self):
        factory = self
        factory.canaryservice = self
        factory.logger = self.logger
        factory.probes = self.probes
        factory.factory = self
        return internet.TCPServer(self.port, factory, interface=self.listen_addr)

CanaryServiceFactory = CanaryGenericTCP
