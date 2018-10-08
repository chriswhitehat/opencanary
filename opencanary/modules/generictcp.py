import codecs
from opencanary.modules import CanaryService

from twisted.protocols.policies import TimeoutMixin
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet
from twisted.internet.defer import Deferred

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
            logdata = {'msg': 'Null Probe Response', 'DATA': codecs.escape_encode(self.factory.probes['Null Probe'])}
            self.factory.log(logdata, transport=self.transport)

    # def display_data(self, data):
    #     self._buffer_escaped = codecs.escape_encode(self._buffer)[0]

    #     logdata = {'Witnessed Probe': self._buffer_escaped}
    #     self.factory.log(logdata, transport=self.transport)

    #     logdata = {'msg': 'Probe Response', 'DATA': codes.escape_encode(self.factory.probes[self._buffer_escaped])[0]}
    #     self.factory.log(logdata, transport=self.transport)
    #     self.transport.write(self.factory.probes[self._buffer_escaped])

    # def error_func(self, error):
    #     logdata = 'Whoops here is the error: {0}'.format(error)
    #     self.factory.log(logdata, transport=self.transport)

    def dataReceived(self, data):
        # d = Deferred()
        # d.addCallback(self.display_data)
        # d.addErrback(self.error_func)
        # d.callback(data)
        
        self._buffer += data
        self.resetTimeout()

        self._buffer_escaped = codecs.escape_encode(self._buffer)[0]

        if self._busyReceiving:
            return

        try:
            self._busyReceiving = True
            logdata = {'Witnessed Probe': self._buffer_escaped}
            self.factory.log(logdata, transport=self.transport)

            if self._buffer_escaped in self.factory.probes:
                logdata = {'msg': 'Probe Response', 'DATA': codecs.escape_encode(self.factory.probes[self._buffer_escaped])[0]}
                self.factory.log(logdata, transport=self.transport)
                self.transport.write(self.factory.probes[self._buffer_escaped])


            # for probe, response in self.factory.probes.items():
            #     if probe in self._buffer_escaped:
            #         self.transport.write(response)
            #         logdata = {'msg': 'Probe Response', 'DATA': codes.escape_encode(response)[0]}
            #         self.factory.log(logdata, transport=self.transport)
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

        self.blacklist = config.getVal('generictcp.blacklist', [139])

        self.logtype = logger.LOG_GENERIC_TCP
        self.listen_addr = config.getVal('device.listen_addr', default='')

        if self.port in self.blacklist:
            self.probes = {}
        elif self.probes:
            for probe, response in self.probes.items():
                self.probes[probe] = codecs.escape_decode(response)[0]

    def getService(self):
        factory = self
        factory.canaryservice = self
        factory.logger = self.logger
        factory.probes = self.probes
        factory.blacklist = self.blacklist
        factory.factory = self
        return internet.TCPServer(self.port, factory, interface=self.listen_addr)

CanaryServiceFactory = CanaryGenericTCP
