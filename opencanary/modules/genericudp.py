from opencanary.modules import CanaryService

from zope.interface import implements
from twisted.application import internet
from twisted.internet.protocol import DatagramProtocol

from twisted.application.internet import UDPServer
from twisted.internet.address import IPv4Address

from twisted.internet import protocol

class MiniUDP(DatagramProtocol):
    def datagramReceived(self, data, (host, port)):
        try:
            self.buffer += data
            print "Recieved data: ", repr(data)
            logdata={'DATA': self.buffer.strip("\r\n\x00")}
            self.transport.getPeer = lambda: IPv4Address('UDP', host, port)
            self.factory.log(logdata=logdata, transport=self.transport)
        except Exception as e:
            print e
        pass


class CanaryGenericUDP(CanaryService):
    NAME = 'genericudp'

    def __init__(self, config=None, logger=None, instanceParams={}):
        CanaryService.__init__(self, config=config, logger=logger)
        if instanceParams:
            self.port = int(instanceParams['genericudp.port'])
        else:
            self.port = int(config.getVal('genericudp.port', default=161))
        self.logtype = logger.LOG_GENERIC_UDP
        self.listen_addr = config.getVal('device.listen_addr', default='')

    def getService(self):
        f = MiniUDP()
        f.factory = self
        return internet.UDPServer(self.port, f, interface=self.listen_addr)
