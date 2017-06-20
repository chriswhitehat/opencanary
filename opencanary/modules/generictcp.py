from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet

class MiniTCP(Protocol):

    def __init__(self):
        self.prompts = 0

    def connectionMade(self):
        self.prompts += 1

    def dataReceived(self, data):
        self.buffer += data
        print "Recieved data: ", repr(data)
        logdata={'DATA': self.buffer.strip("\r\n\x00")}
        self.factory.log(logdata, transport=self.transport)
        
        if self.prompts < 3:
            self.prompts += 1
        else:
            self.transport.loseConnection()
                
class CanaryGenericTCP(Factory, CanaryService):
    NAME = 'generictcp'

    def __init__(self, config=None, logger=None, instanceParams={}):
        CanaryService.__init__(self, config, logger)
        if instanceParams:
            self.port = int(instanceParams['generictcp.port'])
        else:
            self.port = int(config.getVal('generictcp.port', default=161))
        self.logtype = logger.LOG_GENERIC_TCP

    def getService(self):
        f = MiniTCP()
        f.factory = self
        return internet.TCPServer(self.port, f, interface=self.listen_addr)

CanaryServiceFactory = CanaryExample0
