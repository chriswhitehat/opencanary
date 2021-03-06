import traceback

from twisted.application import service
from twisted.application import internet
from twisted.internet.protocol import Factory
from pkg_resources import iter_entry_points

from opencanary.config import config
from opencanary.logger import getLogger
from opencanary.modules.http import CanaryHTTP
from opencanary.modules.ftp import CanaryFTP
from opencanary.modules.ssh import CanarySSH
from opencanary.modules.telnet import Telnet
from opencanary.modules.httpproxy import HTTPProxy
from opencanary.modules.mysql import CanaryMySQL
from opencanary.modules.mssql import MSSQL
from opencanary.modules.ntp import CanaryNtp
from opencanary.modules.tftp import CanaryTftp
from opencanary.modules.vnc import CanaryVNC
from opencanary.modules.sip import CanarySIP
from opencanary.modules.generictcp import CanaryGenericTCP
from opencanary.modules.genericudp import CanaryGenericUDP

#from opencanary.modules.example0 import CanaryExample0
#from opencanary.modules.example1 import CanaryExample1

ENTRYPOINT = "canary.usermodule"
MODULES = [Telnet, CanaryHTTP, CanaryFTP, CanarySSH, HTTPProxy, CanaryMySQL,
           MSSQL, CanaryVNC, CanaryTftp, CanaryNtp, CanarySIP, CanaryGenericTCP, 
           CanaryGenericUDP ]
           #CanaryExample0, CanaryExample1]
try:
    #Module needs RDP, but the rest of OpenCanary doesn't
    from opencanary.modules.rdp import CanaryRDP
    MODULES.append(CanaryRDP)
except ImportError:
    pass


try:
    #Module need Scapy, but the rest of OpenCanary doesn't
    from opencanary.modules.snmp import CanarySNMP
    MODULES.append(CanarySNMP)
except ImportError:
    pass

# NB: imports below depend on inotify, only available on linux
import sys
if sys.platform.startswith("linux"):
    from opencanary.modules.samba import CanarySamba
    from opencanary.modules.portscan import CanaryPortscan
    MODULES.append(CanarySamba)
    MODULES.append(CanaryPortscan)

logger = getLogger(config)

def start_mod(application, klass, instances=[]):
    objs = []
    if instances:
        for instance in instances: 
            try:
                objs.append(klass(config=config, logger=logger, instanceParams=instance))
            except Exception as e:
                logMsg({'logdata': {'msg': 'Failed to instantiate instance', 'service': klass.__name__, 'module': klass.__module__, 'traceback': traceback.format_exc()}})
    else:
        try:
            objs.append(klass(config=config, logger=logger))
        except Exception as e:
            logMsg({'logdata': {'msg': 'Failed to instantiate instance', 'service': klass.__name__, 'module': klass.__module__, 'traceback': traceback.format_exc()}})

    for obj in objs:

        

        if hasattr(obj, 'startYourEngines'):
            try:
                obj.startYourEngines()
                logMsg({'logdata': {'msg': 'Ran startYourEngines', 'service': klass.__name__, 'module': klass.__module__, 'port': obj.port}})

            except Exception as e:
                logMsg({'logdata': {'msg': 'Failed to run startYourEngines', 'service': klass.__name__, 'module': klass.__module__, 'port': obj.port, 'traceback': traceback.format_exc()}})
        elif hasattr(obj, 'getService'):
            try:
                service = obj.getService()
                service.setServiceParent(application)
                logMsg({'logdata': {'msg': 'Added service to fake', 'service': klass.__name__, 'module': klass.__module__, 'port': obj.port}})
            except Exception as e:
                logMsg({'logdata': {'msg': 'Failed to add service', 'service': klass.__name__, 'module': klass.__module__, 'port': obj.port, 'traceback': traceback.format_exc()}})
        else:
            logMsg({'logdata': {'msg': 'Module is missing required starting method', 'service': klass.__name__, 'module': klass.__module__, 'port': obj.port}})

def logMsg(data):
    logger.log(data, retry=False)

application = service.Application("opencanaryd")

# List of modules to start
start_modules = []

# Add all custom modules
# (Permanently enabled as they don't officially use settings yet)
for ep in iter_entry_points(ENTRYPOINT):
    try:
        klass = ep.load(require=False)
        start_modules.append(klass)
    except Exception as e:
        logMsg({'logdata': {'msg': 'Faled to load class from the entrypoint', 'service': str(ep), 'traceback': traceback.format_exc()}})

# Add only enabled modules
start_modules.extend(filter(lambda m: config.moduleEnabled(m.NAME), MODULES))

for klass in start_modules:
    klassName = klass.NAME.lower()
    if config.getVal(klassName+'.instances', default=''):
        start_mod(application, klass, config.getVal(klassName+'.instances'))
    else:
        start_mod(application, klass)



logMsg({'logdata': {'msg': "OpenCanary running!!!"}})
