#============================================================================================
# Designed & Developed by "Mohamed ELMesseiry"
# Contacts: mohamed.mamdouh@itlogiakuwait.com, m.messeiry@gmail.com, +965 97490408
# Date: 1-March-2015
# Version: 0.1 (Beta)
# the following is a script used to parse Base24 Messages for transactions Notifications
#============================================================================================
import os,json, calendar, logging
from datetime import datetime
from dateutil import parser as DUp
from socket import *
#============================================================================================
# Config Items
#============================================================================================
logging.basicConfig(filename='b24.log',level=logging.DEBUG, format='%(asctime)s::%(name)s::%(levelname)s::%(message)s')

# Backend/Socket collector  data
serverHost = 'localhost'            # servername is localhost
serverPort = 2060                   # use arbitrary port > 1024 (backend port)
#serverPort = 2000                  # use arbitrary port > 1024 (backend port)

pollingDuration = "5" # in minutes
start = -1 #"1359147600000"
end = -1
count = 0
sleepDuration = 60

doSendToBackend = False
printData = False
s = None

# SNMP traps
sendTraps=True
oid = '.1.2.3.4.5.6'
NmsIP = '192.168.1.147'
thisServerIp='192.168.1.80'
doSendTrapToSmarts =True
printTrap = True


#============================================================================================
# Convert Data to Raw Data Format
#============================================================================================

def toRawData(timestamp,group,var,val,device,devtype,unit,name,source,other):
    result =  "+r\t"+timestamp+"\t"+group+"\t"+var+"\t"+val+"\tdevice="+device+"\tdevtype="+devtype+"\tunit=""\tname="+name+"\tsource="+source
    if other:
        result += "\t"+other
    return result

#============================================================================================
# SEND DATA to Socket
#============================================================================================

def sendToBackend(dataToSend):
    global s
    if not s:
        s = socket(AF_INET,SOCK_STREAM)    # create a TCP socket
        s.connect((serverHost,serverPort)) # connect to server on the port
    if not "\n" in dataToSend: dataToSend+= "\n"
    s.send(dataToSend.encode('utf-8')) # send the data

def sendToAPG(data):
    if doSendToBackend:
        sendToBackend(data)
    else:
        logging.warn("Raw Data NOT Sent to APG, Please Enable Sending to APG in configuration")
    if printData: print data

#============================================================================================
# SEND TRAP TO SMARTS
# sendTrap('10.222.21.30', '10.10.10.10', '.1.2.3.4.5.6', '1', '2', {'.1.2.3.4.5.6.1.2.1':'var1','.1.2.3.4.5.6.1.2.2':'var2'})
#============================================================================================
def sendTrap(host, agent, EnterpriseOID, type, specific, vars):
    if not sendTrap: return

    trap = "snmptrap -v 1 -c public %(host)s '%(EnterpriseOID)s' '%(agent)s' %(type)s %(specific)s '55' 2>/dev/null" \
               % {"host": host, "EnterpriseOID": EnterpriseOID, "agent":agent, "type":type, "specific":specific}
    for oid,value in vars.items(): trap += " %(oid)s  s \"%(value)s\"" % {"oid": oid, "value": value}
    if doSendTrapToSmarts:
        os.system(trap)
        logging.info("Trap Sent to Smarts:: %s", trap)
    else:
        logging.warn("Traps Disabled from Sending, Enable Trap Sending in configuration")


    if printTrap: print trap

#============================================================================================
# Parse Notification File from Base24
#============================================================================================
def getLastinMarker():
    val = file("b24.marker", "r").readlines()[-1]
    if val == "\n":
        return 0
    else:
        return val.replace("\n","")

def extractAlarms(alarms):
    lastTime = getLastinMarker()
    #print "Last Time in Marker: " + repr(lastTime)
    logging.info("last Time in Marker %s", repr(lastTime))
    jsonObj = []

    for alarm in alarms:
        alarm = alarm.replace("\b","").replace("\x61","").replace("x1b6","").replace("\x1b","").replace("\x04","").replace("6 A6$","").replace("\r\n", "*MESS*").replace("\r", "").replace("\n"," ").replace("  ","").replace(": ",":").replace("^","-").replace("'","").replace("\"","").replace(","," ")
        indexOFSSID = alarm.find("SSID:")

        # remove any string before timer
        alarm = repr(alarm[indexOFSSID-13:])

        indexOFGen = alarm.find("GENERATOR:")
        indexOFFirstEnter = alarm.find("*MESS*")
        indexOFSSID = alarm.find("SSID:")

        currentDate = datetime.now().strftime("%Y-%m-%d")
        timer = currentDate + " " + alarm[:13].replace("'","").replace("\"","").strip()
        foo = DUp.parse(timer)
        timestamp = calendar.timegm(foo.timetuple())

        ssid = alarm[indexOFSSID+5:indexOFGen].strip()
        generator = alarm[indexOFGen+10:indexOFFirstEnter].strip()
        message = alarm[indexOFFirstEnter:].replace("*MESS*","").replace("'","").replace("\"","").strip()

        # Status List : just-parsed sent-smarts sent-apg
        jsonStr = {"unixtime":timestamp, "time":timer,"ssid":ssid, "generator":generator, "messege":message, "status":"just-parsed", "value":1}


        # Should only Send the Notification after a certain Date
        # Example Date: > 1424789643
        if (timestamp >= lastTime):
            if (message != "" or  ssid != ""):
                jsonObj.append(jsonStr)
                logging.info("Notification Added::%s", jsonStr)
                rawdata= toRawData(str(timestamp),"B24",generator,"1",ssid,"transaction","",generator,"B24-Source","message="+message)
                logging.info("Raw Data to Send:: %s", rawdata)
                sendToAPG(rawdata)
                varbinds = {'.1.2.3.4.5.6.1.2.1':ssid,'.1.2.3.4.5.6.1.2.2':generator,'.1.2.3.4.5.6.1.2.3':message,'.1.2.3.4.5.6.1.2.4':timestamp,'.1.2.3.4.5.6.1.2.5':timer}
                sendTrap(NmsIP,thisServerIp,oid,'1','2',varbinds)

    jsonAlarms = json.dumps(jsonObj)

    # create a python dictionary
    pyDic = json.loads(jsonAlarms)


    #sorted_array = sorted(pyDic, key=pyDic.status)
    #newlist = sorted(pyDic, key=lambda k: k['unixtime'], reverse=True)
    #latestTime = newlist[0]['unixtime']

    if (len(pyDic) == 0):
        logging.info("No New Alarms to Process Right Now")
    else:
        #print(pyDic)
        maxTime = (max(pyDic, key=lambda x:x['unixtime']))['unixtime']
        open("b24.marker","a+b").write(str(maxTime)+"\n")
        logging.info("Latest Time in File::%s", str(maxTime))


    print getLastinMarker()

def main():
    file = open("ezz.cap.cap")

    alarms = [""]
    for i,line in enumerate(file):
        if (line.startswith(u"\u0004")):
            #print "Starting new alarm"
            alarms.append(line)
        else:
            #print "committing to current alarm"
            alarms[len(alarms) -1] = alarms[len(alarms)-1] + line

    extractAlarms(alarms)





if __name__ == "__main__":
    main()