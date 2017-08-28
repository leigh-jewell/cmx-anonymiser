# Author Leigh Jewell
import configparser
import requests
# Ignore HTTPS warnings if they appear
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from requests.auth import HTTPBasicAuth
from collections import defaultdict
import csv
import hashlib
from datetime import datetime
from datetime import timedelta
import os
import sched, time

#Constants
url_prefix = "http://"

#Read configuration from config.ini file into global variables
config = configparser.ConfigParser()
if os.path.isfile("config.ini"):
    try:
        config.read("config.ini")
        cmx = config.get('cmx', 'cmx_ip')
        username = config.get('cmx', 'username')
        password = config.get('cmx', 'password')
        pageSize = config.get('cmx', 'page_size', fallback=1000)
        url_clients = config.get('cmx', 'url_clients', fallback="/api/location/v1/clients/")
        url_aps = config.get('cmx', 'url_aps', fallback="/api/config/v1/aps/")
        output_dir = config.get('output', 'output_dir', fallback=os.path.join(os.getcwd(), 'output'))
        log_dir = config.get('output', 'log_dir', fallback=os.path.join(os.getcwd(), 'logs'))
        log_console = config.getboolean('output', 'log_console', fallback=False)
        days = config.get('schedule', 'days', fallback=5)
        schedule = config.get('schedule', 'hours', fallback='9:00,12:00,15:00,18:00')
        salt = config.get('privacy', 'salt', fallback='b1303114888c11e79e6a448500844918')
        configError = False
    except configparser.Error as e:
        print("Error with config.ini: ", e)
        configError = True
else:
    print("config.ini missing from current directory.")
    configError = True

# Setup logging
if not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir)
    except OSError as e:
        print('Error - log directory {} does not exist, and cannot create it {}'.format(log_dir, e))
    # Create a unique file name by appending the date to the end
logFile = 'cmx' + datetime.strftime(datetime.now(),'-%d-%m-%y-%H-%M.log')
fulllogFile = os.path.join(log_dir, logFile)

def logging(info):
    dateStamp = datetime.strftime(datetime.now(),'%d/%m/%y %H:%M.%S.%f: ') + info
    if log_console:
        print(dateStamp)
    try:
        with open(fulllogFile,'a', newline='\n', encoding='utf-8') as f:
            print(dateStamp, file=f)
    except OSError as e:
        print('Error - tried to open file for writing but something went wront {}'.format(e))
    return

def deidentifyMac(mac):
    # Take the mac-address and deidentify it by securely hashing it
    # Add the salt to the mac and encode before hashing result and then returning the unique token
    mac_hashed = hashlib.sha256(salt.encode()+mac.encode()).hexdigest()
    return mac_hashed

def getCMXData():
    URL = url_prefix + cmx + url_clients
    logging('getCMXData: Getting data for:{}'.format(URL))
    response_dict = defaultdict(list)
    try:
        response = requests.get(url = URL, auth = HTTPBasicAuth(username, password), verify=False)
        logging('getCMXData: Got status code {} from CMX API (200 is good)'.format(response.status_code))
        response_dict['statusCode'] = response.status_code
        if response.status_code == 200:
            response.encoding = 'utf-8'
            response_dict['data'].append(['hash',
                                         'mapHierarchyString',
                                          'floorRefId',
                                          'length',
                                          'width',
                                          'x',
                                          'y',
                                          'unit',
                                          'currentlyTracked',
                                          'confidenceFactor',
                                          'currentServerTime',
                                          'firstLocatedTime',
                                          'lastLocatedTime',
                                          'maxDetectedRssiApMacAddress',
                                          'band',
                                          'rssi',
                                          'lastHeardInSeconds',
                                          'networkStatus',
                                          'changedOn',
                                          'ssId',
                                          'band',
                                          'apMacAddress',
                                          'dot11Status',
                                          'manufacturer',
                                          'detectingControllers',
                                          'bytesSent',
                                          'bytesReceived'
                                         ])
            for client in response.json():
                response_dict['data'].append([deidentifyMac(client['macAddress']), \
                                              client['mapInfo']['mapHierarchyString'], \
                                              client['mapInfo']['floorRefId'], \
                                              client['mapInfo']['floorDimension']['length'], \
                                              client['mapInfo']['floorDimension']['width'], \
                                              client['mapCoordinate']['x'], \
                                              client['mapCoordinate']['y'], \
                                              client['mapCoordinate']['unit'], \
                                              client['currentlyTracked'], \
                                              client['confidenceFactor'], \
                                              client['statistics']['currentServerTime'], \
                                              client['statistics']['firstLocatedTime'], \
                                              client['statistics']['lastLocatedTime'], \
                                              client['statistics']['maxDetectedRssi']['apMacAddress'], \
                                              client['statistics']['maxDetectedRssi']['band'], \
                                              client['statistics']['maxDetectedRssi']['rssi'], \
                                              client['statistics']['maxDetectedRssi']['lastHeardInSeconds'], \
                                              client['networkStatus'], \
                                              client['changedOn'], \
                                              client['ssId'], \
                                              client['band'], \
                                              client['apMacAddress'], \
                                              client['dot11Status'], \
                                              client['manufacturer'], \
                                              client['detectingControllers'], \
                                              client['bytesSent'], \
                                              client['bytesReceived']
                                             ])
            logging('getCMXData: Got {} records from CMX.'.format(len(response_dict['data'])-1))
            response_dict['isError'] = False
    except requests.exceptions.RequestException as e:
        logging(e)
        response_dict['isError'] = True

    return response_dict

def getCMXAPData():
    URL = url_prefix + cmx + url_aps
    logging('getCMXAPData: Getting data for: {}'.format(URL))
    response_dict = defaultdict(list)
    try:
        response = requests.get(url = URL, auth = HTTPBasicAuth(username, password), verify=False)
        logging('getCMXAPData: Got status code {} from CMX API (200 is good)'.format(response.status_code))
        response_dict['statusCode'] = response.status_code
        if response.status_code == 200:
            response.encoding = 'utf-8'
            response_dict['data'].append(['radioMacAddress',
                                          'name',
                                          'x',
                                          'y',
                                          'unit',
                                          '802_11_BChannelNumber',
                                          '802_11_BTxPowerLevel',
                                          '802_11_AChannelNumber',
                                          '802_11_ATxPowerLevel',
                                          'floorId'
                                         ])
            for ap in response.json():
                if len(ap['apInterfaces']) == 2:
                    response_dict['data'].append([ap['radioMacAddress'], \
                                                  ap['name'], \
                                                  ap['mapCoordinates']['x'], \
                                                  ap['mapCoordinates']['y'], \
                                                  ap['mapCoordinates']['unit'], \
                                                  ap['apInterfaces'][0]['channelNumber'], \
                                                  ap['apInterfaces'][0]['txPowerLevel'], \
                                                  ap['apInterfaces'][1]['channelNumber'], \
                                                  ap['apInterfaces'][1]['txPowerLevel'], \
                                                  ap['floorIdString']
                                                 ])
                elif len(ap['apInterfaces']) == 1:
                    response_dict['data'].append([ap['radioMacAddress'], \
                          ap['name'], \
                          ap['mapCoordinates']['x'], \
                          ap['mapCoordinates']['y'], \
                          ap['mapCoordinates']['unit'], \
                          ap['apInterfaces'][0]['channelNumber'], \
                          ap['apInterfaces'][0]['txPowerLevel'], \
                          0, \
                          0, \
                          ap['floorIdString']
                         ])
            logging('getCMXAPData: Got {} ap records from CMX.'.format(len(response_dict['data'])-1))
            response_dict['isError'] = False
    except requests.exceptions.RequestException as e:
        logging(e)
        response_dict['isError'] = True

    return response_dict

def writeFile(data, fileName):
    # Write the data to an appropriate file
    logging('writeFile:Using {} as output directory'.format(output_dir))
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except OSError as e:
            logging('writeFile:Error - output directory {} does not exist, and cannot create it {}'.format(output_dir, e))
    if os.path.exists(output_dir):
        # Create a unique file name by appending the date to the end
        fileNameDate = fileName + datetime.strftime(datetime.now(),'-%d-%m-%y-%H-%M-%S-%f.csv')
        fullFileName = os.path.join(output_dir, fileNameDate)
        # Its a new unique file so it shouldn't exist
        if not os.path.isfile(fullFileName):
            try:
                with open(fullFileName,'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerows(data['data'])
                    logging('writeFile:Finished writing.')
            except IOError as e:
                logging('writeFile:Error - tried to open file for writing but something went wront {}'.format(e))
        else:
            logging('writeFile:Error - tried to create unique output file name {} but file exists'.format(fileNameDate))
    else:
        logging('writeFile: problem with output directory.')
    return

def getData():
    logging('getData: Process woken up.')
    logging('getData:Using CMX:{} and username:{}'.format(cmx, username))

    ap_data = getCMXAPData()
    if not ap_data['isError']:
        writeFile(ap_data, 'ap_data')
    else:
        logging("getData: getCMXAPData had an error, nothing to write.")
    user_data = getCMXData()
    if not user_data['isError']:
        writeFile(user_data, 'user_data')
    else:
        logging("getData: getCMXData had an error, nothing to write.")

    logging('getData: Process sleeping.')
    return

def main():
    if not configError:
        logging("main: Process started, scheduling jobs {} days and {} hours".format(days, schedule))
        if 'now' in schedule:
            getData()
        else:
            s = sched.scheduler(time.time, time.sleep)
            sched_time = [i.split(':') for i in schedule.split(',')]
            today = datetime.now()
            # Convert days str into integer
            days_int = int(days)
            # Step through the days and schedule the getData function to run at the appropriate time.
            for day in range(days_int):
                for (sched_hour,sched_min) in sched_time:
                    hr = int(sched_hour)
                    mn = int(sched_min)
                    future = datetime.now() + timedelta(days=day)
                    secs = (future-today).total_seconds()
                    # For time that is in the future schedule the call of the getData function
                    if secs > 0:
                        logging('main: getData will be run {} total secs {}'.format(future, secs))
                        s.enter(secs, 1, getData)
            # Allow the scheduler to run schedule the jobs to run.
            s.run()
        logging('main: Finished scheduled runs.')

if __name__ == "__main__":
    main()
