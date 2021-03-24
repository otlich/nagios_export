#!/usr/bin/python3.8

import os, sys, time
import configparser
from threading import Thread
import requests
from requests.auth import HTTPBasicAuth
from lxml import html
from alertaclient.api import Client as AlertaClient

default_config_path = './nagios_export.conf'

class Alert():

    def __init__(self):
        self.host         = None
        self.ip           = None
        self.atype        = None
        self.service      = None
        self.service_link = None
        self.host_group   = []
        self.severity     = None
        self.last_check   = None
        self.dyration     = None
        self.attempt      = None
        self.info         = None

        self.attributes   = {}

    def set_attribute(self, attribute, value=True):
        if type(value) == 'dict':
            value = ", ".join(value)
        self.attributes[attribute] = value

class Alerta():

    def __init__(self, url, key, env, origin="Nagios", nagios_profile=None, ssl_verify=False, group = None):

        self.env    = env
        self.origin = origin
        self.group  = group
        self.nagios_profile = nagios_profile

        self.alerta_active_alerts = None

        try:
            self.client = AlertaClient(endpoint=url, key=key, ssl_verify=ssl_verify, debug=False)
        except:
            print ("Error connect to alarma")

    def get_alerta_alerts(self):

        self.alerta_active_alerts = self.client.search([("environment",self.env),("status",("open","ack")), ("attributes.nagios_profile", self.nagios_profile)], page_size=10000)

    def send(self, alert, id=None, force_severity=None):

        if force_severity is not None:
            severity = force_severity
        else:
            severity = alert.severity.lower()

        if self.alerta_active_alerts is None:
            self.get_alerta_alerts()
        
        is_active = False
        for a in self.alerta_active_alerts:
            if a.resource == alert.host and a.event == alert.service and a.severity == severity:
                is_active = True
                alarma_alert = a
        
        if not is_active:
            alert.set_attribute("source", str(self.origin)+'/'+str(alert.service_link))
            alert.set_attribute("nagios_profile", self.nagios_profile)

            alarma_alert = self.client.send_alert(environment=self.env, 
                                                service  = alert.host_group, 
                                                resource = alert.host, 
                                                event    = alert.service, 
                                                value    = 0, 
                                                text     = alert.info, 
                                                severity = severity,
                                                origin   = self.nagios_profile,
                                                tags     = ['nagios', alert.host, self.nagios_profile ],
                                                group    = self.group,
                                                attributes = alert.attributes,
                                                id       = id )[1]
        
        if 'ack' in alert.attributes and alarma_alert.status != 'ack':
            self.client.set_status(alarma_alert.id, 'ack')

        return id

    def close_alerts(self, nagios_alerts):

        if self.alerta_active_alerts is None:
            self.get_alerta_alerts()

        active_alerts_ids = []
        for a in self.alerta_active_alerts:
            for active_alert in nagios_alerts:
                if active_alert.host == a.resource and active_alert.service == a.event:
                    active_alerts_ids.append(a.id)

        for a in self.alerta_active_alerts:
            if a.id not in active_alerts_ids:
                self.client.set_status(a.id, 'closed')
                alert = Alert()
                alert.host    = a.resource
                alert.service = a.event
                alert.service_link = ''
                alert.info = 'Closed because not found active alarm in nagios'
                alert.attributes = {}

                self.send(alert, force_severity='normal')

    def heartbeat(self):
      
        self.client.heartbeat("Nagios export from:"+str(self.nagios_profile), attributes = {'environment':self.env}, timeout=120)


class Nagios:

    #https://github.com/HenriWahl/Nagstamon/blob/6f10b1dbb437b9434162215bfd207848a29284db/Nagstamon/Servers/Generic.py#L101
    BROWSER_URLS = {'monitor': '$MONITOR$',
                    'hosts':   '$MONITOR-CGI$/status.cgi?hostgroup=all&style=hostdetail&hoststatustypes=12',
                    'services':'$MONITOR-CGI$/status.cgi?host=all&servicestatustypes=253',
                    'history': '$MONITOR-CGI$/history.cgi?host=all'}

    def nagios_attributes_from_gif_names(self, alarm, images):

        another  = []

        for image_name in images:
            if 'comment.gif' in image_name:
                alarm.set_attribute("comment")
            elif 'ack.gif' in image_name:
                alarm.set_attribute("ack")
            elif 'passiveonly.gif' in image_name:
                alarm.set_attribute("passive")
            elif 'flapping.gif' in image_name:
                alarm.set_attribute("flapping")
            else:
                another.append(image_name)
        if len(another) != 0:
            alarm.set_attribute("another", another)
        return 


    def read_nagios_table(self, body):
       
        alerts = []
        tree = html.fromstring(body)
        rows = tree.xpath('//table[@class="status"]/tr')

        prev_host_name = None

        for row in rows:
            name_tds = row.xpath('./td[1]')
            if len(name_tds) == 0:

            host_name    = row.xpath('./td[1]/table/tr/td[1]/table/tr/td[1]/a/text()')
            ip           = row.xpath('./td[1]/table/tr/td[1]/table/tr/td[1]/a/@title')
            atype        = row.xpath('./td[1]/table/tr/td[1]/table/tr/td[1]/@class')
            service_name = row.xpath('./td[2]/table/tr/td[1]/table/tr/td[1]/a/text()')
            service_link = row.xpath('./td[2]/table/tr/td[1]/table/tr/td[1]/a/@href')
            attributes   = row.xpath('./td[2]/table/tr/td[2]/table/tr/td/a/img/@src')

            if len(host_name) == 0 and len(service_name) == 0:
                continue
            elif len(host_name) == 0 and len(service_name) != 0:
                host_name = prev_host_name
                ip        = prev_ip
                atype     = prev_atype
            else:
                host_name = host_name[0]
            
            alert = Alert()

            alert.host         = host_name
            alert.ip           = ip[0]
            alert.atype        = atype[0]
            alert.service      = service_name[0]
            alert.service_link = service_link[0]
            alert.severity     = (row.xpath('./td[3]/text()')[0])
            alert.last_check   = (row.xpath('./td[4]/text()')[0])
            alert.dyration     = (row.xpath('./td[5]/text()')[0])
            alert.attempt      = (row.xpath('./td[6]/text()')[0])
            alert.info         = (row.xpath('./td[7]/text()')[0])

            self.nagios_attributes_from_gif_names(alert, attributes)

            if alert.ip is not None:
                alert.set_attribute('ip', alert.ip)
            if alarm.atype is not None and alarm.atype not in ['statusEven', 'statusOdd']:
                alert.set_attribute('nagios_type', alert.atype)

            alerts.append(alert)

            prev_host_name = host_name
            prev_ip        = ip
            prev_atype     = atype

        return alerts

            
    def fetch_alerts(self, host):

        url = self.BROWSER_URLS['services'].replace('$MONITOR-CGI$', host['monitor_cgi'])
        try:
            resp = requests.get(url, auth=HTTPBasicAuth(host['username'], host['password']))
        except Exception as e:
            print ("Error fetch alerts from {name}: {error}".format(name=host['name'], error=e))
            return False
        
        if  resp.status_code == 200:
            alerts = self.read_nagios_table(resp.text)
        else:
            alerts = []

        return alerts

def read_config(config_path): 

    cfg = {}
    cfg['hosts'] = []
    cfg['alerta']  = {}

    config = configparser.ConfigParser()
    config.read(config_path)
    for s in config.sections():
        if s == 'general':
            cfg['update_interval'] = config[s]['update_interval']
        elif 'alerta ' in s:
            alerta_name = s.split(' ')[1] 
            cfg['alerta'][alerta_name] = {'key':config[s]['key'], 'url':config[s]['url'], 'env':config[s]['env']}
        else:
            host = {}
            host['name']        = s
            host['monitor_url'] = config[s]['monitor_url']
            host['monitor_cgi'] = config[s]['monitor_cgi']
            host['username']    = config[s]['username']
            host['password']    = config[s]['password']
            host['status']      = config[s]['status']
            host['alerta']      = config[s]['alerta']
            cfg['hosts'].append(host)
    return cfg

def main(nagios_host, alerta_conf):

    nagios = Nagios()
    alerts = nagios.fetch_alerts(nagios_host)

    if not alerts or len(alarms) == 0:
        return 

    alerta = Alerta(alerta_conf["url"], 
                    alerta_conf["key"], 
                    alerta_conf["env"], 
                    origin=nagios_host['monitor_cgi'], 
                    nagios_profile=nagios_host['name'], 
                    group='nagios')

    alerta.close_alerts(alerts)

    for alert in alerts:
        alerta.send(alert)

    alerta.heartbeat()
    
    return


def child():

    config = read_config(default_config_path)
    
    while True:
        
        for nagios_conf in config['hosts']:

            if nagios_conf['status'] != 'enable':
                continue

            alerta_conf = config['alerta'][nagios_conf['alerta']]
            worker = Thread(target=main, args=(nagios_conf,alerta_conf, ))
            worker.daemon = True
            worker.start()
        
        time.sleep(int(config['update_interval']))

if __name__ == "__main__":
  
    is_child = os.fork()
    if is_child == 0:
        child()
    else:    
        sys.exit(0)


