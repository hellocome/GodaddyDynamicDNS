#!/usr/bin/python
import sys
import pif
import smtplib
import configparser
import ipaddress
import logging
import logging.handlers
import requests
import sys
import os

from godaddypy import Client, Account

from email.mime.text import MIMEText

dir_path = os.path.dirname(os.path.realpath(__file__))
log_path = dir_path + '/godaddy-dyndns.log'
config_path = dir_path + '/godaddy-dyndns.conf'

def init_logging():
    l = logging.getLogger()
    rotater = logging.handlers.RotatingFileHandler(log_path, maxBytes=10000000, backupCount=2)
    l.addHandler(rotater)
    l.setLevel(logging.INFO)
    rotater.setFormatter(logging.Formatter('%(asctime)s %(message)s'))


def get_godaddy_client():
    config = configparser.ConfigParser()
    config.read(config_path)

    account = Account(api_key=config.get('godaddy', 'api_key'),
                      api_secret=config.get('godaddy', 'api_secret'))
    if not account:
        raise RuntimeError('Could not log in into GoDaddy')

    client = Client(account)

    return client

# email function


def email_update(body):
    global smtplib

    config = configparser.ConfigParser()
    config.read(config_path)

    email_enable = config.get('email', 'enable')

    if email_enable == 'true':
        logging.info("sending email")
        msg = MIMEText(body)
        msg['From'] = config.get('email', 'sender')
        msg['To'] = config.get('email', 'to')
        msg['Subject'] = 'IP address updater'
        logging.info("server {0} {1}".format(config.get('email','smtpserver'), int(config.get('email','smtpport'))))
        s = smtplib.SMTP(config.get('email', 'smtpserver'), int(config.get('email','smtpport')))
        logging.info("init email ok")
        s.ehlo()
        s.starttls()
        s.login(config.get('email','user'), config.get('email','pwd'))
        s.sendmail(config.get('email', 'sender'),
                   config.get('email', 'to'), msg.as_string())
        s.quit()
        logging.info("email send to: " + config.get('email','to'))

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def main():
    init_logging()

    config = configparser.ConfigParser()
    config.read(config_path)

    godaddydomain = config.get('godaddy', 'domain')
    records = [x.strip()
               for x in (config.get('godaddy', 'records').split(','))]
    # what is my public ip?
    ip = pif.get_public_ip()

    if len(ip) > 30:
       logging.info("Invalid String, netwock could be down: {:30s}".format(ip))
    else:
       logging.info("My ip: {0}".format(ip))

    if validate_ip(ip) == False:
       return

    client = get_godaddy_client()

    for domain in client.get_domains():
        if domain == godaddydomain:  # Check to make sure the domain is requested
            for dns_records in client.get_records(domain, record_type='A'):
                #logging.info(dns_records["name"])
                if dns_records["name"] in records:
                    full_domain = "%s.%s" % (dns_records["name"], domain)

                    if ip == dns_records["data"]:
                        # There's a race here (if there are concurrent writers),
                        # but there's not much we can do with the current API.
                        logging.info("%s unchanged" % full_domain)
                    else:
                        if not client.update_record_ip(ip, domain, dns_records["name"], 'A'):
                            raise RuntimeError(
                                'DNS update failed for %s' % full_domain)

                        logging.info("%s changed from %s to %s" %
                                     (full_domain, dns_records["data"], ip))

                        email_update("%s changed from %s to %s" %
                                     (full_domain, dns_records["data"], ip))
if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.error('Exception: %s' % e)
        logging.shutdown()
        sys.exit(1)