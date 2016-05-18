#!/usr/bin/env python

# Note: for setting up email with sendmail, see: http://linuxconfig.org/configuring-gmail-as-sendmail-email-relay

from subprocess import check_output
from datetime import datetime
import os
import sys, smtplib, json

PWD = os.path.dirname(sys.argv[0])

import logging
import logging.handlers

logger = logging.getLogger('ge-checker')
for path in ['/var/run/syslog', '/dev/log']:
    if os.path.exists(path):
        handler = logging.handlers.SysLogHandler(address=path)
        break
else:
    handler = logging.handlers.SysLogHandler()

formatstring = ('[%(asctime)s][%(levelname)s][%(name)s]'
                '[%(process)d %(processName)s]'
                '[%(funcName)s (line %(lineno)d)]'
                '%(message)s')
formatter = logging.Formatter(formatstring)
handler.setFormatter(formatter)

logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# Get settings
try:
    with open('%s/config.json' % PWD) as json_file:    
        settings = json.load(json_file)
except Exception as e:
    print 'Error extracting config file: %s' % e
    sys.exit()

# Make sure we have all our settings
if not 'current_interview_date_str' in settings or not settings['current_interview_date_str']:
    print 'Missing current_interview_date_str in config'
    sys.exit()
if not 'email' in settings or not settings['email']:
    print 'Missing email data in config'
    sys.exit()
if not 'init_url' in settings or not settings['init_url']:
    print 'Missing initial URL in config'
    sys.exit()
if not 'enrollment_location_id' in settings or not settings['enrollment_location_id']:
    print 'Missing enrollment_location_id in config'
    sys.exit()
if not 'username' in settings or not settings['username']:
    print 'Missing username in config'
    sys.exit()
if not 'password' in settings or not settings['password']:
    print 'Missing password in config'
    sys.exit()

CURRENT_INTERVIEW_DATE = datetime.strptime(settings['current_interview_date_str'], '%B %d, %Y')

def send_apt_available_email(current_apt, avail_apt):
    esets = settings.get('email', {})
    message = """From: %s
To: %s
Subject: Alert: New Global Entry Appointment Available
Content-Type: text/html

<p>Good news! There's a new Global Entry appointment available on <b>%s</b> (your current appointment is on %s).</p>

<p>If this sounds good, please sign in to https://goes-app.cbp.dhs.gov/main/goes to reschedule.</p>

<p>If you reschedule, please remember to update CURRENT_INTERVIEW_DATE in your config.json file.</p>
""" % (esets['from'], ', '.join(esets['to']), avail_apt.strftime('%B %d, %Y'), current_apt.strftime('%B %d, %Y'))

    try:
        server = smtplib.SMTP(host=esets.get('host', 'localhost'), port=esets.get('port', 0))
        if esets.get('tls'):
            server.starttls()
        if esets.get('user'):
            server.login(esets['user'], esets['password'])
        server.sendmail(esets['from'], esets['to'], message)
        server.quit()
    except Exception as e:
        logger.exception('Failed to send success email: %s' % e)



new_apt_str = check_output(['phantomjs', '%s/ge-cancellation-checker.phantom.js' % PWD]); # get string from PhantomJS script - formatted like 'July 20, 2015'
new_apt_str = new_apt_str.strip()

try: new_apt = datetime.strptime(new_apt_str, '%B %d, %Y')
except ValueError as e:
    logger.exception('%s: %s' % (new_apt_str, e))
    sys.exit()

if new_apt < CURRENT_INTERVIEW_DATE: # new appointment is newer than existing!
    send_apt_available_email(CURRENT_INTERVIEW_DATE, new_apt)   
    logger.info('Found new appointment on %s (current is on %s)!' % (new_apt, CURRENT_INTERVIEW_DATE))
else:
    logger.debug('No new appointments. Next available on %s (current is on %s)' % (new_apt, CURRENT_INTERVIEW_DATE))
