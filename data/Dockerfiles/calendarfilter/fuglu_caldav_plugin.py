# Fuglu plugin for sending ics/iCal attachments to a CalDav server
from typing import Union

from fuglu.mailattach import Mailattachment
from fuglu.shared import ScannerPlugin, ACCEPT, DUNNO, Suspect

import icalendar
import caldav


class CalendarPlugin(ScannerPlugin):
  """Sends ics/iCal attachments to a CalDav server."""

  """Supported MIME types."""
  CONTENT_TYPES = (
    'application/ics',
    'text/calendar',
  )

  """Max calendar attachment size."""
  MAX_SIZE = 10240

  """Allowed PARTSTAT values for replies."""
  REPLY_PARTSTAT_ALLOWED = (
    # not really an action: 'NEEDS-ACTION',
    'ACCEPTED',
    'DECLINED',
    'TENTATIVE',
    # unsupported: 'DELEGATED'
  )

  def __init__(self, config, section=None):
    ScannerPlugin.__init__(self, config, section)
    self.logger = self._logger()
    self.requiredvars = {
      'maxsize': {
        'default': self.MAX_SIZE * 2,
        'description': 'Maximum message size',
      },
      'caldav_url': {
        'default': '',
        'description': 'CalDAV server URL (%s will be replaced with recipient email)'
      },
      'caldav_username': {
        'default': '',
        'description': 'CalDAV server username'
      },
      'caldav_password': {
        'default': '',
        'description': 'CalDAV server password'
      },
      'caldav_ssl_skip_verify': {
        'default': 'False',
        'description': 'Skip CalDAV server SSL certificate verification'
      }
    }

  def __str__(self):
    return 'Calendar plugin'

  def examine(self, suspect: Suspect):
    maxsize = self.config.getint(self.section, 'maxsize')
    if suspect.size > maxsize:
      self.logger.info("Message is too large, ignoring (%d bytes, allowed %d bytes)" % (suspect.size, maxsize))
      return DUNNO

    try:
      from_address_list = suspect.parse_from_type_header()
      if from_address_list:
        from_address = from_address_list[0][1]
        self.logger.debug("Extracted From header: %s" % from_address)
      else:
        from_address = None
    except ValueError:
      from_address = None

    for attObj in suspect.att_mgr.get_objectlist():  # type: Mailattachment
      contenttype_mime = attObj.contenttype_mime
      att_name = attObj.filename

      if (attObj.is_inline or attObj.is_attachment) and (contenttype_mime in self.CONTENT_TYPES):
        # process all attachments marked as "inline", "attachment" and with supported content types
        pass
      else:
        self.logger.debug("Skip message object: %s (attachment: %s, inline: %s, type: %s)" % (
          att_name, attObj.is_attachment, attObj.is_inline, contenttype_mime
        ))
        continue

      if attObj.filesize > self.MAX_SIZE:
        self.logger.warning("Calendar too big! Skipping attachment %s "
                            "(attachment: %s, inline: %s, type: %s)" %
                            (att_name, attObj.is_attachment, attObj.is_inline, contenttype_mime))
        continue

      #self.logger.debug("Event data: \n%s" % attObj.decoded_buffer_text)
      cal = icalendar.Calendar.from_ical(attObj.decoded_buffer_text)

      # supports replies only for now
      if cal.get('method') != 'REPLY':
        self.logger.info("Not a calendar reply, skipping attachment %s" % att_name)
        continue

      for event in cal.walk('vevent'):
        uid = event.get('uid')
        self.logger.debug("Calendar event: %s [%s]" % (event.get('name'), uid))

        """
        TODO / based on event UID
        if event exists, look for PARTSTAT=(ACCEPTED|...) for the user matching the mail sender
        if event does not exist, import it fully (or not?)

        Security checks for replies:
        * only accept replies for already present attendees
        * only the email sender can update his/her own participation (no real way of certifying this, still...)
        * only update PARTSTAT information if valid
        * (what else we can update other than PARTSTAT?)
        """

        for recipient in suspect.recipients:
          principal = self.get_caldav_client(recipient)
          cal_event = self.find_event(principal, uid)
          if cal_event:
            self.logger.debug("Found event on server: %s [%s][%s]" %
                              (cal_event.name, cal_event.id, cal_event.url))

            attendees = event.get('attendee')
            if type(attendees) != list:
              attendees = [attendees]

            self.logger.debug("Attendees: %s", attendees)
            for attendee in attendees:  # type: icalendar.vCalAddress
              attendee_mailto = attendee
              if not mailto_matches(attendee_mailto, suspect.from_address) and \
                not mailto_matches(attendee_mailto, from_address):
                self.logger.warning("Not accepting reply on behalf of another user! " +
                                    "Sender: %s, attendee: %s" %
                                    (suspect.from_address, attendee_mailto))
                continue

              if attendee.params['partstat']:
                cal_instance = cal_event.icalendar_instance
                _debug_save_temp(cal_instance, 'pre')
                self.logger.debug(cal_instance.to_ical())

                try:
                  attendee_instance = self.get_invited_attendee(cal_instance, uid, attendee_mailto)
                except ValueError:
                  self.logger.warning("Attendee %s not found in event %s, ignoring reply" %
                                      (attendee_mailto, uid))
                  continue

                try:
                  self.set_attendee_partstat(attendee_instance, attendee.params['partstat'])
                except ValueError:
                  self.logger.warning("Unable to set partstat for attendee %s to %s in event %s, "
                                      "ignoring reply" %
                                      (attendee_mailto, attendee.params['partstat'], uid))
                  continue

                _debug_save_temp(cal_instance, 'post')
                self.logger.debug(cal_instance.to_ical())
                cal_event.save()
          else:
            self.logger.info("Event not found in calendar %s: %s" %
                             (recipient, uid))

    return ACCEPT

  def get_caldav_client(self, recipient) -> caldav.Principal:
    url = self.config.get(self.section, 'caldav_url') % recipient
    ssl_verify_cert = not self.config.getboolean(self.section, 'caldav_ssl_skip_verify')
    username = self.config.get(self.section, 'caldav_username')
    password = self.config.get(self.section, 'caldav_password')
    client = caldav.DAVClient(url=url,
                              username=username,
                              password=password,
                              ssl_verify_cert=ssl_verify_cert)
    return caldav.Principal(client, url)

  def find_event(self, principal: caldav.Principal, uid: str) -> Union[caldav.Event, None]:
    for calendar in principal.calendars():  # type: caldav.Calendar
      try:
        event = calendar.event_by_uid(uid)
        self.logger.debug("EVENT: %s", event)
        if event:
          event.load()
          return event
      except caldav.lib.error.NotFoundError:
        self.logger.debug("EVENT: error!")
        pass
    return None

  def get_invited_attendee(self, ical_object: icalendar.Calendar, event_uid, attendee_email) -> icalendar.vCalAddress:
    vevents = ical_object.walk('VEVENT')
    if len(vevents) > 1:
      raise ValueError("Only calendars with 1 event are supported")

    event = vevents[0]
    if event['uid'] != event_uid:
      raise ValueError("Event uid mismatch!")

    attendee = event['attendee']
    if attendee.casefold() == attendee_email.casefold():
      return attendee

    raise ValueError("Attendee not found: %s" % attendee_email)

  def set_attendee_partstat(self, attendee_instance: icalendar.vCalAddress, partstat):
    if partstat.upper() in self.REPLY_PARTSTAT_ALLOWED:
      attendee_instance.params['partstat'] = partstat
    else:
      raise ValueError("Unsupported PARTSTAT: %s" % partstat)


def _debug_save_temp(ical_object: icalendar.Calendar, name):
  with open('/tmp/ical_' + name + '.ics', 'wb+') as file:
    file.write(ical_object.to_ical())


def mailto_matches(mailto: str, email: str) -> bool:
  return mailto.casefold() == ('mailto:' + email).casefold()
