# coding: utf8
# -*- coding: utf-8 -*-

import email
import imaplib
import gzip
import os
import unicodedata
import string
import sys
import ConfigParser
import hashlib
import random
import logging
import zipfile
import json

cfgdic = {'servername': '',
          'username': '',
          'password': '',
          'maildir': '',
          'with_servername': False,
          'gzip': False,
          'zip': False,
          'mimetype': [],
          'loglevel': ''}


def randomlist(a):
    b = []
    for i in range(len(a)):
        element = random.choice(a)
        a.remove(element)
        b.append(element)
    return b


def read_cfg():
    config = ConfigParser.RawConfigParser(allow_no_value=True)
    config.read('imap_get.cfg')

    global cfgdic

    cfgdic['servername'] = config.get('server', 'servername')
    cfgdic['username'] = config.get('server', 'username')
    cfgdic['password'] = config.get('server', 'password')
    cfgdic['maildir'] = config.get('data', 'maildir')
    cfgdic['with_servername'] = config.getboolean('data', 'with_servername')
    cfgdic['gzip'] = config.getboolean('data', 'gzip')
    cfgdic['zip'] = config.getboolean('data', 'zip')
    cfgdic['mimetype'] = config.options('attachments')
    cfgdic['loglevel'] = config.get('logs', 'loglevel')


def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')


validFilenameChars = "-_.() %s%s" % (string.ascii_letters, string.digits)


def removedisallowedfilenamechars(filename):
    cleanedfilename = unicodedata.normalize('NFKD', filename).encode('utf-8', 'ignore')
    return ''.join(c for c in cleanedfilename if c in validFilenameChars)


mimetypedict = {
                'multipart/alternative': 'alternative',
                'application/pgp-encrypted': 'pgp-encrypted',
                'application/vnd.google-earth.kmz': 'vnd.google-earth.kmz',
                'application/vnd.rn-realmedia': 'vnd.rn-realmedia',
                'image/jpeg': 'jpeg',
                'image/jpg': 'jpg',
                'image/png': 'png',
                'image/gif': 'gif',
                'video/mpeg': 'mpg',
                'image/bmp': 'bmp',
                'image/vnd.dwg': 'dwg',
                'image/vnd.dxf': 'dxf',
                'application/jpg': 'jpg',
                'application/png': 'png',
                'multipart/mixed': 'txt',
                'multipart/related': 'txt',
                'text/html': 'html',
                'text/plain': 'txt',
                'text/xml': 'xml',
                'video/avi': 'avi',
                'video/mp4': 'mp4',
                'video/quicktime': 'quicktime',
                'video/x-msvideo': 'x-msvideo',
                'video/x-ms-wmv': 'x-ms-wmv',
                'application/gzip': 'gzip',
                'application/msword': 'msword',
                'application/octet-stream': 'octet-stream',
                'application/pdf': 'pdf',
                'application/pgp-keys': 'pgp-keys',
                'application/pgp-signature': 'pgp-signature',
                'application/pkcs7-signature': 'pkcs-signature',
                'application/postscript': 'ps',
                'application/vnd.ms-excel': 'xls',
                'application/vnd.ms-excel.sheet.macroenabled.12': 'vnd.ms-excel.sheet.macroenabled.12',
                'application/vnd.ms-excel.addin.macroenabled.12': 'vnd.ms-excel.addin.macroenabled.12',
                'application/vnd.ms-pki.seccat': 'vnd.ms-pki.seccat',
                'application/vnd.ms-powerpoint': 'vnd.ms-powerpoint',
                'application/vnd.ms-xpsdocument': 'vnd.ms-xpsdocument',
                'application/vnd.oasis.opendocument.presentation': 'vnd.oasis.opendocument.presentation',
                'application/vnd.oasis.opendocument.spreadsheet': 'vnd.oasis.opendocument.spreadsheet',
                'application/vnd.oasis.opendocument.text': 'vnd.oasis.opendocument.text',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'vnd.openxmlformats-officedocument.presentationml.presentation',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/x-7z-compressed': 'x-7z-compressed',
                'application/x-gzip': 'x-gzip',
                'application/x-zip-compressed': 'x-zip-compressed',
                'application/zip': 'zip',
                'audio/wav': 'wav',
                'csv/plain': 'csv',


 # application/x-amiga-executable
 # application/x-download
 # application/x-lha
 # application/x-macbinary
 # application/x-perl
 # application/x-pkcs7-signature
 # application/x-shellscript
 # application/x-shockwave-flash
 # application/x-zip-compressed
 # audio/mid
 # audio/mpeg
 # audio/vnd.rn-realaudio
 # image/pjpeg
 # image/svg+xml
 # image/tiff
 # image/unknown
 # image/x-art
 # image/x-bmp
 # image/x-citrix-gif
 # image/x-citrix-jpeg
 # image/x-png
 # message/delivery-status
 # message/disposition-notification
 # message/rfc822
 # multipart/alternative
 # multipart/appledouble
 # multipart/mixed
 # multipart/related
 # multipart/report
 # multipart/signed
 # text/calendar
 # text/enriched
 # text/rfc822-headers
 # text/richtext
 # text/x-asm
 # text/x-chdr
 # text/x-csrc
 # text/x-c++src
 # text/x-moz-deleted
 # text/x-patch
 # text/x-python
 # text/x-sh
 # text/x-vcard
 # unknown/unknown
                }


def main():

    read_cfg()
    servername = cfgdic['servername']
    username = cfgdic['username']
    userpasswd = cfgdic['password']
    bgzip = cfgdic['gzip']
    bzip = cfgdic['zip']
    loglevel = int(cfgdic['loglevel'])
    maildir = cfgdic['maildir']
    if not maildir:
        maildir = "./"
    else:
        maildir += '/'

    if cfgdic['with_servername']:
        maildir = cfgdic['servername'] + '/' + maildir
    message_id_file = maildir+'message-id.dat.gz'

    message_id = list()
    attachment_type_lst = cfgdic['mimetype']
    randomfetch = False
    if not os.path.isdir(maildir):
        os.makedirs(maildir)

    logfilepath = maildir + "logfile.log"
    log_format = "%(asctime)s %(levelname)s - %(message)s"
    logging.basicConfig(filename=logfilepath, level=loglevel, format=log_format)
    logger = logging.getLogger(__name__)

    try:
        with gzip.open(message_id_file, 'rb') as mfile:
            message_id = json.load(mfile)
            mfile.close()
    except IOError as e:
        logger.info("Creating message-id.dat file")
        try:
            with gzip.open(message_id_file, 'wb') as mfile:
                json.dump(message_id,mfile )
                mfile.close()
        except IOError as fileerror:
            logger.error("Error cannot create message-id.dat")

    attfilename = None

    imapconnect = imaplib.IMAP4_SSL(servername)

    imapconnect.login(username, userpasswd)
    mailboxes = imapconnect.list()
    result, subsmbox = imapconnect.lsub()
    if result == 'OK':
        for mbox in subsmbox:
            if "Noselect" in mbox.split('"')[0]:
                continue

            if mbox.find('"/"') > 0:
                mboxname = mbox.rsplit('"/"')[len(mbox.rsplit('"/"')) - 1].lstrip().replace('"', '')
            else:
                mboxname = mbox.rsplit()[2].replace('"', '')

            logger.debug("Processing: " + mboxname)
            if not os.path.isdir(maildir + mboxname):
                logger.info("Creating " + maildir + mboxname)
                os.makedirs(maildir + mboxname)

            imapconnect.select(mboxname, True)
            result, data = imapconnect.uid('search', None, "ALL")
            idlst = data[0]
            if len(idlst) > 0:
                id_list = idlst.split()
                if randomfetch:
                    id_list = randomlist(id_list)
                for mailkey in id_list:
                    headerresult, headerdata = imapconnect.uid('fetch', mailkey, '(BODY.PEEK[HEADER])')
                    if headerresult == 'OK':
                        raw_emailheader = headerdata[0][1]
                        email_header = email.message_from_string(raw_emailheader)
                        if email_header['Message-ID'] in message_id:
                            logger.debug("%s has been downloaded before" % email_header['Message-ID'])
                            continue

                    result, data = imapconnect.uid('fetch', mailkey, '(RFC822)')
                    raw_email = data[0][1]
                    email_message = email.message_from_string(raw_email)
                    if not email_message['Message-ID'] in message_id:
                        message_id.append(email_message['Message-ID'])
                        if (len(message_id)) % 10 == 0:
                            try:
                                with gzip.open(message_id_file, 'wb') as mfile:
                                    json.dump(message_id,mfile)
                                    mfile.close()
                            except IOError as fileerror:
                                logger.error("Error cannot create message-id.dat")

                    if 'Subject' in email_message:
                        email_subject = email_message['Subject']
                    else:
                        email_subject = ""

                    if email_message.is_multipart():
                        logger.debug("Processing " + email_subject)
                        for email_parts in email_message.walk():
                            mimetype = email_parts.get_content_type()
                            logger.debug("Mimetype: " + mimetype)
                            for attachmenttype in attachment_type_lst:
                                if mimetype == attachmenttype:
                                    attachfile = email_parts.get_payload(decode=True)
                                    attfilename = email_parts.get_filename()
                                    if attfilename is None:
                                        attfilename = email_parts.get('Content-ID')
                                        if attfilename is None:
                                            attfilename = "Name_not_found"
                                            logger.warning("Filename not found")
                                            typelst = mimetype.split('/')
                                            attfilename = attfilename + '.' + typelst[-1]

                                    hash_object = hashlib.sha256(attachfile)
                                    if not isinstance(attfilename, unicode):
                                        attfilename = attfilename.decode('utf-8', 'replace')
                                    attfilename = removedisallowedfilenamechars(attfilename)
                                    attfilename = hash_object.hexdigest() + "_" + attfilename
                                    attfilename = attfilename.replace(" ", "_")

                                    if bgzip:
                                        attfilename += '.gz'
                                    elif bzip:
                                        attfilename += '.zip'

                                    if len(attfilename) > 255:
                                        ext = attfilename[attfilename.rfind('.'):]
                                        attfilename = attfilename[0:251] + ext

                                    filename = maildir + mboxname + '/' + attfilename

                                    if not os.path.exists(filename):
                                        if bzip:
                                            try:
                                                fhandle = zipfile.ZipFile(filename, mode="w", compression=zipfile.ZIP_DEFLATED, )
                                                fhandle.writestr(attfilename, attachfile)
                                            except IOError:
                                                logger.error("Cannot create file " + filename)
                                                logger.exception("Exception : ")
                                                quit()
                                        else:
                                            if bgzip:
                                                try:
                                                    fhandle = gzip.open(filename, 'wb')
                                                except IOError:
                                                    logger.error("Cannot create file " + filename)
                                                    logger.exception("Exception : ")
                                                    quit()
                                            else:
                                                try:
                                                    fhandle = open(filename, 'wb')
                                                except IOError:
                                                    logger.error("Cannot create file " + filename)
                                                    logger.exception("Exception : ")
                                                    quit()
                                            logger.debug("Writing " + attfilename)
                                            fhandle.write(attachfile)
                                            fhandle.flush()

                                        fhandle.close()
                                    else:
                                        logger.warning("File " + filename + " exist")

                                    attachfile = None
                                    attfilename = None
            imapconnect.close()
    else:
        logger.error("Imap connection error: {0}", result)
    imapconnect.logout()
    logger.debug("Writing message-id.dat file")
    try:
        with gzip.open(message_id_file, 'wb') as mfile:
            json.dump(message_id, mfile)
            mfile.close()
    except IOError as fileerror:
        logger.error("Error cannot create message-id.dat")

if __name__ == "__main__":
    main()

