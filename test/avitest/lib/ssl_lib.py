from tempfile import NamedTemporaryFile
import subprocess
import os

import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils


def import_key_and_certificate(data, name=None, key_file=None, cert_file=None, user_session='default_session', should_pass=True, slug=None, tenant='admin'):
    path = 'sslkeyandcertificate/importkeyandcertificate'
    headers = {}
    if slug:
        headers = {'slug': slug}
    if not data:
        if not name:
            logger_utils.fail('name must be specified if data is not')
        if not key_file and not cert_file:
            logger_utils.fail('key and/or cert file must be specified if data is not')
        key_s = ''
        cert_s = ''
        try:
            if key_file:
                with open(key_file, 'r') as f:
                    key_s = f.read()
        except Exception as e:
            logger_utils.fail('Failed to read key file %s: %s' %(key_file, str(e)))
        try:
            if cert_file:
                with open(cert_file, 'r') as f:
                    cert_s = f.read()
        except Exception as e:
            logger_utils.fail('Failed to read certificate file %s: %s' %(cert_file, str(e)))
        data = {}
        data['name'] = name
        if cert_s:
            data['certificate'] = cert_s
        if key_s:
            data['key'] = key_s

    rest.post(path, data=data)


def update_ssl_cert(cert_name, cert=None, is_invalid=False):
    """

    :param cert_name:
    :param cert:
    :return:
    """
    status_code, ssl_cert = rest.get(
        'sslkeyandcertificate?name=%s&export_key=true' % (cert_name))
    if is_invalid:
        # Scenario is to update object with invalid certificate.
        # For this we are replacing last 10 characters with invalid value to make the cert invalid.
        old_cert = ssl_cert['results'][0]['certificate']['certificate']
        old_cert = old_cert.replace(old_cert.split('\n')[-3][-10:], 'invalidstr')
        ssl_cert['results'][0]['certificate']['certificate'] = old_cert
    else:
        ssl_cert['results'][0]['certificate']['certificate'] = cert
    rest.put('sslkeyandcertificate', name=cert_name,
             data=ssl_cert['results'][0])


def __create_temp_file(s):
    """
    Create temporary file containing the string s
    Make sure to delete the file when finished
    """
    req_f = NamedTemporaryFile(delete=False)
    req_f.write(s)
    req_f.close()
    return req_f


def generate_key_and_cert_string(name, valid_period='1'):
    cert_f = __create_temp_file('')
    key_f = __create_temp_file('')

    subj = '"/CN=' + name + '"'
    try:
        subprocess.check_output(
            ('openssl req -x509 -nodes -days %s -subj %s -newkey rsa:1024 -keyout %s -out %s' %
             (valid_period, subj, key_f.name, cert_f.name)), shell=True)
        with open(key_f.name, 'r') as f:
            key_s = f.read()
        with open(cert_f.name, 'r') as f:
            cert_s = f.read()

        data = {'name': name,
                'certificate': cert_s,
                'key': key_s
                }
        return data

    except Exception as e:
        if hasattr(e, 'output'):
            s = str(e) + '\n' + e.output
        else:
            s = str(e)
        raise RuntimeError('Cannot verify ssl request: ' + s)

    finally:
        os.unlink(key_f.name)
        os.unlink(cert_f.name)


def ssl_import_key_and_certificate(cert_data):
    """
    cert_name: Name of Certificate
    cert_type: Type of certificate - CA/VIRTUALSERVICE/SYSTEM
    cert: Certificate to Import
    Type of ssl cert (pb): SSLKeyAndCertificate
    API called: api/sslkeyandcertificate
    """
    data = cert_data
    for k,v in cert_data.iteritems():
        if k == 'certificate':
            data['certificate'] = {k:v}

    data['type'] = 'SSL_CERTIFICATE_TYPE_VIRTUALSERVICE'

    rest.post('sslkeyandcertificate', data=data)

    return
