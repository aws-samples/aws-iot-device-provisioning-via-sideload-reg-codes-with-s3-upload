import datetime
import hashlib
import hmac
import json
import re
import requests
from urllib.parse import urlparse


class RequestWithAWSAuth:
    def __init__(self, request_url, access_key=None, secret_key=None, token=None, boto_session=None):
        print("Initializing client for:")
        print(request_url)
        self.request_url = request_url

        self.signed_headers = 'host;x-amz-date'
        self.algorithm = 'AWS4-HMAC-SHA256'

        if boto_session:
            print("Using boto session provided")
            creds_object = boto_session.get_credentials()
            creds = creds_object.get_frozen_credentials()

            self.access_key = creds.access_key
            self.secret_key = creds.secret_key
            self.token = creds.token
        elif access_key:
            print("Using static credentials")
            self.access_key = access_key
            self.secret_key = secret_key
            self.token = token
        else:
            print("No credentials provided")
            raise Exception

    def sign_all_the_things(self, request_body, request_url, method):
        t = datetime.datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

        region, service, host, uri = self.pull_apart_url(request_url)
        credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
        signing_key = self.get_signature_key(self.secret_key, region, service, datestamp)
        canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'

        payload_hash = hashlib.sha256(request_body).hexdigest()
        canonical_request = (method + '\n' + uri + '\n\n' + canonical_headers +
                             '\n' + self.signed_headers + '\n' + payload_hash)

        string_to_sign = (self.algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' +
                          hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = (self.algorithm + ' ' + 'Credential=' + self.access_key + '/' + credential_scope +
                                ', ' + 'SignedHeaders=' + self.signed_headers + ', ' + 'Signature=' + signature)
        headers = {
            'x-amz-date': amzdate,
            'Authorization': authorization_header,
            'x-amz-content-sha256': payload_hash
        }
        if self.token:
            headers['X-Amz-Security-Token'] = self.token
        return headers

    @staticmethod
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(self, key, region_name, service_name, date_stamp):
        kdate = self.sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kregion = self.sign(kdate, region_name)
        kservice = self.sign(kregion, service_name)
        ksigning = self.sign(kservice, 'aws4_request')
        return ksigning

    @staticmethod
    def sort_querystrings(querystrings):
        canonical_querystring = ''
        querystring_sorted = '&'.join(sorted(querystrings.split('&')))

        for query_param in querystring_sorted.split('&'):
            key_val_split = query_param.split('=', 1)

            key = key_val_split[0]
            if len(key_val_split) > 1:
                val = key_val_split[1]
            else:
                val = ''

            if key:
                if canonical_querystring:
                    canonical_querystring += "&"
                canonical_querystring += u'='.join([key, val])

        return canonical_querystring

    @staticmethod
    def pull_apart_url(request_url):
        re_region_ex = "\w{2,3}-\w+-\d\w?"
        re_service_ex = "execute-api?|(?!\.)es(?=\.amazonaws.com)"
        parsed_url = urlparse(request_url)
        uri = parsed_url.path
        region = re.search(re_region_ex, request_url).group()
        service = re.search(re_service_ex, request_url).group()
        host = parsed_url.netloc

        # canonical_querystring = self.sort_querystrings(parsed_url.query)

        return region, service, host, uri

    def get(self, request_url, add_headers):

        # canonical_querystring = ''
        request_body = ''
        headers = self.sign_all_the_things(
            request_body=request_body.encode('utf-8'),
            request_url=request_url,
            method='GET'
        )

        if add_headers:
            for k, v in add_headers.items():
                headers[k] = v
        r = requests.get(request_url, headers=headers)
        print('\nRESPONSE++++++++++++++++++++++++++++++++++++'
              'Response code: {0}\n{1}'.format(r.status_code, r.text))

    def post(self, request_url, body, add_headers=None):

        if type(body) == dict:
            request_body = json.dumps(body)
        else:
            request_body = body
        # canonical_querystring = ''
        headers = self.sign_all_the_things(
            request_body=request_body.encode('utf-8'),
            request_url=request_url,
            method='POST'
        )
        # canonical_querystring = self.sort_querystrings(parsed_url.query)

        if add_headers:
            for k, v in add_headers.items():
                headers[k] = v

        r = requests.post(request_url, data=request_body, headers=headers)
        #
        # if r.headers['Content-Type'] == "application/json":
        #     response = r.json()
        # else:
        #     response = r.text

        return r.text, r.status_code
