import requests
import cryptor
import time
import json

requests.packages.urllib3.disable_warnings()

static_headers = {
    'platform': 'Android',
    'Content-Type': 'application/json; charset=utf-8',
    'User-Agent': 'okhttp/3.4.2'
}
default_device_id = '2492458045226-123847009231098131'
default_member_id = '1234567'
baseurl = 'https://mobile.o.bike/'
#baseurl = 'http://localhost:8000/'

class HttpClient(object):

    def __init__(self, version='2.5.4', country_code='+41', device_id=default_device_id, member_id=default_member_id, verify=True):
        self.version = version
        self.country_code = country_code
        self.device_id = device_id
        self.member_id = default_member_id
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update(static_headers)
        self.session.headers.update({'version': version})
        self.cryptor = cryptor.Cryptor(version)

    def authenticated(func):
        """ decorator used to trigger authentication as needed """
        def func_wrapper(self, *args, **kwargs):
            if not self.session.headers.get('Authorization'):
                self._connect()
            return func(self, *args, **kwargs)
        return func_wrapper

    def _connect(self):
        try:
            with open('/tmp/obike_token') as f:
                self.session.headers.update({'Authorization': 'Bearer ' + f.readline().strip()})
        except IOError as e:
            pass

        if not self.session.headers.get('Authorization'):
            self.login()

    def login(self):
        self.session.headers.pop('Authorization', None)
        phone = raw_input('phone (e.g. 791234567): ')
        password = raw_input('password: ')

        params = json.dumps({
            'phone': phone,
            'deviceId': self.device_id,
            'password': password,
            'countryCode': self.country_code,
            'dateTime': int(time.time()*1000)
        }, separators=(',', ':'))

        payload = {'value': self.cryptor.encrypt(params)}
        r = self.session.post(baseurl + 'api/v2/member/login', json=payload)
        if r.status_code == 200:
            print "successfully logged in"
            token = r.json()['data']['accessToken']
            self.session.headers.update({'Authorization': 'Bearer' + token})
            with open('/tmp/obike_token', 'w') as f:
                f.write(token)

    @authenticated
    def list(self, latitude, longitude):
        params = json.dumps({
            'countryCode': self.country_code,
            'latitude': latitude,
            'longitude': longitude,
            'deviceId': self.device_id,
            'dateTime': int(time.time()*1000)
        }, separators=(',', ':'))
        payload = {'value': self.cryptor.encrypt(params)}
        r = self.session.post(baseurl + 'api/v2/bike/list', json=payload)
        if r.status_code == 200:
            return r.json()
        else:
            print r.text

    @authenticated
    def lock_no(self, bike_no):
        params = json.dumps({
            'deviceId': self.device_id,
            'dateTime': int(time.time()*1000)
        }, separators=(',', ':'))
        payload = {'value': self.cryptor.encrypt(params)}
        r = self.session.post(baseurl + 'api/v2/bike/%s/lockNo' % bike_no, json=payload)
        try:
            return r.json()['data']['lockNo']
        except KeyError:
            return r.text.encode('utf-8')

    @authenticated
    def unlock_pass(self, bike_id, key_source):
        params = json.dumps({
            'bikeId': bike_id,
            'deviceId': self.device_id,
            'keySource': key_source,
            'dateTime': int(time.time()*1000)
        }, separators=(',', ':'))
        payload = {'value': self.cryptor.encrypt(params)}
        r = self.session.post(baseurl + 'api/v2/bike/unlockPass', json=payload)
        if r.status_code == 200:
            return r.json()
        else:
            print r.text

    @authenticated
    def lock_message(self, latitude, longitude, index, timestamp, mac_key, vol, transtype, bike_trade_no):
        """ wip """
        params = json.dumps({
            'deviceId': self.device_id,
            'lati': latitude,
            'longi': longitude,
            'memberId': self.member_id,
            'dateTime': int(time.time()*1000),
            'index': index,
            'timestamp': timestamp,
            'mackey': mac_key,
            'vol': '3.21',
            'transtype': 0,
            'bikeTradeNo': bike_trade_no
        }, separators=(',', ':'))

