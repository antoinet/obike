# oBike Protocol Description (BLE/HTTP)

This document provides an analysis of the oBike communication protocols as of
January 2018.

Results have been presented at the [AREA41 security conference 2018](https://a41con.ch/):
 * [slides](https://www.slideshare.net/AntoineNeuenschwande/on-the-security-of-dockless-bike-sharing-services)
 * [recording](https://www.youtube.com/watch?v=KKlCLsU4v7o)

## General oBike Communication

The oBike lock consists of a TI CC2541 microcontroller, a power-optimized
System on a Chip (SoC) used for Bluetooth Low Energy (BLE) applications. The
lock itself has no IP connectivity; it piggybacks the mobile device’s 3G/4G
connection to communicate with the oBike backend. The lock communicates via
BLE with the oBike app on the mobile device. Protocol messages are then relayed
to the oBike backend via a REST API.

The lock has no GPS module of its own. As such, the position reported to the
backend is always that of the mobile device, not of the oBike itself.

```
                                GPS
                                 |
+---------+                 +---------+                   +----------+
|  oBike  |                 |  Mobile |                   |  oBike   |
|  Lock   |  +--- BLE --->  |  Device |   +--- HTTPS ---> |  Backend |
+---------+                 +---------+                   +----------+
```

## Unlock Sequence
```
 oBike Lock          (BLE)     Mobile Device    (HTTPS)           oBike Backend
------------+------------------------+---------------------------+--------------
            |                        |                           |
            | [1] hello(lat, lng)    |                           |
            | <--------------------- |                           |
Generate    |                        |                           |
32bit       | [2] keySource          |                           |
Challenge   | ---------------------> | [3] unlockPass(keySource) |
            |                        | ========================> | Compute
            |                        |                           | Response
            | [5]                    | [4] encKey, keys          |
            | sendKeys(encKey, keys) | <======================== |
!Unlock     | <--------------------- |                           |
 Bike!      |                        |                           |
            |                        |                           |
Generate    |                        |                           |
Acknowledge | [6] macKey, index      | [7]                       |
Message     | ---------------------> | lockMessage(macKey,index) |
            |                        | ========================> | Register
            |                        |                           | Ride (start
            |                        |                           | billing)
```

Steps:
1. BLE send `hello` message, push coordinates to lock.
2. BLE receive `keySource`, a 32bit value representing the number of
   milliseconds since the chip was powered (little endian).
3. HTTPS send keySource to oBike backend via the `unlockPass` REST call.
4. HTTPS receive `encKey` (key index) and a 128bit key value in `keys`.
5. BLE send `encKey` (truncated to 96bits) and the `index` ( corresponds to
  `encKey`). At that point, the bike will unlock.
6. BLE receive `macKey` and `index`, an acknowledgement that the unlocking was
  successful.
7. HTTPS send `lockMessage`, with the corresponding values (`macKey` and
  `index`). At that point, the oBike backend will register the ride and start
  billing.

## BLE Protocol

The BLE protocol components described in the following sections are implemented
in the python module `obike.ble_client`. In addition, a scanner to detect obike
BLE advertisements is implemented in `obike.ble_scanner.py`.

### General Command Format

```
 6774  0D  86  59AEB6...3931  FD
 |     |   |   |              |
 |     |   |   |              +-- Check byte
 |     |   |   +----------------- Payload
 |     |   +--------------------- Command type
 |     +------------------------- Length of payload in bytes
 +------------------------------- Command Signature ('gt')
```

The message both ingoing and outgoing always start with the signature `\x67\x74`
(ascii `gt`).

Length of the payload is number of bytes without header/trailer.

The protocol supports different message types identified by a byte. The two most
significant bits define the message direction:

```
 0x86   1000 0101     mobile -> obike
 0x46   0100 0101     obike  -> mobile
```

The check byte is computed from XORing the command type and the payload bytes:

```
 check_byte = cmdtype ^ b[0] ^ b[1] ^ ... ^ b[N-1]
```

The maximumn PDU size is 19 bytes (header + payload + trailer). Messages
exceeding this size are fragmented.

### BLE getLockRecord/deleteLockRecord

Command type: `6`  
These messages are used to manage the "lock record", a data record persisted by
the chip consisting of information from the last ride, such as memberid,
timestamp, oBike identifier, coordinates, etc.

Called without a payload, the command is used to retrieve the saved lock
record:
```
00000000  67 74 00 86 86                                    |gt...|
```

If no lock record is available, the lock responds with an empty payload.
```
00000000  67 74 00 46 46                                    |gt.FF|
```

Otherwise, the lock's response contains several values from the last ride, in
the following format:

```
00000000  67 74 46 46 00 00 01 23  45 67 59 9d 72 2a 44 31  |gtFF...#d2Y.r*D1|
00000010  39 33 36 42 33 31 37 2a  72 9d 59 00 34 37 2e 33  |936B317*r.Y.47.3|
00000020  37 32 37 36 30 00 00 00  30 38 2e 35 33 30 38 34  |72760...08.53084|
00000030  32 32 00 00 87 76 f3 7a  8c be 90 f8 4b a4 fa 00  |22...v.z....K...|
00000040  2e ae e3 dc 91 00 00 00  a9 01 8b                 |...........|
```

```
Offset Value                    Description
-------------------------------------------------------------------------
 0004  000001234567             member-id (explicitly coded in decimal,
                                value is: 1234567)

 000a  599d722a                 UNIX timestamp, 08/23/2017 @ 12:16pm

 000e  443139333642333137       obike identifier (D1936B317)
                                this corresponds to the MAC address without
                                the first 3 hex digits, in this case:
                                D4:3D:19:36:B3:17

 0017  2a729d59                 same UNIX timestamp, little endian

 001b  00                       transaction type

 001c  34372e333732373630000000 latitude  (47.372760)

 0028  30382e353330383432320000 longitude (08.5308422)

 0035  8776f37a8cbe90f84ba4fa002eaee3dc  mackey (128 bits)

 0044  91                       key index

 0045  000000                   ?
 004b  a901                     battery voltag level (little endian)
                                e.g. 4.25V
```

When used with a payload, this command deletes the current lock record:

```
00000000  67 74 0d 86 59 d5 ff a4  36 33 39 38 37 37 31 33  |gt..Y...63987713|
00000010  43 14                                             |C.|
```

The payload consists of the current timestamp and the obike identifier:

```
Offset Value                    Description
-------------------------------------------------------------------------
 0004  59d5ffa4                 timestamp (little endian)
 000e  3633393837373133         "63987713C" obike identifier
```

### BLE Push Coords / Get Challenge

Command type: `1`  
These messages are used by the mobile device to indicate the current location of
the obike, which it will store.

```
00000000  67 74 13 81 30 38 2e 35  33 30 38 34 32 32 34 37  |gt..08.530842247|
00000010  2e 33 37 32 37 36 30 b7                           |.372760.|
```

The payload consists of latitude and longitude:
```
Offset Value                    Description
-------------------------------------------------------------------------
 0004  30382e35333038343232     longitude (08.5308422)
 000e  34372e333732373630       latitude (47.372763)
```

The command may also be used without a payload:
```
00000000 67 74 00 81 81                                     |gt...|
```

In response, the obike sends a challenge, a 32bit integer (little endian)
representing the number of milliseconds elapsed since poweron:

```
00000000  67 74 0b 41 00 11 51 00  06 ef 5f 34 aa 01 00 28  |gt.A..Q..._4...(|
```

```
Offset Value                    Description
-------------------------------------------------------------------------
 0004  00115100                 ? (constant, sometimes also 00115900)
 0008  06ef5f34                 challenge (aka keysource)
 000c  aa01                     battery voltage level (little endian),
                                e.g 4.26V
 000e  00                       ? (constant)
```

### BLE Send Keys

Command type: `2`   
These messages are used to convey the response of the challenge to the obike.

```
00000000  67 74 18 82 8b 00 00 01  23 45 67 00 2a 72 9d 59  |gt......#d2.*r.Y|
00000010  2f 42 d3 b4 3b 1b 9d 51  e7 67 13 e3 77           |/B..;..Q.g..w|
```

```
Offset Value                    Description
-------------------------------------------------------------------------
 0004  8b                       key index
 0005  00000123456700           member-id (explicitly coded in decimal,
                                value is 1234567)
 000c  2a729d59                 UNIX timestamp, little endian
                                08/23/2017 @ 12:16pm (UTC)
 0010  2f42d3b43b1b9d51e76713e3 enckey (truncated to 96 bits)
```

The obike responds with a single status byte (00):
```
00000000  67 74 01 42 00 42                                 |gt.B.B|
```

### BLE Reset

Command type: `9`    
Reset the CC2541 chip.
```
00000000: 67 74 00 89 89                                    gt...
```

No answer is returned.

## oBike HTTP REST API

A client for the obike REST API including encryption layer is implemented in the
python module `obike.http_client`.

### REST API Specification

The REST API endpoint for all communication with the oBike backend is:

```
https://mobile.o.bike/api/<version>/
```
Depending on the REST call, either `v1` or `v2` is currently used.

Requests performed by the oBike mobile app towards the oBike backend use the
following headers:

```
Host: mobile.o.bike
Connection: keep-alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: okhttp/3.4.2
platform: Android
Content-Type: application/json; charset=utf-8
version: 2.5.4
Authorization: Bearer 0123456789abcdef0123456789abcdef
Content-Length: 397
```

### Encryption

Starting in fall 2017, version 2 of the API was introduced, which encrypts most
HTTP POST payloads using a symmetric encryption scheme. Encrypted values are
conveyed in the payload of a JSON object of the form:

```
{"value": "b9fb151cd004e1d570201c8ee1a42a6bea3053550c545c446f192f11cfebac8389741
94cff9d3985cebf2bc751acc98359769a9886bc02fe9ab9fc1a5a646c46e1c51e668a717343307fc
5dcef00f8bf92e1badc6d0506f31303e5947ee3453d"}
```

The hex value is encrypted with AES-128, CBC mode in the following manner:

```
ciphertext = AES(plaintext_with_hash, secret_key, iv)
```

where `secret_key` is the string `oBAddMYFUzLed` with the mobile app's version
number appended. E.g. for version 2.5.4, the secret key is `oBAddMYFUzLed254`.
The used initialization vector is `1234567890123456`.

The `plaintext_with_hash` is computed from:

```
plaintext_with_hash = plaintext + '&' + SHA1(hash_key + plaintext + '&')
```

where `hash_key` is the string `oBaddX4buhBMG`.

Here's how to decrypt a payload using OpenSSL:

```
$ echo -n "b9fb151cd0...453d" | \
xxd -r -p | \
openssl enc -aes-128-cbc -d -K 6f424164644d5946557a4c6564323534 -iv 313233343536
37383930313233343536
```

### Authentication

The REST API's authentication scheme vaguely reminds of OAuth/OpenID. Username
and password are posted, and in return, the server sends access and refresh
tokens for a new session. Example:

HTTP Request:
```
POST /api/v2/member/login HTTP/1.1
platform: Android
Connection: close
Accept-Language: en
version: 2.5.4
Content-Type: application/json; charset=utf-8
Content-Length: 396
Host: mobile.o.bike
Accept-Encoding: gzip
User-Agent: okhttp/3.4.2

{"value":"e4526007ae3791e4fabdd5f6833563f8499d076fe5a4039e1ac1bcb7788dc7a053e8b4
384faf202828e6587bbc4bf32f505429129871253ecc388b493f32368ac418f627acc7720c1b5e1a
4ecc35fca7e80dd99062c24cea0b920fcc297164f8703511520f05c2f91ada946dbee9320a0d2f24
f1101036133d53425e91f2b52b7abbea95cde3f395ce8f2c586aa1ea9eaa35fecb26214eb498dbd3
5c56d37b88ebdc100180da662cdae6d6aa50c31d2f92063c2acb8ff45f62d12d34005d48a3"}
```

Decrypted payload:
```
{"phone":"791234567","deviceId":"0123456789abc-0123456789abcdef01","password":"s
wordfish","countryCode":"41","dateTime":"1515100814123"}&687fdcb704d0661b67cf1a2
97b5059b1d4d67900
```

HTTP Response:
```
HTTP/1.1 200
Server: nginx/1.10.3 (Ubuntu)
Date: Thu, 04 Jan 2018 21:20:14 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close
Vary: Accept-Encoding

{"data":{"resourceOwnerId":1234567,"accessToken":"0123456789abcdef0123456789abcd
ef","refreshToken":"0123456789abcdef0123456789abcdef","scope":"customer","expire
sIn":5184000,"registerCoupon":null},"success":true,"errorCode":100}
```

Authenticated requests must include the access token in the Authorization header
, e.g.:
```
Authorization: Bearer 0123456789abcdef0123456789abcdef
```

### Unlock Bike

Send a challenge and receive a response used to unlock the oBike.

HTTP request:
```
POST /api/v2/bike/unlockPass HTTP/1.1
Host: mobile.o.bike
Connection: keep-alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: okhttp/3.4.2
platform: Android
Content-Type: application/json; charset=utf-8
version: 2.5.4
Authorization: Bearer 0123456789abcdef0123456789abcdef
Content-Length: 397

{"value": "697560f47a113c7950836a914d60a342ea3feac166dd74ae67aabfa5c51f79f27d0a0
3335e72d6fcf747681badbd177499deec15a2e545ef1e293431592f2e080ae5fa6e031064369bbfe
f7bccf1a626d7c22265d2df4bcc20b514bf8aa0263d808d1de57ab3a8ef71093e0d558f0f6fba15b
59901b01ca6c95878d69f2f85c5dd90d9610222eb5f7ca2cf955991b7701496e701d39ed0b05514b
6f014634554"}
```

Decrypted payload:

```
{"dateTime":1515016440105,"deviceId":"0123456789abc-0123456789abcdef01","bikeId"
:"041001337","keySource":"54835578"}&cd835995e39c8076f15e3d989727106115b02b8b
```

Notes:
 * `bikeId` must not correspond to the actual oBike being unlocked
 * `keySource` is the 32bit challenge generated by the oBike lock as a response
 to the "BLE Push Coords / Get Challenge" command.

HTTP response:
```
HTTP/1.1 200
Server: nginx/1.10.3 (Ubuntu)
Date: Fri, 05 Jan 2018 16:03:35 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close
Vary: Accept-Encoding
X-Application-Context: customer:prod:8084

{"data":{"encryptionKey":136,"keys":"ff533ae8ec0b1a1816160e9182af7d74","serverTi
me":1515168215665},"success":true,"errorCode":100}
```

### Lock Message
Send the acknowledgement code to the server. The server starts billing when
receiving this message.

HTTP Request:
```
POST /api/v2/bike/lockMessage HTTP/1.1
platform: Android
Connection: close
Accept-Language: en
version: 2.5.4
Authorization: Bearer 80828d0bd57c95f6d5012c45e548598e
Content-Type: application/json; charset=utf-8
Content-Length: 652
Host: mobile.o.bike
Accept-Encoding: gzip
User-Agent: okhttp/3.4.2

{"value":"14420a2ef69b61c06667a58bc6842c7b781b3fc650100652982bbe369b5c818df3225c
6cd8bb63e9cbd7c33a21b6d7be5c66b4ff7744ddcc3b5debf1a1fc0a1a8b379278b360edb5ab3ceb
7014954dc084c1f05a76aa311b09aafe5ca84215f8f3e03f4d9187c14bd0215c8f8c1f535cb46f8f
fc3cd8f327a9410b0378a61dddc0ffdbadd084ccae67442da6598e52f69452a5a7c4fc087df6f8f0
dfd3277db90ae6ecbaf4c7763f5c2bb24611fd8b89c00a2f87442b526bce73405b7370b8adca045c
2852068516c3f8a473cb79c8635092531ef9104f361370c2d11f352c8b3ad9c356a8f363e8da7120
0dcf36d264009e0098c208089f7fbc113fdf342b4222b1466e3d40287dd1b024b3c55bfcf4dbce28
e7156ea5ef1883dd2c390bf7f5eef7833e72ff33eb04ed501f91c7915670f4bb24382fe232adbe30
7ebf80acfb"}
```

Decrypted Payload:
```
{"deviceId":"0123456789abc-0123456789abcdef01","lati":47.3732953,"longi":8.53144
7,"memberId":1234567,"dateTime":"1515159966559","index":"85","timestamp":"151515
9965000","mackey":"6C81C6822A08C30881CFB0D0FAF7D89B","vol":"3.79","transtype":0,
"bikeTradeNo":"5A4F819D639BC4AE1"}&4b5d220310f48744cfadcfd0d554384e2df03921
```

Notes:
 * `mackey` corresponds to the 128bit value received by the BLE Hello Command,
 when the bike is in the unlock state.

HTTP Response:
```
HTTP/1.1 200
Server: nginx/1.10.3 (Ubuntu)
Date: Fri, 05 Jan 2018 13:46:07 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close
Vary: Accept-Encoding

{"data":{"startTime":1515159967958,"message":"Unlocked successfully."},"success"
:true,"errorCode":100}
```

### Order List
Get a list of rides booked with this account.

HTTP Request:
```
POST /api/v2/order/list HTTP/1.1
platform: Android
Connection: close
Accept-Language: en
version: 2.5.4
Authorization: Bearer 0123456789abcdef0123456789abcdef
Content-Type: application/json; charset=utf-8
Content-Length: 268
Host: mobile.o.bike
Accept-Encoding: gzip
User-Agent: okhttp/3.4.2

{"value":"14420a2ef69b61c06667a58bc6842c7b781b3fc650100652982bbe369b5c818df3225c
6cd8bb63e9cbd7c33a21b6d7be45a70bc261bf64e65f985aa51faefe44de6dcafd6e4037b82f1d05
029b4dcb85caeac6f67df317710c7ccd0b3303c92bb9557e2fde213bc397ede304c0c13a16b0310c
799a569df81f2f07a89c5cca06"}
```

Decrypted Payload:
```
{"deviceId":"0123456789abc-0123456789abcdef01","current":1,"dateTime":"151605127
4357"}&11fae15b700f6f69133bfe167c1f99c503359cde
```

HTTP Response (with JSON pretty-printed):
```
HTTP/1.1 200
Server: nginx/1.10.3 (Ubuntu)
Date: Mon, 15 Jan 2018 21:21:16 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close
Vary: Accept-Encoding

{
  "data": {
    "per": 20,
    "current": 1,
    "count": 42,
    "list": [
      {
        "id": 15871962,
        "orderNo": "1801060003123123",
        "status": 5,
        "price": 0,
        "bookTime": null,
        "cancelBookTime": null,
        "startTime": 1515168315000,
        "endTime": 1515168321000,
        "userId": 1234567,
        "bikeId": "041001337",
        "trackId": 17041234,
        "distance": 0,
        "minutes": 0,
        "freeMinutes": 0,
        "carbon": 0,
        "calorie": 0,
        "grade": 0,
        "unitPrice": 1.5,
        "currency": "CHF",
        "currencySymbol": "CHF",
        "actualPrice": 0,
        "actualCurrency": "CHF",
        "actualCurrencySymbol": "CHF",
        "activityId": null,
        "couponId": null,
        "clubcardId": null,
        "savedMoney": null,
        "tempActualPrice": null,
        "tradeNo": "5A4FA1D763990A444",
        "tempEndTime": null,
        "tempMinutes": null,
        "lockType": 1,
        "countryId": 167,
        "cityId": null,
        "platForm": null,
        "promotionActivityId": 0,
        "parkingAreaType": 0
      },
      ...
    ],
    "pages": 3
  },
  "success": true,
  "errorCode": 100
}
```

### List Bikes
Get a list of bikes around the provided coordinates (lat, lng).

HTTP Request:
```
POST /api/v2/bike/list HTTP/1.1
platform: Android
Connection: close
Accept-Language: en
version: 2.5.4
Authorization: Bearer 0123456789abcdef0123456789abcdef
Content-Type: application/json; charset=utf-8
Content-Length: 428
Host: mobile.o.bike
Accept-Encoding: gzip
User-Agent: okhttp/3.4.2

{"value":"1a585fffc27493e530e50c48b834f0df905fa023d59a7db8d64bae39473cd75adc7c33
e8a0e9173845c9478046cff0c85bccbaecc7acd9cfadfc650c30cae4278d7f906da3a710742b6372
79f21f5367f3ea2fd95564ee7077b85af5ef9ebcf7d456c15616ffda4f25524b587936984b62abfe
8a2a94c042d4893c9e74c267a42aed5310acc5fbb4924d57008cb2081e3e3009fdab5cbc7fc640b7
2efc4e2ba2a10af81ac72aee5100e1c706b9eb500810e40aae855134fe9f625bb34a3626e843922c
7c2b222e6f32daf69f130e9350"}
```

Decrypted Payload:
```
{"countryCode":41,"latitude":"47.37326917039802","longitude":"8.531275056302547"
,"deviceId":"0123456789abc-0123456789abcdef01","dateTime":"1508318416019"}&21b7e
af2631f62fca73faf4c63fd75b1302aed4f
```

HTTP Response (with JSON pretty-printed and truncated):
```
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close
Server: cloudflare-nginx

{
  "data": {
    "iconUrl": null,
    "list": [{
      "id": "041003059",
      "longitude": 8.527892,
      "latitude": 47.369085,
      "imei": "6F6E384C30503166",
      "countryId": 167,
      "helmet": 0
    }, {
      "id": "041001731",
      "longitude": 8.526518,
      "latitude": 47.369303,
      "imei": "6F6E53696D39706C",
      "countryId": 167,
      "helmet": 0
    },
    ...
    {
     "id": "041000911",
     "longitude": 8.526561,
     "latitude": 47.377715,
     "imei": "72616C48496E6974",
     "countryId": 167,
     "helmet": 0
   }]
 },
 "success": true
}
```

## Installation
```
 $ apt update
 $ apt install git build-essential python python-pip libbluetooth-dev libglib2.0-dev
 $ git clone https://github.com/antoinet/obike.git
 $ cd obike
 $ pip install -r requirements
```

## References
 * [oBike lock teardown and rebuild, dockless share bike rescue](https://www.youtube.com/watch?v=Vl3Gl8w8n-Q)
 * [Exploration of Weakness in Bike Sharing System](http://www.comp.nus.edu.sg/~hugh/CS3235/CS3235-SemI-2017-18-FinalProjects.pdf), [alternative source](http://web.archive.org/web/20180102175104/http://www.comp.nus.edu.sg/%7Ehugh/CS3235/CS3235-SemI-2017-18-FinalProjects.pdf)
 * [FCC filing Huangzhou Luoping Electronics - Smart Locker HBT203](https://fccid.io/2ALWC-HBT203)
 * [Les vélos en libre service dans les villes de Zurich et de Berne sont désormais retirés de la circulation temporairement, rts.ch](https://www.rts.ch/play/tv/19h30/video/les-velos-en-libre-service-dans-les-villes-de-zurich-et-de-berne-sont-desormais-retires-de-la-circulation-temporairement?id=9797225&station=a9e7621504c6960e35c3ecbe7f6bed0446cdf8da)
 * [CVE-2018-16242](https://seclists.org/bugtraq/2018/Sep/30)
