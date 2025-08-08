## 1. Visit below URL

https://accounts.zoho.com/oauth/v2/auth?scope=ZohoCRM.modules.ALL,ZohoCRM.settings.ALL,ZohoCRM.Files.CREATE&client_id=1000.CDTB3FQJIP5QHTHSG99MGTESYCJQWK&response_type=code&access_type=offline&redirect_uri=https://itrpartnerportal.preview.softr.app&prompt=consent

```bash
--->   code=1000.f85ebb2dca412724e0f40de5adad2114.3d51ff1777ad8586b70dece71920e967
```

## 2. Run request below

```bash
curl -X POST \
  https://accounts.zoho.com/oauth/v2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&client_id=1000.CDTB3FQJIP5QHTHSG99MGTESYCJQWK&client_secret=9b9c6f8cc831d55fec8ece948e81a04a14a96206a1&redirect_uri=https://itrpartnerportal.preview.softr.app&code=1000.817ebb5fc1906d06813c301e50b2a60c.b74a9c1a1b3c6a8cb971ebfc6e38a01a'
```


CLIENT ID: 1000.CDTB3FQJIP5QHTHSG99MGTESYCJQWK

CLIENT SECRET: 9b9c6f8cc831d55fec8ece948e81a04a14a96206a1

"refresh_token": "1000.2122ccc5ebc3c05fe8174de2307ac061.4dcc210776e36e271e497a6e678900a7"


Whenever you need an access token, use the refresh token:

POST https://accounts.zoho.com/oauth/v2/token

Parameters:
- refresh_token=YOUR_REFRESH_TOKEN
- client_id=YOUR_CLIENT_ID
- client_secret=YOUR_CLIENT_SECRET
- grant_type=refresh_token