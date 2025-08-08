https://accounts.zoho.com/oauth/v2/auth?scope=ZohoAnalytics.fullaccess.all&client_id=1000.S5MSJ8DAQ78GY94FK63MROR8MYHOYP&response_type=code&access_type=offline&redirect_uri=https://itrpartnerportal.preview.softr.app&prompt=consent

https://itrpartnerportal.preview.softr.app/?code=1000.ba3adb0b2e4b5cd7c68e54020264968e.efcec734a6888cb59bdedc2fa63894e0&location=us&accounts-server=https%3A%2F%2Faccounts.zoho.com&

code = 1000.ba3adb0b2e4b5cd7c68e54020264968e.efcec734a6888cb59bdedc2fa63894e0

curl -X POST \
  https://accounts.zoho.com/oauth/v2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&client_id=1000.S5MSJ8DAQ78GY94FK63MROR8MYHOYP&client_secret=d09f3c3e0bb37c23d9e211a4c5394963cafd1101cf&redirect_uri=https://itrpartnerportal.preview.softr.app&code=1000.4b2c89aae1eb7738ccc41fc7f3759b37.e5a93d1a07bb20ef98ac232e1e57c8d0'


  https://accounts.zoho.com/oauth/v2/token?code=<CODE>&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&redirect_uri=<REDIRECT_URI>&grant_type=authorization_code

  refresh token=1000.d4ca2b4041e2621e71b233a4716c13d1.53d8d747c5760e03c4670e9c3460a986