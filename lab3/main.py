import jwt

pkey="""-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAukxOhxtFHcm4zRFjF/0g
AxZUUG9Ukr7JLVhvMYLzs/EDcY9KiKsjW3DKOceCuedDTwR9yPTIGvmK/iRR9PM2
lPN6mTqEzloZGNuibrdDssxvxC9ATss4kFobvbsgRJBqgZUmvnfJlraBQM9oIQOu
7J1ATzflemPUgcvHr2j39jqm8Fsu59H/vwgDp/ZsKHKhAgxmNAZwc1CHwpAoS8al
wdYbD/5VzWcIScGiXLlyJ7gPFzdurEBY2RiTVTyllGBeiAzocSzE883sf6aXzhui
L0rJQOvINo8yTkrYCyxoIm3WR2DNjaTQtc2ircIYecQbTClrjwYk7bLuP+b7Qkkt
mKVbgb+JKjgZ34LcHXyJEL06kXQyf0URtt7ilPuQBkjQyklP2KTY63l9ZcFCOdMt
VZ3CNadTlbxUGd4/O/X+0JEopb1ys0U6d0DIfJYrVWVduF+XOEjFISgyBcK4MzEa
6IzVbISSJ/uM0cVWCCdkHYabqDr749EAeA+Ig+djgigd865z+4lJemRJQ/Lwe551
LEwODmCKMxYBV+nM3Y3V//Wdqa5NkS8kyOQEpkMUeaZZVMxcS8GyXjSA6J9A08Eu
7ctJa5Btgc73gAycOh+sy6F+CV4l/e/fm9tAdYsxQF8Jt/xLVTMkcQ9T1YXD8dkm
eSpHf8bSrnaWXRpnHzAriUECAwEAAQ==
-----END PUBLIC KEY-----"""

encoded_jwt = jwt.encode({"user_type":"admin"}, pkey, algorithm="HS256")
print(encoded_jwt)