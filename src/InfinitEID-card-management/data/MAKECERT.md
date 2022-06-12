# How to create trusted self-signed root certificate

1. `openssl genrsa -out rootkey.pem 4096`

1. `openssl req -new -sha512 -key rootkey.pem -out rootcsr.csr`

    > You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.

    > Country Name (2 letter code) [AU]:**CZ**\
    State or Province Name (full name) [Some-State]:**Czechia**\
    Locality Name (eg, city) []:**Brno**\
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:**Brno University of Technology**\
    Organizational Unit Name (eg, section) []:**UTKOO**\
    Common Name (e.g. server FQDN or YOUR name) []:**Web-eID Nextcloud Root CA**\
    Email Address []:**petr.muzikant@vut.cz**

    > Please enter the following 'extra' attributes
    to be sent with your certificate request\
    A challenge password []:**nextcloudadmin**\
    An optional company name []:

1. `openssl req -x509 -sha512 -days 365 -key rootkey.pem -in rootcsr.csr -out rootcertificate.pem`
    > Warning: No -copy_extensions given; ignoring any extensions in the request

1. `openssl req -in rootcsr.csr -text -noout | grep -i "Signature.*SHA512" && echo "All is well" || echo "This certificate will stop working in 2017! You must update OpenSSL to generate a widely-compatible certificate"`

   > Signature Algorithm: sha512WithRSAEncryption
All is well

1. `openssl req -in rootcsr.csr -text -noout`
    ```
    Certificate Request:
        Data:
            Version: 1 (0x0)
            Subject: C = CZ, ST = Czechia, L = Brno, O = Brno University of Technology, OU = UTKOO, CN = Web-eID Nextcloud Root CA, emailAddress = petr.muzikant@vut.cz
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    Public-Key: (4096 bit)
                    Modulus:
                        00:d0:d3:5d:e9:69:9d:cd:be:86:c6:f8:4a:bc:69:
                        8b:72:42:a4:5e:bc:c2:6a:23:9b:dd:58:76:98:37:
                        8c:14:c3:42:ef:f5:9b:71:80:a8:cd:ea:b0:25:f8:
                        16:80:88:73:74:7a:6a:a7:6c:40:2f:92:4c:fc:db:
                        29:01:e8:45:d0:94:d5:a7:0a:9d:11:ff:92:c3:c9:
                        65:55:fd:44:e4:e6:4b:ad:3b:00:a1:d7:e5:a2:6c:
                        63:e7:2a:da:c0:9f:03:1d:e8:e3:ae:63:7d:58:f1:
                        d8:3f:8f:ff:91:5e:01:ed:74:83:93:6a:0f:b4:2b:
                        e4:d7:5d:5d:36:22:15:7b:8b:bb:18:3c:77:87:f1:
                        c5:e8:d7:37:7b:98:51:a6:0f:a6:ec:18:92:9b:c6:
                        d5:92:b3:fd:ca:a8:37:cb:7a:2e:70:e4:94:a5:0e:
                        62:3f:bb:ad:1a:9e:b7:42:eb:12:35:1a:47:30:84:
                        05:ea:26:56:17:c8:6d:29:ee:a2:4f:39:1b:0b:22:
                        48:02:01:33:03:d1:51:63:b4:0f:22:5a:46:f5:8c:
                        82:d5:cf:76:f0:c2:84:69:7b:3e:7d:90:b0:1b:b4:
                        a2:e1:04:81:c2:ae:32:53:7e:35:3e:4f:a0:97:a2:
                        fa:c6:8d:d5:3f:d2:66:b0:32:a0:cc:b3:83:26:3d:
                        10:3f:14:b6:a3:69:4a:02:04:d9:c6:8a:c3:1b:de:
                        5d:99:78:f7:43:78:ee:02:48:9f:8d:75:d4:96:31:
                        d8:15:94:27:de:78:0d:00:82:08:5d:17:db:5f:83:
                        57:5b:cd:be:61:94:6d:f9:48:ab:66:a0:d6:34:0b:
                        95:1e:c0:e7:8d:50:c1:8e:60:7b:0d:73:1c:f0:62:
                        b2:6b:b0:1c:c6:4b:02:48:a7:3e:a5:25:e0:cf:96:
                        35:72:19:7c:4f:49:a5:0b:0b:a4:f0:8f:b8:2a:bc:
                        93:78:06:be:3a:a1:00:54:60:16:b7:22:19:0f:82:
                        b3:f2:55:b4:38:ce:44:fe:c1:c4:e0:a2:90:c2:5d:
                        f8:81:1c:39:c1:fa:f3:21:56:66:06:9a:2f:5d:ec:
                        3f:36:f0:6a:4a:67:5e:86:6f:9d:ca:7a:60:94:8a:
                        4d:e6:c5:41:32:ed:4e:ac:f5:cb:6d:f6:60:1b:55:
                        98:6f:b2:05:71:aa:e1:25:7d:c0:d8:b0:96:43:d0:
                        d4:31:ff:b2:2a:30:b3:66:0c:b2:1f:f2:c9:4c:88:
                        c6:40:05:e8:de:2c:2b:1f:ec:68:1c:3f:d0:0e:35:
                        05:d4:38:07:1b:8b:b7:1a:cd:bc:aa:65:dd:fa:c2:
                        9b:40:3d:9b:1a:47:33:d4:61:27:c8:21:86:b0:6b:
                        77:b2:2b
                    Exponent: 65537 (0x10001)
            Attributes:
                challengePassword        :nextcloudadmin
                Requested Extensions:
        Signature Algorithm: sha512WithRSAEncryption
        Signature Value:
            7d:ae:17:aa:35:2c:9b:ad:33:04:6f:27:89:da:47:86:5e:bc:
            9d:25:03:63:21:f6:69:ac:19:d2:c5:ef:de:28:7f:cb:9a:a8:
            9a:43:26:b3:30:0f:3a:11:20:ef:d9:6a:bc:29:74:80:3e:83:
            2c:5f:ed:50:ed:7b:81:8c:85:94:47:30:c2:eb:c5:10:53:5a:
            fd:d0:95:95:87:2f:8d:45:e1:87:a5:09:ab:5f:d4:88:bd:a4:
            f6:94:27:a3:7e:f6:88:55:e6:81:7d:e8:ef:8e:c5:b2:08:ac:
            2b:be:ce:64:1f:71:c4:e9:d4:98:7a:17:92:2e:06:49:56:6f:
            4b:72:d4:61:da:a8:31:e2:2f:95:58:9c:e1:22:9a:ca:e1:63:
            0d:d3:da:e9:08:0e:70:96:29:ec:53:cf:3f:c6:72:1b:be:77:
            c9:e9:ed:0e:b6:1c:70:eb:4b:91:29:c2:06:ef:5a:4e:14:d4:
            ce:c1:34:07:d2:24:36:17:6e:42:3a:19:ad:9b:fd:eb:ee:95:
            79:e3:77:e6:b5:ba:df:aa:c0:bb:01:03:0a:cd:b3:8f:ab:c2:
            9d:2d:44:d3:82:cf:4a:01:e2:f3:9c:64:dd:d7:74:2b:b7:ab:
            f7:30:ab:91:7b:e4:a7:63:02:a3:86:c6:dc:e7:98:d6:50:28:
            18:06:67:ca:78:80:34:d9:eb:e4:86:06:8f:8e:30:e2:ae:d7:
            34:ab:e1:64:da:70:66:4a:e3:05:7f:47:10:b5:1f:b1:54:69:
            9b:75:56:07:55:9f:9a:d6:0e:40:1b:77:59:04:05:c9:5f:bd:
            99:51:9f:9f:2e:58:34:23:bb:45:c9:62:a8:7e:da:e1:b1:f2:
            f2:79:20:ab:26:f9:28:6e:40:52:b2:14:bf:f5:99:3d:18:e4:
            74:6a:54:60:c5:60:28:6f:a0:fc:81:ff:c5:0f:a9:95:5f:38:
            42:1c:39:66:38:2a:4c:b9:ae:9c:ec:9e:5c:c3:21:8a:b4:35:
            29:1f:8d:3c:89:3a:ca:4e:8f:f9:82:fc:c5:36:06:f8:f8:5f:
            8e:db:85:42:bf:c5:63:85:5d:85:89:14:03:5e:3e:b2:5a:68:
            ed:ff:70:50:ca:44:f4:e9:d6:ae:94:b7:ff:af:eb:c6:66:a0:
            a0:b3:85:d7:b9:1d:68:dd:1e:ba:a6:5e:81:38:e1:13:ee:42:
            5e:8b:b1:12:b1:c0:f0:9f:51:a5:3e:68:18:59:a7:45:73:42:
            ef:be:7b:9c:97:97:96:dd:c8:78:33:e7:e6:3d:d2:79:b4:19:
            34:7c:a6:92:2b:0e:30:7f:97:96:9c:47:2e:86:5a:d9:40:41:
            a2:97:96:02:57:8b:c3:78
    ```