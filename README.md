Secure Device Connection Protocol
=====

The Secure Device Connection Protocol (SDCP), is designed to enable secure
biometrics with fingerprint sensors, providing a mechanism to ensure that:

1. The device is trusted.
2. The device is healthy.
3. The input from the device is protected.

Thorough documentation can be found on the
[wiki](https://github.com/Microsoft/SecureDeviceConnectionProtocol/wiki/Secure-Device-Connection-Protocol).

Sample Client Implementation
-----

This repository contains a sample client implementation of the protocol
documented in the wiki, using the [mbed TLS](https://tls.mbed.org/) library,
which must be obtained and installed prior to building the sample.

Build
----

To build this sample, the mbed TLS library must have already been built and
installed on your system. CMake and a C compiler for your platform are required.

**Linux** (Tested on Windows Subsystem for Linux, using Ubuntu)

```
git clone https://github.com/Microsoft/SecureDeviceConnectionProtocol.git
cd SecureDeviceConnectionProtocol
mkdir build
cd build
cmake ..
make
```

**Windows** (With Visual Studio)

```
git clone https://github.com/Microsoft/SecureDeviceConnectionProtocol.git
cd SecureDeviceConnectionProtocol
mkdir build
cd build
cmake ..
```

And then open `sdcp.sln` with Visual Studio

Test
-----

This repository contains a test executable, `sdcptest`, that can be used to
generate test vectors for your own client implementation of the protocol, and
can be used as a reference for the expected calling pattern of the client
functions. Example output:

```
Model and device keys:
----------------------

pk_m:
  04c5eb2c24de08a4dd9cfd42c5bc5610277d492111f151bf33ad71ad9525401d
  00d9320976c3c83980fab279d04d1fc9f4196da4d68a2f3b6891189af231bf50
  88
sk_m:
  5496111c965ef41c9cf91e54b38d714b4e7d7c482dcb34a3ec5e7265cf6ec800

Factory provisioning:
---------------------

pk_d:
  04840f109357fbf397e44c895cbfaff6b27527866828c94353120941b6020b1d
  be75ffd7b22b7ee2b7a57e8e89007f06eee43b7b8fceb382f8a6e78b812ed437
  f9
sk_d:
  d9aaf63632d61fa52da80260fdc0bb3ddbc33822cc2fb26fa962828b9bdb4e67
s_m:
  e9782b0e27729276810f3f1a5dfeaa5852e817e1a5cf1cadf20afbc7fc64b282
  a8371b36cb975c9b3bce16c92a40308b3651fccfb6fdca0dd3c850c22109b23f

Device bootloader:
------------------

firmware:
  6669726d77617265
h_f:
  c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835
pk_f:
  04083cb5e7ece3a8ffa2b6d2d52e2c1721f7d8de6eaaca7fad08267e289e97ec
  a18f3bf8afe57e528b6ad07023df442621c4ad8294816d12852339848eb1196d
  16
sk_f:
  1bdd42b6567101a59ef03e342138f506c83f27ecf21418cd9eaee223af7f3193
s_d:
  fd914d22d2fcb199a4d988d091d3ab9b1d50863dd4f118218045ccd3fa6609fa
  f11c6d0290ade334d0f5c954241828bc3723c015a4f4adcb2aede261f347fbfa

Connect:
--------

h_r:
  4916be80a96b552fe4d10793e8cebcc8cb883216ecf051f2b230b16c1a475329
pk_h:
  0462bbb45097fe85ae781de1e1f2b580b49f63fc6a00f7c2d85d909c52369a56
  e4bcee09dc05bf3500a7974d95f92b7a920dcab8fb31507867f453d887d336a3
  06
r_d:
  353eb43ffb422fc96c857140d5c399d588feef46f62bd363b97c823975bb27e7
ms:
  dfffeed23e848c194ae46dda671d0d86a7eea1eac904e7ed3f8c4d7c67a23c42
s:
  073d33268aa9551954a06564784dd7e4f8d6cc29d9fa350c4e2266204ec4e15d
k:
  dec9bb8e35338fb353a597f6243bcc006cb9a72fbd87b8d38a42f5827d48fabc
H(c):
  e3f50f7e6fe4a13eb9d6f631e7e1fbd1ee01aacfc27a23f5130af6a0dc310a6c
m:
  25e4744839cd2fe1e8e136e5175c69ddc016cfddc989c5e285be1aec12d7fe85

Reconnect:
----------

r:
  a65b26a3b441ae724a4730e62672e222a32b4a7edb90aa8389ab282668c16b76
m:
  5f253842eaaa026e8ccc82f1dbc6a5ea885c3abc08b2b1e7f32e9a8b08e1e364
```

Contributing
-----

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
