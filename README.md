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
