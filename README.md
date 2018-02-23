# Intel SGX WAVE Demo

Sample code taken from [hello enclave](https://github.com/digawp/hello-enclave), [Tiny AES in C](https://github.com/kokke/tiny-AES-c), and this simple [UDP client](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/udpclient.c)

### Remote Attestation Simulation Notes
* "network_ra.cpp" simulates network communication between the enclave app (ISV app) and the client/challenger (service provider)
* "service_provider.cpp" simulates the client/challenger (service provider). Many security features (such as enrollment and message verification) are not implemented and are left for production. These are pointed out in the comments of the sample app.
* "isv_app.c" simulates the enclave app (ISV app). Some features are not fully implemented to production standards

### Todo
* Generate enclave signature using command line for client

### How to generate the enclave signature


