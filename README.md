# Intel SGX WAVE Demo

Sample code taken from the Intel SGX remote attestation [example](https://software.intel.com/en-us/articles/intel-software-guard-extensions-remote-attestation-end-to-end-example) and [Tiny AES in C](https://github.com/kokke/tiny-AES-c)

### Remote Attestation Simulation Notes
* "network_ra.cpp" simulates network communication between the enclave app (ISV app) and the client/challenger (service provider)
* "service_provider.cpp" simulates the client/challenger (service provider). Many security features (such as enrollment and message verification) are not implemented and are left for production. These are pointed out in the comments of the sample app.
* "isv_app.cpp" simulates the enclave app (ISV app). Some features are not fully implemented to production standards

### Todo
* Generate enclave signature using command line such that client can match it to the quote given by the enclave

### How to generate the enclave signature


