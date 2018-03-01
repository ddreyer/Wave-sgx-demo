# Intel SGX WAVE Demo

Sample code taken from the Intel SGX remote attestation [example](https://software.intel.com/en-us/articles/intel-software-guard-extensions-remote-attestation-end-to-end-example) and [RSA-Library](https://github.com/andrewkiluk/RSA-Library)

### Remote Attestation Simulation Notes
* "network_ra.cpp" simulates network communication between the enclave app (ISV app) and the client/challenger.
* "client.cpp" simulates the client/challenger. Many security features (such as enrollment and message verification) are not implemented and are left for production. These are pointed out in the comments of the sample app.
* "isv_app.cpp" simulates the enclave app (ISV app). Some features are not fully implemented to production standards

### Todo
* Generate enclave signature using command line such that client can match it to the quote given by the enclave

### How to generate the enclave signature
$ sgx_sign sign -key isv_enclave/isv_enclave_private.pem -enclave isv_enclave.so -out isv_enclave.signed.so -config isv_enclave/isv_enclave.config.xml 

