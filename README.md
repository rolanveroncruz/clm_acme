# CLM Acme
CLM Acme is one of the three parts of the Certificate Lifecycle Management system.
It is the client for the ACME protocol which communicates with the ACME server of the CA.
This code base is separate from the CLM Client for easier development and testing.
It is what coordinates with the CA's ACME server to setup the HTTP-01 solution in the CLM Client.


### October 28, 2025
Conceptually, this is working already. Just need to test one more time. Problem now is just that
we've reached LetsEncrypt's rate limit.
Next to figure out is how to make this work with GlobalSign as an acme client.
The miscellaneous stuff like uploading the certificate files to the clm_client still needs to be decided on:
if this acme client will run on the clm_client, there won't be a need to upload the certificate files anymore.