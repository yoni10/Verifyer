# Verifyer
Tool to sign and validating tokens


### Prerequisites

- Open PowerShel as Administrator and run this command
    ```
    $todaydt = Get-Date
    $10years = $todaydt.AddYears(10)
    New-SelfSignedCertificate -dnsname verifyer.co.il -notafter $10years -CertStoreLocation cert:\LocalMachine\My
    ```
- Go to Certificate Manager and export the certificate as pfx file
  - choose with the private key option
  - name the file as Verifyer.pfx
  - set password "12345" etc..
  
- Open cmd in the location of the exported Verifyer.pfx file and run this command
    ```
    openssl pkcs12 -in Verifyer.pfx -nocerts -out keypair.key
    ```
- and then run this command
    ```
      openssl rsa -in keypair.key -pubout -out public.key
     ```
- and then run this command
    ```
      openssl pkcs12 -info -in Verifyer.pfx -nodes -out private.key
     ```
- Copy the private.key to the signer and the public.key to the client
