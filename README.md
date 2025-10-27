# mutka


```


About "trusted-keys"

trusted-keys are ED25519 long-term key pair used for authentication between clients
so they know for sure they are talking to the right person.
Each server member must have each other's PUBLIC trusted key to validate signatures.

They are stored in configurable directory on user's device.
Default is "/home/user/.mutka/<user chosen nickname>/"

The private key is encrypted using AES-256-GCM
and the key for it is passed through key derivation function.



(I will write more techniacal details when more parts are done 
 ~ 331uw13)

```



