# mutka


> NOTE: I will add more details in the future...



## About "trusted-keys"
```
trusted-keys are ED25519 long-term key pair
used for authentication between clients
so they know for sure they are talking to the right person.
Each server member must 
have each other's PUBLIC trusted key to validate signatures.

They are stored in configurable directory on user's device.
Default is "/home/user/.mutka/<user chosen nickname>/"

The private key is encrypted using AES-256-GCM
and the key for it is passed through key derivation function.
```

## About packets
```
Packets have this kind of structure:
(first number is the byte offset)
0 - packet_id
4 - expected_length
8 - packet_data

data_entry = "label":<data_encoding_option>"entry_data"

Then the 'packet_data' may be:
packet_data = data_entry|data_entry ...


'entry_data' is always encrypted when a normal message is sent.
But if client and server exchange metadata keys public keys
it will not be encrypted.


The 'data_encoding_option' can be following:
RPACKET_ENCODE_NONE    -  No encoding is done.
RPACKET_ENCODE_BASE64  -  Used for bytes.
(see "./libmutka/include/packet.h")
```

## About packet metadata
```
As seen in the packet structure the 'label'
for packet 'data_entry' may expose some information
about the packet.
While this is not a big issue, encrypting the
whole packet again adds layer of privacy for users

This is done using "metadata keys".
```

