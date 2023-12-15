import eth_keys, eth_utils, binascii, os

# privKey = eth_keys.keys.PrivateKey(os.urandom(32))
privKey = eth_keys.keys.PrivateKey(binascii.unhexlify(
    '97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a'))
pubKey = privKey.public_key
pubKeyCompressed = '0' + str(2 + int(pubKey) % 2) + str(pubKey)[2:66]
address = pubKey.to_checksum_address()

pubKeyHex = pubKey.to_hex()
pubKeyX = list(bytes.fromhex(pubKeyHex[2:])[0:32])
pubKeyY = list(bytes.fromhex(pubKeyHex[2:])[32:])


print('Private key (64 hex digits):', privKey)
print('Public key (plain, 128 hex digits):', pubKey)
print('Public key X:', len(pubKeyX), pubKeyX)
print('Public key Y:', len(pubKeyY), pubKeyY)
print('Public key (compressed):', pubKeyCompressed)
print('Signer address:', address)

msg = b'Message for signing signing signing signing signing signing signing signing'
msgHash = eth_utils.keccak(msg)
signatureInput = msgHash
signature = privKey.sign_msg_hash(signatureInput)

print('Msg:', msg)
print('Msg hash:', binascii.hexlify(msgHash))
print('Signature: [v = {0}, r = {1}, s = {2}]'.format(
  hex(signature.v), hex(signature.r), hex(signature.s)))
print('Signature (130 hex digits):', signature.to_hex())


msgSigner = '0xa44f70834a711F0DF388ab016465f2eEb255dEd0'
signature = eth_keys.keys.Signature(binascii.unhexlify(signature.to_hex()[2:]))
signerPubKey = signature.recover_public_key_from_msg_hash(signatureInput)
print('Signer public key (recovered):', signerPubKey)
signerAddress = signerPubKey.to_checksum_address()
print('Signer address:', signerAddress)
print('Signature valid?:', signerAddress == msgSigner)

print(f"""
    {list(signatureInput)},
    {pubKeyX},
    {pubKeyY},
    {list(binascii.unhexlify(signature.to_hex()[2:])[:-1])}
""")
