const crypto = require('crypto')
const nacl = require('tweetnacl-sealed-box');
const { fromHexString } = require('./formatsTransform');

const ENCRYPTION_KEY_SUPPORT = 'EncryptionKeyContext'
const MOCK_HASH_KEY = '7a30c31575197861405d2346de765baab1b77900adb192d0243fe4db8e0b314a'
const KEYS_VERSIONS = {
    "1.0.0": "7a30c31575197861405d2346de765baab1b77900adb192d0243fe4db8e0b314a",
    "1.1.0": "6a30c31575197861405d2346de765baab1b77900adb192d0243fe4db8e0b314a"
}

function sha256(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    const hashHex = hash.digest('hex')
    return hashHex;
}

async function getKeyPairFromHashedUserKey(UserKey) {
    try {
        let KeyPair
        if (UserKey) {
            const hashedUserKey = fromHexString(sha256(ENCRYPTION_KEY_SUPPORT + UserKey))
            KeyPair = nacl.box.keyPair.fromSecretKey(hashedUserKey)
        } else {
            return false;
        }
        return KeyPair
    } catch (err) {
        return false;
    }
}

async function getKeyPair(keyVersion) {
    if(keyVersion){
        return await getKeyPairFromHashedUserKey(KEYS_VERSIONS[keyVersion])
    }
    return await getKeyPairFromHashedUserKey(MOCK_HASH_KEY)
}

function generateIV() {
    const initializationVector = crypto.getRandomValues(new Uint8Array(16));
    return initializationVector
}

function encryptDataAES256(key, iv, data) {
    const algorith = 'aes-256-cbc';
    const cipher = crypto.createCipheriv(algorith, key, iv)
    const encryptedMessage = cipher.update(data, 'utf-8', 'hex') + cipher.final('hex')
    return encryptedMessage;
}

function decryptDataAES256(key, iv, cipherData) {
    const algorith = 'aes-256-cbc';
    const decipher = crypto.createDecipheriv(algorith, key, iv);
    const decryptedMessage = decipher.update(cipherData, 'hex', 'utf-8') + decipher.final('utf-8');
    return decryptedMessage;
}

function generateNonce() {
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    return nonce
}

function encryptDataX25519(publicKey, nonce, data) {
    try {
        let sealedBox = nacl.sealedbox(data, nonce, publicKey);
        return sealedBox;
    } catch (err) {
        return null
    }
}

function decryptDataX25519(secretKey, nonce, box) {
    try {
        let openedBox = nacl.sealedbox.open(box, nonce, secretKey);
        return openedBox;
    } catch (err) {
        return null;
    }
}

module.exports = {
    sha256
}
