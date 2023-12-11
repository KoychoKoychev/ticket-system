const crypto = require('crypto')

function sha256(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    const hashHex = hash.digest('hex')
    return hashHex;
}

module.exports = {
    sha256
}
