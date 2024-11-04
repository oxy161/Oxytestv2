const crypto = require('crypto');

class CryptoManager {
    static hash(text) {
        return crypto.createHash('sha256').update(text).digest('hex');
    }

    static encrypt(text, key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return {
            iv: iv.toString('hex'),
            encryptedData: encrypted,
            authTag: authTag.toString('hex')
        };
    }

    static decrypt(encrypted, key) {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(key),
            Buffer.from(encrypted.iv, 'hex')
        );
        decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
        let decrypted = decipher.update(encrypted.encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    static generateToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }
}

module.exports = CryptoManager;