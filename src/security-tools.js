const PasswordManager = require('./modules/password');
const CryptoManager = require('./modules/crypto');

class SecurityTools {
    static generatePassword(length) {
        return PasswordManager.generate(length);
    }

    static checkPasswordStrength(password) {
        return PasswordManager.checkStrength(password);
    }

    static hashText(text) {
        return CryptoManager.hash(text);
    }

    static encryptText(text, key) {
        return CryptoManager.encrypt(text, key);
    }

    static decryptText(encrypted, key) {
        return CryptoManager.decrypt(encrypted, key);
    }

    static generateToken(length) {
        return CryptoManager.generateToken(length);
    }
}

module.exports = SecurityTools;