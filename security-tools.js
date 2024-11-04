const crypto = require('crypto');
const fs = require('fs');

class SecurityTools {
    // Génération de mot de passe sécurisé
    static generatePassword(length = 16) {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        const array = new Uint8Array(length);
        crypto.randomFillSync(array);
        for (let i = 0; i < length; i++) {
            password += chars[array[i] % chars.length];
        }
        return password;
    }

    // Hachage de texte (SHA-256)
    static hashText(text) {
        return crypto.createHash('sha256').update(text).digest('hex');
    }

    // Chiffrement de texte
    static encryptText(text, key) {
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

    // Déchiffrement de texte
    static decryptText(encrypted, key) {
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

    // Vérification de force de mot de passe
    static checkPasswordStrength(password) {
        const result = {
            score: 0,
            feedback: []
        };

        if (password.length >= 12) result.score += 2;
        else if (password.length >= 8) result.score += 1;
        else result.feedback.push("Le mot de passe est trop court");

        if (/[A-Z]/.test(password)) result.score += 1;
        else result.feedback.push("Ajoutez des majuscules");

        if (/[a-z]/.test(password)) result.score += 1;
        else result.feedback.push("Ajoutez des minuscules");

        if (/[0-9]/.test(password)) result.score += 1;
        else result.feedback.push("Ajoutez des chiffres");

        if (/[^A-Za-z0-9]/.test(password)) result.score += 1;
        else result.feedback.push("Ajoutez des caractères spéciaux");

        return result;
    }

    // Génération de token sécurisé
    static generateToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }
}

// Export de la classe
module.exports = SecurityTools;