const crypto = require('crypto');

class PasswordManager {
    static generate(length = 16) {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        const array = new Uint8Array(length);
        crypto.randomFillSync(array);
        for (let i = 0; i < length; i++) {
            password += chars[array[i] % chars.length];
        }
        return password;
    }

    static checkStrength(password) {
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
}

module.exports = PasswordManager;