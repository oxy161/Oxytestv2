const crypto = require('crypto');
const SecurityTools = require('./src/security-tools');

console.log('=== Multi-Tools de Sécurité ===\n');

// Test de génération de mot de passe
const password = SecurityTools.generatePassword();
console.log('Mot de passe généré:', password);

// Test de force du mot de passe
const strength = SecurityTools.checkPasswordStrength(password);
console.log('Force du mot de passe:', strength);

// Test de hachage
const hash = SecurityTools.hashText('MonMotDePasse123');
console.log('Hash SHA-256:', hash);

// Test de chiffrement/déchiffrement
const key = crypto.randomBytes(32);
const textToEncrypt = 'Information secrète';
const encrypted = SecurityTools.encryptText(textToEncrypt, key);
console.log('Texte chiffré:', encrypted);

const decrypted = SecurityTools.decryptText(encrypted, key);
console.log('Texte déchiffré:', decrypted);

// Test de génération de token
const token = SecurityTools.generateToken();
console.log('Token généré:', token);