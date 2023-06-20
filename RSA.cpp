#include <iostream>
#include <string>
#include <vector>
#include <cmath>

bool isPrime(int number) {
    if (number <= 1) {
        return false;
    }

    for (int i = 2; i <= std::sqrt(number); i++) {
        if (number % i == 0) {
            return false;
        }
    }

    return true;
}

int gcd(int a, int b) {
    if (b == 0) {
        return a;
    }

    return gcd(b, a % b);
}

int modInverse(int a, int m) {
    int m0 = m;
    int y = 0, x = 1;

    if (m == 1) {
        return 0;
    }

    while (a > 1) {
        int q = a / m;
        int t = m;

        m = a % m;
        a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0) {
        x += m0;
    }

    return x;
}

void generateKeys(int p, int q, int& publicKey, int& privateKey, int& modulus) {
    if (!isPrime(p) || !isPrime(q)) {
        std::cout << "p and q must be prime numbers.\n";
        return;
    }

    modulus = p * q;
    int phi = (p - 1) * (q - 1);

    publicKey = 2;
    while (publicKey < phi) {
        if (gcd(publicKey, phi) == 1) {
            break;
        }
        publicKey++;
    }

    privateKey = modInverse(publicKey, phi);
}

int modPow(int base, int exponent, int modulus) {
    int result = 1;

    base %= modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }

    return result;
}

std::vector<int> rsaEncrypt(const std::string& plaintext, int publicKey, int modulus) {
    std::vector<int> ciphertext;

    for (char c : plaintext) {
        int asciiValue = static_cast<int>(c);
        int encryptedValue = modPow(asciiValue, publicKey, modulus);
        ciphertext.push_back(encryptedValue);
    }

    return ciphertext;
}

std::string rsaDecrypt(const std::vector<int>& ciphertext, int privateKey, int modulus) {
    std::string plaintext;

    for (int encryptedValue : ciphertext) {
        int decryptedValue = modPow(encryptedValue, privateKey, modulus);
        char c = static_cast<char>(decryptedValue);
        plaintext += c;
    }

    return plaintext;
}

int main() {
    int p = 29;  // Prime numbers for key generation
    int q = 31;
    int publicKey, privateKey, modulus;  // RSA keys
    std::string plaintext;
    std::vector<int> ciphertext;

    generateKeys(p, q, publicKey, privateKey, modulus);

    std::cout << "Public Key (e): " << publicKey << std::endl;
    std::cout << "Private Key (d): " << privateKey << std::endl;
    std::cout << "Modulus (n): " << modulus << std::endl;

    std::cout << "Enter the plaintext to encrypt: ";
    std::getline(std::cin >> std::ws, plaintext);

    ciphertext = rsaEncrypt(plaintext, publicKey, modulus);

    std::cout << "Ciphertext: ";
    for (int encryptedValue : ciphertext) {
        std::cout << encryptedValue << " ";
    }
    std::cout << std::endl;

    std::string decryptedText = rsaDecrypt(ciphertext, privateKey, modulus);

    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}

