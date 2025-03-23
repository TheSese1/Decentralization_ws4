import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // Use the Web Crypto API to generate the key pair
  const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP", // RSA encryption scheme
        modulusLength: 2048, // 2048-bit key length
        publicExponent: new Uint8Array([1, 0, 1]), // Common public exponent (65537)
        hash: "SHA-256", // Hash function to be used for encryption
      },
      true, // Whether the keys are extractable (i.e., can be exported)
      ["encrypt", "decrypt"] // The keys will be used for encryption and decryption
  );
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  // remove this
  return Buffer.from(exportedKey).toString('base64');
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey
): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  // remove this
  return Buffer.from(exportedKey).toString('base64');
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = Buffer.from(strKey, 'base64');

  const publicKey = await webcrypto.subtle.importKey(
      "spki", // SPKI format for public keys
      keyBuffer, // The ArrayBuffer containing the public key data
      {
        name: "RSA-OAEP", // The algorithm for the key
        hash: "SHA-256",   // Hash function for RSA-OAEP
      },
      true, // Indicating that the key is extractable
      ["encrypt"] // The operations this public key will be used for
  );

  return publicKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  // Convert the Base64 string back to ArrayBuffer
  const keyBuffer = Buffer.from(strKey, 'base64');

  // Import the private key from the ArrayBuffer in PKCS#8 format
  const privateKey = await webcrypto.subtle.importKey(
      "pkcs8", // PKCS#8 format for private keys
      keyBuffer, // The ArrayBuffer containing the private key data
      {
        name: "RSA-OAEP", // The algorithm for the key
        hash: "SHA-256",   // Hash function for RSA-OAEP
      },
      true, // Indicating that the key is extractable
      ["decrypt"] // The operations this private key will be used for
  );

  return privateKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
    b64Data: string,
    strPublicKey: string
): Promise<string> {
  // Convert Base64-encoded data to ArrayBuffer
  const dataBuffer = base64ToArrayBuffer(b64Data);

  // Convert the Base64-encoded public key to ArrayBuffer
  const publicKeyBuffer = base64ToArrayBuffer(strPublicKey);

  // Import the public key from the ArrayBuffer (SPKI format)
  const publicKey = await webcrypto.subtle.importKey(
      "spki", // SPKI format for public keys
      publicKeyBuffer, // ArrayBuffer containing the public key
      {
        name: "RSA-OAEP", // The RSA encryption algorithm
        hash: "SHA-256",   // Hash function for RSA-OAEP
      },
      true, // Indicating that the key is extractable
      ["encrypt"] // The operation this key can be used for (encryption)
  );

  // Encrypt the data using the public key
  const encryptedData = await webcrypto.subtle.encrypt(
      {
        name: "RSA-OAEP", // RSA encryption algorithm
      },
      publicKey, // The public key used for encryption
      dataBuffer // The data to be encrypted (ArrayBuffer)
  );

  // Convert the encrypted data to a Base64 string and return it
  return arrayBufferToBase64(encryptedData);
}

// Decrypt a message using an RSA private key
export async function rsaDecrypt(
    data: string,
    privateKey: webcrypto.CryptoKey
): Promise<string> {
  // Convert the Base64-encoded encrypted data to ArrayBuffer
  const encryptedDataBuffer = base64ToArrayBuffer(data);

  // Decrypt the encrypted data using the private key
  const decryptedDataBuffer = await webcrypto.subtle.decrypt(
      {
        name: "RSA-OAEP", // RSA decryption algorithm
      },
      privateKey, // The private key used for decryption
      encryptedDataBuffer // The encrypted data to be decrypted (ArrayBuffer)
  );

  // Convert the decrypted ArrayBuffer back to a string
  const decoder = new TextDecoder();
  const decryptedData = decoder.decode(decryptedDataBuffer);

  return decryptedData;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // Generate a symmetric AES key using the Web Crypto API (AES-GCM for example)
  const key = await webcrypto.subtle.generateKey(
      {
        name: "AES-GCM",      // AES-GCM is a widely used mode of AES encryption
        length: 256,          // Length of the key in bits (AES supports 128, 192, and 256 bits)
      },
      true,                   // Indicate that the key is extractable
      ["encrypt", "decrypt"]  // This key can be used for both encryption and decryption
  );

  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export the key as raw bytes
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);

  // Convert the raw key (ArrayBuffer) to a Base64 string
  return arrayBufferToBase64(exportedKey);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  /// Convert the Base64 string to ArrayBuffer
  const rawKey = base64ToArrayBuffer(strKey);

  // Import the raw key into a native CryptoKey object (AES-GCM for encryption/decryption)
  const key = await webcrypto.subtle.importKey(
      "raw",                  // We are importing the raw key material
      rawKey,                 // The raw key as ArrayBuffer
      { name: "AES-GCM" },    // We specify AES-GCM algorithm
      true,                   // Make the key extractable if needed (depends on your use case)
      ["encrypt", "decrypt"]  // Specify that this key is for both encryption and decryption
  );

  return key;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // Convert the data to a Uint8Array using TextEncoder
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  // Generate a random initialization vector (IV) for AES-GCM (12 bytes is a common choice)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the data using AES-GCM and the provided key
  const encryptedData = await webcrypto.subtle.encrypt(
      {
        name: "AES-GCM",      // The encryption algorithm
        iv: iv,               // The initialization vector
      },
      key,                   // The symmetric key used for encryption
      dataBuffer             // The data to encrypt (Uint8Array)
  );

  // Concatenate the IV and encrypted data (IV should be stored for decryption)
  const encryptedDataWithIv = new Uint8Array(iv.byteLength + encryptedData.byteLength);
  encryptedDataWithIv.set(iv);
  encryptedDataWithIv.set(new Uint8Array(encryptedData), iv.byteLength);

  return arrayBufferToBase64(encryptedDataWithIv.buffer);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format
  const encryptedDataBuffer = base64ToArrayBuffer(encryptedData);

  // Extract the IV from the encrypted data (the first 12 bytes are the IV for AES-GCM)
  const iv = encryptedDataBuffer.slice(0, 12);

  // The rest of the buffer is the actual encrypted data
  const encryptedMessage = encryptedDataBuffer.slice(12);

  // Import the symmetric key from Base64
  const key = await importSymKey(strKey);

  // Decrypt the data using AES-GCM
  const decryptedDataBuffer = await webcrypto.subtle.decrypt(
      {
        name: "AES-GCM",      // The decryption algorithm
        iv: iv,               // The initialization vector used in encryption
      },
      key,                   // The symmetric key used for decryption
      encryptedMessage       // The encrypted data (ArrayBuffer)
  );

  // Convert the decrypted data back to a string using TextDecoder
  const decoder = new TextDecoder();
  return decoder.decode(decryptedDataBuffer);
}
