//
//  SecretBox.swift
//  Swiftium
//
//  Created by dman on 1/2/17.
//  Copyright © 2017 Daniel Hong. All rights reserved.
//

import Foundation

public class SecretBox {
    
    public static let keySize = Int(crypto_secretbox_keybytes())
    public static let nonceSize = Int(crypto_secretbox_noncebytes())
    public static let macSize = Int(crypto_secretbox_macbytes())
    
    public init() { }
    
    //
    // Secret-key authenticated encryption
    // This is a quick method to encrypt. With the given message, a random key is generated
    // and the results are returned as a tuple of the cipher text and key
    //
    // This uses sodium's crypto_secretbox_easy() function
    //
    // - Parameters:
    //     - message: The plain text message to encrypt
    //
    // - Returns: A tuple of the nonce + mac + cipher text and the key
    //
    public func encrypt(message: NSData) throws -> (nonceMacCipherText: NSData, secretKey: Key) {
        // Generate a random key
        guard let secretKey = Swiftium.utils.randomBytes(len: SecretBox.keySize) else {
            throw SwiftiumError.allocationFailed(reason: "Random bytes generation failed")
        }
        
        // Try and encrypt
        // We are not catching exceptions because we want them to bubble up to the caller
        let nonceMacCipherText: NSData = try encrypt(message: message, secretKey: secretKey)
        
        return (nonceMacCipherText: nonceMacCipherText, secretKey: secretKey)
    }
    
    //
    // Secret-key authenticated encryption
    // Encrypts the given message and computes an auth tag (aka mac) on the encrypted value and returns
    // the results as nonce + mac + cipher text
    //
    // This uses sodium's crypto_secretbox_easy() function
    //
    // - Parameters:
    //     - message: The plain text message to encrypt
    //     - secretKey: A secret key used to encrypt the message and compute the mac
    //
    // - Returns: Combined results as nonce + mac + cipher text
    //
    public func encrypt(message: NSData, secretKey: Key) throws -> NSData {
        // Passing the params to our main encrypt method
        // We are not catching exceptions because we want them to bubble up to the caller
        let (macCipherText, nonce): (NSData, Nonce)
                    = try encrypt(message: message, secretKey: secretKey)
        
        // Concat the nonce and mac+cipher values
        let nonceMacCipherText = NSMutableData()
        nonceMacCipherText.append(nonce as Data)
        nonceMacCipherText.append(macCipherText as Data)
        
        return nonceMacCipherText
    }
    
    //
    // Secret-key authenticated encryption
    // Encrypts the given message and computes an auth tag (aka mac) on the encrypted value and returns
    // the results a tuple
    //
    // This uses sodium's crypto_secretbox_easy() function
    //
    // - Parameters:
    //     - message: The plain text message to encrypt
    //     - secretKey: A secret key used to encrypt the message and compute the mac
    //
    // - Returns: A tuple of the mac+cipher text and nonce values
    //
    public func encrypt(message: NSData, secretKey: Key) throws -> (macCipherText: NSData, nonce: Nonce) {
        // Make sure the key size is valid
        if secretKey.length != SecretBox.keySize {
            throw SwiftiumError.invalidSize(reason: "Secret key length not valid")
        }
        
        // Allocate enough bytes to hold the encrypted text and mac
        guard let macCipherText = NSMutableData(length: message.length + SecretBox.macSize) else {
            throw SwiftiumError.allocationFailed(reason: "Unable to allocate NSMutableData for macCipherText")
        }
        
        // Generate random bytes for the nonce
        // Nonce is basically the IV and should be different everytime
        guard let nonce = Swiftium.utils.randomBytes(len: SecretBox.nonceSize) else {
            throw SwiftiumError.allocationFailed(reason: "Random bytes generation failed")
        }
        
        // Run everything through sodiums crypto_secretbox_easy() function
        // This works well out of the box, however the secretKey is used to encrypt and create the mac
        // which can become an attack surface
        if crypto_secretbox_easy(macCipherText.mutableBytesPtr(), message.bytesPtr(),
                                 UInt64(message.length), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            throw SwiftiumError.encryptFailed(reason: "Sodium crypto_secretbox_easy() verification failed")
        }
        
        return (macCipherText: macCipherText, nonce: nonce)
    }
    
    //
    // Secret-key authenticated encryption
    // Same as the other encrypt(...) overloaded methods, except this returns a tuple of all
    // computed values individually
    //
    // This uses sodium's crypto_secretbox_detached() function
    //
    // - Parameters:
    //     - message: The plain text message to encrypt
    //     - secretKey: A secret key used to encrypt the message and compute the mac
    //
    // - Returns: A tuple of the cipher text, nonce, and mac
    //
    public func encrypt(message: NSData, secretKey: Key) throws -> (cipherText: NSData, nonce: Nonce, mac: Mac) {
        // Make sure the key size is valid
        if secretKey.length != SecretBox.keySize {
            throw SwiftiumError.invalidSize(reason: "Secret key length not valid")
        }
        
        // Allocate memory for the cipher text
        guard let cipherText = NSMutableData(length: message.length) else {
            throw SwiftiumError.allocationFailed(reason: "Unable to allocate NSMutableData for cipherText")
        }
        
        // Allocate memory for the mac
        guard let mac = NSMutableData(length: SecretBox.macSize) else {
            throw SwiftiumError.allocationFailed(reason: "Unable to allocate NSMutableData for mac")
        }
        
        // Generate random bytes for the nonce
        guard let nonce = Swiftium.utils.randomBytes(len: SecretBox.nonceSize) else {
            throw SwiftiumError.allocationFailed(reason: "Random bytes generation failed")
        }
        
        // Using the "detached" function this time so that we can get the values for each
        // of the computed parts
        if crypto_secretbox_detached(cipherText.mutableBytesPtr(), mac.mutableBytesPtr(),
                                     message.bytesPtr(), UInt64(message.length),
                                     nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            throw SwiftiumError.encryptFailed(reason: "Sodium crypto_secretbox_detached() verification failed")
        }
        
        return (cipherText: cipherText, nonce: nonce, mac: mac)
    }
    
    //
    // Secret-key authenticated decryption
    // Decrypts the combined nonce + mac + ciphertext that was computed from encrypt() -> NSData
    //
    // This uses sodium's crypto_secretbox_open_easy() function
    //
    // - Parameters:
    //     - nonceAndAuthenticatedCipherText: The combined nonce + mac + ciphertext
    //     - secretKey: The same secret key originally used to encrypt
    //
    // - Returns: The decoded message
    //
    public func decrypt(nonceMacCipherText: NSData, secretKey: Key) throws -> NSData {
        // Make sure the given buffer is at least the size of mac and nonce
        // We don't know how long the cipher text should be so it's not possible to
        // check if the buffer is of correct length
        if nonceMacCipherText.length < SecretBox.macSize + SecretBox.nonceSize {
            throw SwiftiumError.invalidSize(reason: "Cipher text length not valid")
        }
        
        // Try and allocate memory for some length of size greater than the mac and nonce sizes combined
        // If this does not fail, we can some what assume that a cipher text is present in the orginal buffer
        guard let _ = NSMutableData(length: nonceMacCipherText.length -
                        SecretBox.macSize - SecretBox.nonceSize) else {
            throw SwiftiumError.invalidSize(reason: "Cipher text length not valid")
        }
        
        // Pull out the nonce value
        let nonce = nonceMacCipherText.subdata(with: NSRange(0..<SecretBox.nonceSize)) as Nonce
        
        // Pull out the mac+cipher value
        let macCipherText = nonceMacCipherText.subdata(with:
                NSRange(SecretBox.nonceSize..<nonceMacCipherText.length)) as NSData
        
        return try decrypt(macCipherText: macCipherText, secretKey: secretKey, nonce: nonce)
    }
    
    //
    // Secret-key authenticated decryption
    // Decrypts the combined mac + ciphertext that was computed from encrypt() -> (NSData, Nonce)
    //
    // This uses sodium's crypto_secretbox_open_easy() function
    //
    // - Parameters:
    //     - authenticatedCipherText: The combined mac + ciphertext
    //     - secretKey: The same secret key originally used to encrypt
    //     - nonce: The same nonce value used to encrypt
    //
    // - Returns: The decoded message
    //
    public func decrypt(macCipherText: NSData, secretKey: Key, nonce: Nonce) throws -> NSData {
        // Make sure the given ciper text is at least the length of the mac
        if macCipherText.length < SecretBox.macSize {
            throw SwiftiumError.invalidSize(reason: "Cipher text length not valid")
        }
        
        // Allocate buffer for the decoded message
        guard let message = NSMutableData(length: macCipherText.length - SecretBox.macSize) else {
            throw SwiftiumError.allocationFailed(reason: "Unable to allocate NSMutableData for message")
        }
        
        // Try and decrypt
        if crypto_secretbox_open_easy(message.mutableBytesPtr(), macCipherText.bytesPtr(),
                                      UInt64(macCipherText.length), nonce.bytesPtr(),
                                      secretKey.bytesPtr()) != 0 {
            throw SwiftiumError.decryptFailed(reason: "Sodium crypto_secretbox_open_easy() verification failed")
        }
        
        return message
    }
    
    //
    // Secret-key authenticated decryption
    // Decrypts the ciphertext that was computed from encrypt() -> (NSData, Nonce, Mac)
    //
    // This uses sodium's crypto_secretbox_open_detached() function
    //
    // - Parameters:
    //     - cipherText: The combined mac + ciphertext
    //     - secretKey: The same secret key originally used to encrypt
    //     - nonce: The same nonce value used to encrypt
    //     - mac: The same mac value computed from the encryption
    //
    // - Returns: The decoded message
    //
    public func decrypt(cipherText: NSData, secretKey: Key, nonce: Nonce, mac: Mac) throws -> NSData {
        // Make sure the given key, nonce, and mac values are at least of the correct length
        if secretKey.length != SecretBox.keySize
            || nonce.length != SecretBox.nonceSize
            || mac.length != SecretBox.macSize {
            throw SwiftiumError.invalidSize(reason: "Expected lengths were invalid")
        }
        
        // Allocate memory for the decoded message
        guard let message = NSMutableData(length: cipherText.length) else {
            throw SwiftiumError.allocationFailed(reason: "Unable to allocate NSMutableData for message")
        }
        
        // Try and decrypt
        if crypto_secretbox_open_detached(message.mutableBytesPtr(), cipherText.bytesPtr(),
                                          mac.bytesPtr(), UInt64(cipherText.length),
                                          nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            throw SwiftiumError.decryptFailed(reason: "Sodium crypto_secretbox_open_detached() verification failed")
        }
        
        return message
    }
    
}
