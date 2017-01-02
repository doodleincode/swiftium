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
    // Encrypts the given message and computes an auth tag (aka mac) on the encrypted value and returns
    // the results as nonce + mac + cipher text
    //
    // This uses sodium's crypto_secretbox_easy() function
    //
    // - Parameters:
    //     - message: The plain text message to encrypt
    //     - secretKey: A secret key used to encrypt the message and compute the mac
    //
    // - Returns: Combined results as nonce + auth tag + cipher text
    //
    public func encrypt(message: NSData, secretKey: Key) -> NSData? {
        // Passing the params to the overloaded method below so that we can get
        guard let (authenticatedCipherText, nonce): (NSData, Nonce)
            = encrypt(message: message, secretKey: secretKey) else {
                return nil
        }
        
        // Concat the auth+cipher with the nonce value
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce as Data)
        nonceAndAuthenticatedCipherText.append(authenticatedCipherText as Data)
        
        return nonceAndAuthenticatedCipherText
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
    public func encrypt(message: NSData, secretKey: Key) -> (authenticatedCipherText: NSData, nonce: Nonce)? {
        // Make sure the key size is valid
        if secretKey.length != SecretBox.keySize {
            return nil
        }
        
        // Allocate enough bytes to hold the encrypted text and mac
        guard let authenticatedCipherText = NSMutableData(length: message.length + SecretBox.macSize) else {
            return nil
        }
        
        // Generate random bytes for the nonce
        // Nonce is basically the IV and should be different everytime
        guard let nonce = Swiftium.utils.randomBytes(len: SecretBox.nonceSize) else {
            return nil
        }
        
        // Run everything through sodiums crypto_secretbox_easy() function
        // This works well out of the box, however the secretKey is used to encrypt and create the mac
        // which can become an attack surface
        if crypto_secretbox_easy(authenticatedCipherText.mutableBytesPtr(), message.bytesPtr(),
                                 UInt64(message.length), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
        }
        
        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
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
    public func encrypt(message: NSData, secretKey: Key) -> (cipherText: NSData, nonce: Nonce, mac: Mac)? {
        // Make sure the key size is valid
        if secretKey.length != SecretBox.keySize {
            return nil
        }
        
        // Allocate memory for the cipher text
        guard let cipherText = NSMutableData(length: message.length) else {
            return nil
        }
        
        // Allocate memory for the mac
        guard let mac = NSMutableData(length: SecretBox.macSize) else {
            return nil
        }
        
        // Generate random bytes for the nonce
        guard let nonce = Swiftium.utils.randomBytes(len: SecretBox.nonceSize) else {
            return nil
        }
        
        // Using the "detached" function this time so that we can get the values for each
        // of the computed parts
        if crypto_secretbox_detached(cipherText.mutableBytesPtr(), mac.mutableBytesPtr(), message.bytesPtr(),
                                     UInt64(message.length), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
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
    public func decrypt(nonceAndAuthenticatedCipherText: NSData, secretKey: Key) -> NSData? {
        // Make sure the given buffer is at least the size of mac and nonce
        // We don't know how long the cipher text should be so it's not possible to
        // check if the buffer is of correct length
        if nonceAndAuthenticatedCipherText.length < SecretBox.macSize + SecretBox.nonceSize {
            return nil
        }
        
        // Try and allocate memory for some length of size greater than the mac and nonce sizes combined
        // If this does not fail, we can some what assume that a cipher text is present in the orginal buffer
        guard let _ = NSMutableData(length: nonceAndAuthenticatedCipherText.length -
            SecretBox.macSize - SecretBox.nonceSize) else {
                return nil
        }
        
        // Pull out the nonce value
        let nonce = nonceAndAuthenticatedCipherText.subdata(with: NSRange(0..<SecretBox.nonceSize)) as Nonce
        
        // Pull out the mac+cipher value
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(with:
            NSRange(SecretBox.nonceSize..<nonceAndAuthenticatedCipherText.length)) as NSData
        
        return decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonce)
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
    public func decrypt(authenticatedCipherText: NSData, secretKey: Key, nonce: Nonce) -> NSData? {
        // Make sure the given ciper text is at least the length of the mac
        if authenticatedCipherText.length < SecretBox.macSize {
            return nil
        }
        
        // Allocate buffer for the decoded message
        guard let message = NSMutableData(length: authenticatedCipherText.length - SecretBox.macSize) else {
            return nil
        }
        
        // Try and decrypt
        if crypto_secretbox_open_easy(message.mutableBytesPtr(), authenticatedCipherText.bytesPtr(),
                                      UInt64(authenticatedCipherText.length), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
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
    public func decrypt(cipherText: NSData, secretKey: Key, nonce: Nonce, mac: Mac) -> NSData? {
        // Make sure the given key, nonce, and mac values are at least of the correct length
        if secretKey.length != SecretBox.keySize || nonce.length != SecretBox.nonceSize
            || mac.length != SecretBox.macSize {
            return nil
        }
        
        // Allocate memory for the decoded message
        guard let message = NSMutableData(length: cipherText.length) else {
            return nil
        }
        
        // Try and decrypt
        if crypto_secretbox_open_detached(message.mutableBytesPtr(), cipherText.bytesPtr(), mac.bytesPtr(),
                                          UInt64(cipherText.length), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
        }
        
        return message
    }
    
}
