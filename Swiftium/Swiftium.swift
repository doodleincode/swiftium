//
//  Swiftium.swift
//  Swiftium
//
//  Created by dman on 1/2/17.
//  Copyright © 2017 Daniel Hong. All rights reserved.
//

import Foundation

public final class Swiftium {
    
    public static let utils = Utils()
    public static let memory = Memory()
    
    public static func setup() -> Bool {
        // sodium_init() returns 0 on success, 1 on already initialized
        // If it returns -1 that means failed
        return sodium_init() == -1 ? false : true
    }
    
}

enum SwiftiumError: Error {
    
    // Thrown when an expected length is not valid
    // Examples: key size, nonce size, cipher text less than excepted length
    case invalidSize(reason: String)
    
    // Thrown when any memory allocation fails
    case allocationFailed(reason: String)
    
    // Thrown when any "encrypt" function from Sodium's library fails
    case encryptFailed(reason: String)
    
    // Thrown when any "decrypt" function from Sodium's library fails
    case decryptFailed(reason: String)
    
}

public typealias Key = NSData
public typealias Nonce = NSData
public typealias Mac = NSData
