//
//  Utils.swift
//  Swiftium
//
//  Created by dman on 1/2/17.
//  Copyright © 2017 Daniel Hong. All rights reserved.
//

import Foundation

public class Utils {
    
    //
    // Compare large numbers
    // The comparison is done in constant time for a given length
    //
    // - Parameters:
    //     - b1: First number
    //     - b2: Second number
    //
    // - Returns:
    //     -1 if b1 less than b2
    //     0 if b1 equals b2
    //     1 if b1 greater than b2
    //     nil if lengths do not match
    //
    public func compare(_ b1: NSData, _ b2: NSData) -> Int? {
        if b1.length != b2.length {
            return nil
        }
        
        let res = sodium_compare(b1.bytesPtr(), b2.bytesPtr(), b1.length)
        return Int(res)
    }
    
    //
    // Compare for equality
    // The comparison is done in constant time for a given length
    //
    // - Parameters:
    //     - b1: First data
    //     - b2: Second data
    //
    // - Returns: true if equal, false otherwise
    //
    public func equals(_ b1: NSData, _ b2: NSData) -> Bool {
        if b1.length != b2.length {
            return false
        }
        
        return sodium_memcmp(b1.bytesPtr(), b2.bytesPtr(), b1.length) == 0
    }
    
    //
    // Generate random bytes of given length
    //
    // - Parameter len: Size of random bytes
    //
    // - Returns: On success NSData containing the random bytes; on fail nil
    //
    public func randomBytes(len: Int) -> NSData? {
        // Alloc the len size of bytes, if error we'll return nil
        guard let data = NSMutableData(length: len) else {
            return nil
        }
        
        // Use sodium's cryptographically secure random byte generator
        randombytes_buf(data.mutableBytesPtr(), data.length)
        
        return data
    }
    
}
