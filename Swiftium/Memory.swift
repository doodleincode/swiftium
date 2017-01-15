//
//  Memory.swift
//  Swiftium
//
//  Created by dman on 1/2/17.
//  Copyright © 2017 Daniel Hong. All rights reserved.
//

import Foundation

public class Memory {
    
    //
    // Secure zero memory
    //
    // - Parameter data: NSMutableData to zero
    //
    public func zero(data: NSMutableData) {
        // Clear the memory
        sodium_memzero(data.mutableBytesPtr(), data.length)
    }
    
    //
    // Checks if the given data contains all zeros
    //
    // - Parameter data: The data to check
    //
    // - Returns: True if the data contains all zeros, false otherwise
    //
    public func isZero(data: NSData) -> Bool {
        return sodium_is_zero(data.bytesPtr(), data.length) == 1
    }
    
}
