//
//  NSData+Extensions.swift
//  Swiftium
//
//  Created by dman on 1/2/17.
//  Copyright © 2017 Daniel Hong. All rights reserved.
//

import Foundation

public extension NSData {
    func bytesPtr<T>() -> UnsafePointer<T> {
        let rawBytes = self.bytes
        return rawBytes.assumingMemoryBound(to: T.self);
    }
}

public extension NSMutableData {
    func mutableBytesPtr<T>() -> UnsafeMutablePointer<T> {
        let rawBytes = self.mutableBytes
        return rawBytes.assumingMemoryBound(to: T.self)
    }
}
