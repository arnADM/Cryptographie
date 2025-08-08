#!/usr/bin/python
# -*- coding: utf-8 -*-

# This is a pure python implementation of the DES encryption algorithm.
# It's probably not very fast (I haven't tested it) but it should be correct.
#
# Algorithm taken from: http://www.itl.nist.gov/fipspubs/fip46-2.htm
#
# Usage example:
# from pyDes import *
# 
# data = "Please encrypt my data"
# k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
# d = k.encrypt(data)
# print "Encrypted: %r" % d
# print "Decrypted: %r" % k.decrypt(d)
# assert k.decrypt(d, padmode=PAD_PKCS5) == data
#
# Author: Todd Whiteman
# Date: 16th March, 2010
# Version 1.4.1
# License: Public Domain
#

# Import the needed modules.
import sys

# The base class shared by des and triple des.
class _baseDes(object):
    def __init__(self, mode = 0, IV = None, pad = None, padmode = 0):
        """_baseDes(mode, IV, pad, padmode) -> _baseDes Object"""
        
        if IV:
            IV = self._guardAgainstUnicode(IV)
        if pad:
            pad = self._guardAgainstUnicode(pad)
        
        self.block_size = 8
        # Set the type of des encryption (see constants above)
        self._mode = mode
        # The initialization vector
        self._iv = IV
        # The padding character to use
        self._padding = pad
        # The padding mode (see constants above)
        self._padmode = padmode
        # Current IV for chaining
        self._currentIV = IV
    
    def __str__(self):
        return "<%s obj instance at %x>" % (self.__class__.__name__, id(self))
    
    def __repr__(self):
        return "<%s obj instance at %x>" % (self.__class__.__name__, id(self))
    
    def _guardAgainstUnicode(self, data):
        """Guard against unicode data"""
        if hasattr(data, 'decode'):
            data = data
        else:
            if isinstance(data, str):
                data = data.encode('latin-1')
        return data
    
    def encrypt(self, data, pad=None, padmode=None):
        """encrypt(data, [pad], [padmode]) -> string
        
        data : data to be encrypted
        pad  : pad character for the PAD_NORMAL mode
        padmode : optional override for the padding mode
        """
        data = self._guardAgainstUnicode(data)
        
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        
        # Set the padding mode
        if padmode is None:
            padmode = self._padmode
        
        if padmode and (len(data) % self.block_size != 0):
            if padmode == PAD_PKCS5:
                data += self._padWithPKCS5(data)
        elif padmode and (len(data) % self.block_size == 0):
            if padmode == PAD_PKCS5:
                data += self._padWithPKCS5(data)
        
        if len(data) % self.block_size != 0:
            if not padmode:
                if pad is None:
                    pad = self._padding
                data += (self.block_size - (len(data) % self.block_size)) * pad
        
        # Initialize the current IV
        self._currentIV = self._iv
        
        # Encrypt the data as a string
        if self._mode == ECB:
            return self._crypt(data, ENCRYPT)
        else:
            return self._cbcCrypt(data, ENCRYPT)
    
    def decrypt(self, data, pad=None, padmode=None):
        """decrypt(data, [pad], [padmode]) -> string
        
        data : data to be decrypted
        pad  : pad character for the PAD_NORMAL mode
        padmode : optional override for the padding mode
        """
        data = self._guardAgainstUnicode(data)
        
        if pad is not None:
            pad = self._guardAgainstUnicode(pad)
        
        # Set the padding mode
        if padmode is None:
            padmode = self._padmode
        
        # Initialize the current IV
        self._currentIV = self._iv
        
        # Decrypt the data as a string
        if self._mode == ECB:
            decrypted = self._crypt(data, DECRYPT)
        else:
            decrypted = self._cbcCrypt(data, DECRYPT)
        
        # Remove the padding
        if padmode and padmode == PAD_PKCS5:
            decrypted = self._removePadding(decrypted, padmode)
        elif padmode and pad is None:
            pad = self._padding
        
        if pad is not None:
            decrypted = decrypted.rstrip(pad)
        
        return decrypted
    
    def _padWithPKCS5(self, data):
        """Pad data according to PKCS#5"""
        pad_len = 8 - (len(data) % 8)
        return bytes([pad_len] * pad_len)
    
    def _removePadding(self, data, padmode):
        """Remove the padding from data"""
        if padmode == PAD_PKCS5:
            pad_len = data[-1]
            return data[:-pad_len]
        return data
    
    def _cbcCrypt(self, data, crypt_type):
        """Perform CBC encryption/decryption"""
        if not self._iv:
            self._iv = '\0' * 8
        
        processed = b''
        self._currentIV = self._iv
        
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            
            if crypt_type == ENCRYPT:
                # XOR with previous cipher block (or IV for first block)
                block = self._xor(block, self._currentIV)
                block = self._crypt(block, ENCRYPT)
                self._currentIV = block
            else:
                # For decryption
                temp = block
                block = self._crypt(block, DECRYPT)
                block = self._xor(block, self._currentIV)
                self._currentIV = temp
            
            processed += block
        
        return processed
    
    def _xor(self, a, b):
        """XOR two byte strings"""
        result = b''
        for i in range(len(a)):
            result += bytes([a[i] ^ b[i]])
        return result

# Constants for DES modes
ECB = 0
CBC = 1

# Constants for encryption/decryption
ENCRYPT = 0
DECRYPT = 1

# Constants for padding modes
PAD_NORMAL = 1
PAD_PKCS5 = 2

class des(_baseDes):
    """DES encryption/decryption class
    
    Modes:
    des(key, [mode], [IV])
    
    key  -> Bytes containing the encryption key, must be exactly 8 bytes
    mode -> Either ECB or CBC mode
    IV   -> Initial Value bytes, must be exactly 8 bytes (used for CBC mode)
    """
    
    # DES S-boxes
    __s = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    
    # Permutation tables
    __ip = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]
    
    __fp = [40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25]
    
    __pc1 = [57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19, 11, 3, 60, 52, 44, 36,
             63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4]
    
    __shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    __pc2 = [14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
             23, 19, 12, 4, 26, 8,
             16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55,
             30, 40, 51, 45, 33, 48,
             44, 49, 39, 56, 34, 53,
             46, 42, 50, 36, 29, 32]
    
    __exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
               6, 7, 8, 9, 8, 9, 10, 11,
               12, 13, 12, 13, 14, 15, 16, 17,
               16, 17, 18, 19, 20, 21, 20, 21,
               22, 23, 24, 25, 24, 25, 26, 27,
               28, 29, 28, 29, 30, 31, 32, 1]
    
    __p = [16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25]
    
    def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_PKCS5):
        if len(key) != 8:
            raise ValueError("Invalid DES key size. Must be exactly 8 bytes")
        
        _baseDes.__init__(self, mode, IV, pad, padmode)
        self.key_size = 8
        
        self.L = []
        self.R = []
        self.Kn = [ [0] * 48 ] * 16
        self.final = []
        
        self.setKey(key)
    
    def setKey(self, key):
        """Will set the crypting key for this object"""
        key = self._guardAgainstUnicode(key)
        self.__create_sub_keys(key)
    
    def __create_sub_keys(self, key):
        """Create the 16 subkeys K[1] to K[16] from the given key"""
        key = self.__permutate(self.__pc1, self.__string_to_bitlist(key))
        i = 0
        # Split into Left and Right halves
        self.L = key[:28]
        self.R = key[28:]
        while i < 16:
            j = 0
            # Perform circular left shifts
            while j < self.__shifts[i]:
                self.L.append(self.L[0])
                del self.L[0]
                
                self.R.append(self.R[0])
                del self.R[0]
                
                j += 1
                
            # Create one of the 16 subkeys through pc2 permutation
            self.Kn[i] = self.__permutate(self.__pc2, self.L + self.R)
            
            i += 1
    
    def __string_to_bitlist(self, data):
        """Turn the given string into a list of bits (1, 0)"""
        if hasattr(data, 'decode'):
            data = [c for c in data]
        else:
            data = [c for c in data]
        l = len(data) * 8
        result = [0] * l
        pos = 0
        for ch in data:
            if isinstance(ch, str):
                i = ord(ch)
            else:
                i = ch
            for j in range(8):
                if (i >> (7-j)) & 0x01:
                    result[pos] = 1
                pos += 1
        return result
    
    def __bitlist_to_string(self, data):
        """Turn the given list of bits into a string"""
        result = b''
        pos = 0
        c = 0
        while pos < len(data):
            c += data[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result += bytes([c])
                c = 0
            pos += 1
        return result
    
    def __permutate(self, table, block):
        """Permutate this block with the specified table"""
        return list(map(lambda x: block[x-1], table))
    
    def __des_crypt(self, block, crypt_type):
        """Crypt the given block using DES"""
        block = self.__permutate(self.__ip, block)
        self.L = block[:32]
        self.R = block[32:]
        
        # Encryption starts from Kn[1] through to Kn[16]
        if crypt_type == ENCRYPT:
            iteration = 0
            iteration_adjustment = 1
        else:
            iteration = 15
            iteration_adjustment = -1
        
        i = 0
        while i < 16:
            # Make a copy of R[i-1], this will later become L[i]
            tempR = self.R[:]
            
            # Permutate R[i-1] to start creating f(R[i-1], K[i])
            self.R = self.__permutate(self.__exp_d, self.R)
            
            # Exclusive or R[i-1] with K[i]
            self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
            
            # Split R[i-1] into 8 groups of 6 bits each.
            B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], 
                 self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]
            
            # Apply S-box substitution
            j = 0
            Bn = [0] * 32
            pos = 0
            while j < 8:
                # Work out the offsets
                m = (B[j][0] << 1) + B[j][5]
                n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]
                
                # Find the permutation value
                v = self.__s[j][(m << 4) + n]
                
                # Turn value into bits, add it to result: Bn
                Bn[pos] = (v & 8) >> 3
                Bn[pos + 1] = (v & 4) >> 2
                Bn[pos + 2] = (v & 2) >> 1
                Bn[pos + 3] = v & 1
                
                pos += 4
                j += 1
            
            # Permutate the concatination of B[1] to B[8] (Bn)
            self.R = self.__permutate(self.__p, Bn)
            
            # Xor with L[i-1]
            self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
            
            # L[i] becomes R[i-1]
            self.L = tempR
            
            i += 1
            iteration += iteration_adjustment
        
        # Final permutation of R[16]L[16]
        self.final = self.__permutate(self.__fp, self.R + self.L)
        return self.__bitlist_to_string(self.final)
    
    def _crypt(self, data, crypt_type):
        """Crypt the data in blocks, running it through des_crypt()"""
        # Split the data into list of 8 byte strings
        if not data:
            return b''
        
        if len(data) % self.block_size != 0:
            if crypt_type == DECRYPT:
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
            if not self._padding:
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * self._padding
        
        # Split the data into blocks, crypting each one separately
        result = b''
        for i in range(0, len(data), self.block_size):
            block = data[i:i+self.block_size]
            processed_block = self.__des_crypt(self.__string_to_bitlist(block), crypt_type)
            result += processed_block
        
        return result
