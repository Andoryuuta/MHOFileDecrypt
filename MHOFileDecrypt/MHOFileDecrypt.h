﻿#pragma once

#include <cstdint>

struct DecodeFileEntry
{
    uint8_t* data_ptr;
    uint32_t data_size;
    uint8_t computed_decrypt_table[129];
};


uint8_t MH_FILE_DECRYPT_TABLE_0[65] = {
    0x09, 0x40, 0x48, 0x19, 0xC1, 0x8F, 0x83, 0xF5, 0x60, 0x09, 0x6F, 0x14, 0x0F, 0xBE, 0x51, 0xEA,
    0x7A, 0x81, 0x08, 0xB4, 0x76, 0xB6, 0x1A, 0x91, 0x5A, 0x74, 0x70, 0xC9, 0xDD, 0x83, 0xE5, 0x04,
    0x9F, 0x48, 0xC8, 0x48, 0xA0, 0x9E, 0x9B, 0x8F, 0x8B, 0x0F, 0x9C, 0x01, 0x94, 0x34, 0x62, 0x29,
    0x99, 0xB7, 0xDC, 0x77, 0xFC, 0x87, 0xB2, 0x39, 0xFB, 0x8F, 0x6D, 0xD6, 0x51, 0x97, 0x6C, 0xD8,

    // Original code seems to be off by 1 byte.
    0x91
};

uint8_t MH_FILE_DECRYPT_TABLE_1[65] = {
    0xC7, 0xAB, 0x19, 0x5A, 0x77, 0x88, 0xFA, 0x21, 0xAB, 0x5D, 0x7D, 0x33,	0xAA, 0x3A, 0x75, 0x0A,
    0xF9, 0x7C, 0x76, 0xB6, 0x6A, 0xE3, 0x05, 0xD5, 0x77, 0xCF, 0xF2, 0xFB, 0x2D, 0xB2, 0x1B, 0x29,
    0x17, 0x50, 0x04, 0xDA, 0x4A, 0xC7, 0x8C, 0x31, 0x4A, 0x51, 0xA8, 0x3B, 0x9E, 0xE5, 0xDE, 0x4B,
    0x75, 0x7C, 0x47, 0x54, 0xFB, 0x03, 0x24, 0xA6, 0x13, 0x4A, 0xCB, 0xE9, 0x5E, 0x34, 0xE1, 0xA1,

    // Original code seems to be off by 1 byte.
    0x80
};