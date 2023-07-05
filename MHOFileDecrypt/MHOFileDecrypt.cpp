#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <format>
#include <vector>
#include <stdexcept>

#include "MHOFileDecrypt.h"
#include "CryXMLB.h"

bool decrypt_mh_file(DecodeFileEntry* file_entry, uint8_t* input_data, uint32_t input_size)
{
    int i; // eax
    int j; // edx
    uint8_t v7; // ch
    uint8_t* data_ptr; // edi
    int data_size; // esi
    uint32_t r_i; // ecx
    int r_data_size; // esi
    int k; // edx
    uint8_t v13; // ah

    if (!input_data)
        return 0;

    if (input_size)
    {
        file_entry->data_ptr = input_data;
        file_entry->data_size = input_size;
        if (input_size > 0)
        {
            while (file_entry->data_size >= 129)
            {
                for (i = 0; i < 64; ++i) {
                    file_entry->computed_decrypt_table[i + 0x41] = file_entry->data_ptr[i] ^ MH_FILE_DECRYPT_TABLE_0[i];
                }
                    
                for (j = 0; i < 129; ++j)
                {
                    v7 = file_entry->data_ptr[i];
                    //if (j >= 65)
                    //    __debugbreak();
                     ++i;
                    file_entry->computed_decrypt_table[j] = v7 ^ MH_FILE_DECRYPT_TABLE_1[j];
                }
                data_ptr = file_entry->data_ptr;
                memcpy(file_entry->data_ptr, file_entry->computed_decrypt_table, 0x81u);
                file_entry->data_ptr += 129;
                file_entry->data_size -= 129;
                if (file_entry->data_size <= 0)
                    return 1;
            }
            data_size = file_entry->data_size;
            r_i = 0;
            if (data_size <= 65)
            {
                do
                {
                    if (r_i >= file_entry->data_size)
                        break;
                    file_entry->computed_decrypt_table[r_i] = file_entry->data_ptr[r_i] ^ MH_FILE_DECRYPT_TABLE_1[r_i];
                    ++r_i;
                } while (r_i < 65);
            }
            else
            {
                r_data_size = data_size - 65;
                if (r_data_size > 0)
                {
                    do
                    {
                        //if (r_i >= 65)
                        //    __debugbreak();
                        file_entry->computed_decrypt_table[r_i + 0x41] = file_entry->data_ptr[r_i] ^ MH_FILE_DECRYPT_TABLE_0[r_i];
                        ++r_i;
                    } while (r_i < r_data_size);
                }
                for (k = 0; r_i < file_entry->data_size; ++k)
                {
                    v13 = file_entry->data_ptr[r_i];
                    //if (k >= 65)
                    //    /_debugbreak();
                    ++r_i;
                    file_entry->computed_decrypt_table[k] = v13 ^ MH_FILE_DECRYPT_TABLE_1[k];
                }
            }
            memcpy(file_entry->data_ptr, file_entry->computed_decrypt_table, file_entry->data_size);
            file_entry->data_ptr += file_entry->data_size;
            file_entry->data_size = 0;
        }
    }
    return 1;
}

std::vector<uint8_t> read_file_contents(const std::string& filepath)
{
    // Open file
    std::ifstream file_stream(filepath, std::ios::binary);
    if (!file_stream)
    {
        throw std::runtime_error(std::format("Failed to open file: {}", filepath));
    }

    // Get file length
    file_stream.seekg(0, file_stream.end);
    uint64_t size = file_stream.tellg();
    file_stream.seekg(0, file_stream.beg);

    // Read data into vector
    std::vector<uint8_t> data;
    data.resize(size);

    file_stream.read(reinterpret_cast<char*>(data.data()), size);
    file_stream.close();

    return data;
}


int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cout << std::format("Usage {} <Encrypted MHO filepath>\n", argv[0]);
        return 1;
    }
    
    // Read file
    std::string filepath = argv[1];
    std::vector<uint8_t> buffer = read_file_contents(filepath);

    // Verify magic header
    if ( buffer.size() < 4 || buffer.data()[0] != 0xFF || buffer.data()[1] != 0xFF || buffer.data()[2] != 0x6D || buffer.data()[3] != 0x68 )
    {
        std::cout << "File is not encrypted! (Expected [0xFF, 0xFF, 0x6D, 0x68] file magic/header)" << std::endl;
    }

    // Remove magic header
    buffer.erase(buffer.begin(), buffer.begin() + 4);

    // Decrypt
    std::cout << "Attempting to decrypt: " << filepath << std::endl;
    DecodeFileEntry decode_file_entry = {0};
    decrypt_mh_file(&decode_file_entry, buffer.data(), buffer.size());

    // Write decrypted file
    std::string decrypted_filepath = filepath + "_decrypted.xml";
    std::ofstream out_file(decrypted_filepath, std::ios::out | std::ios::binary);
    out_file.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    out_file.close();


    if (std::string_view(reinterpret_cast<char*>(buffer.data()), 7) == "CryXmlB")
    {
        std::cout << "Converting CryXML binary to XML (using code from github.com/Bl00drav3n) " << std::endl;
        CryXMLB::convert_file(decrypted_filepath.c_str());
    }

	return 0;
}