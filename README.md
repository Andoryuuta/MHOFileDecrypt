# MHOFileDecrypt
A makeshift tool for decrypting specific encrypted files from MHO IFS.
( **Must have [0xFF, 0xFF, 0x6D, 0x68] file magic/header** )

If the decrypted file is a CryGame Binary XML file, it is automatically converted to a regular text XML (using the existing CryXMLB repo - see credits)

## Usage
`MHOFileDecrypt.exe <encrypted file path>`

## Credit
This tool includes a slightly modified copy of https://github.com/Bl00drav3n/CryXmlB for converting binary XML files to regular XML.
