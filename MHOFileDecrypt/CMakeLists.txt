# CMakeList.txt : CMake project for MHOFileDecrypt, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (MHOFileDecrypt "MHOFileDecrypt.cpp" "MHOFileDecrypt.h" "CryXMLB.cpp" "tinyxml2.cpp" "CryXMLB.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET MHOFileDecrypt PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
