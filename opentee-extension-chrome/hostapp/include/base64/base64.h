#include <string>

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);
bool is_str_base64(std::string const& check_string);

