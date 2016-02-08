#include <iostream>
#include <iomanip>

#include <array>
#include <tuple>
#include <cstdint>

#include <string>

#include "vdr/byte.h"
#include "vdr/cipher/fpe_feistel.h"

// TODO: Make a good test suite. Not this hack.


std::string tohex( gsl::span< gsl::byte const > data );
std::string tohex( std::string const & data );


void test_cipher_fpe_feistel()
{
    {
        constexpr const char rawkey[16] = "SomeKeyRightHer";



        enum { domain_size = 17 };
        vdr::cipher::thorp_feistel_cipher_t feistel( domain_size, "secret key" );
        
        std::cout << "Encryption:\n";
        for( auto i = 0; i < domain_size; ++i )
        {
            std::cout << std::setw(2) << i << " -> " << std::setw(2) << feistel.encrypt(i) << "\n";
        }

        std::cout << "Decryption:\n";
        for( auto i = 0; i < domain_size; ++i )
        {
            std::cout << std::setw(2) << i << " -> " << std::setw(2) << feistel.decrypt(i) << "\n";
        }
        std::cout << std::flush;

    }

}




int main( int ac, char *av[] )
{
    test_cipher_fpe_feistel();
    return 0;
}


std::string vec_to_quoted_str( std::vector< std::string > const & vec )
{
    std::string result;

    for( auto const & str : vec )
    {
        result += "\"";
        result += str;
        result += "\", ";
    }
    if( not result.empty() )
    {
        result.resize( result.size() - std::strlen(", ") );
    }

    return result;
}



std::string tohex( gsl::span< gsl::byte const > data )
{
    std::string result;
    result.reserve( data.size_bytes() * 2 );

    static constexpr char hexes[] = "0123456789abcdef";

    for( auto const rawbyte : data )
    {
        uint8_t byte = static_cast< uint8_t >( rawbyte );
        result += hexes[ byte >> 4  ];
        result += hexes[ byte & 0xf ];
    }

    return result;
}



std::string tohex( std::string const & data )
{
    return tohex( gsl::as_bytes( gsl::as_span( data ) ) );
}
