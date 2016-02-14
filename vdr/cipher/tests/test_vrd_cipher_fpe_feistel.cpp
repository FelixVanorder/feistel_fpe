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


int test_cipher_fpe_feistel()
{
    {
        constexpr const char rawkey[16] = "SomeKeyRightHer";



        enum { domain_size = 17 };
        vdr::cipher::fpe_feistel fpe_feistel( domain_size, "secret key" );
        
        std::cout << "Encryption:\n";
        for( auto i = 0; i < domain_size; ++i )
        {
            std::cerr << std::setw(2) << i << " -> " << std::setw(2) << fpe_feistel.encrypt(i) << "\n";
        }

        std::cout << "Decryption:\n";
        for( auto i = 0; i < domain_size; ++i )
        {
            std::cerr << std::setw(2) << i << " -> " << std::setw(2) << fpe_feistel.decrypt(i) << "\n";
        }
        std::cerr << std::flush;

        for( auto i = 0; i < domain_size; ++i )
        {
            auto const enc_i = fpe_feistel.encrypt( i );
            auto const dec_enc_i = fpe_feistel.decrypt( enc_i );
            if( i != dec_enc_i )
            {
                std::cout << "error:\n"
                    <<     i << " -enc-> " << enc_i << "\n"
                    << enc_i << " -dec-> " << dec_enc_i << "\n"
                    << std::flush;
                return 1;
            }
        }

    }

    return 0;
}




int main( int ac, char *av[] )
{
    return test_cipher_fpe_feistel();
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
