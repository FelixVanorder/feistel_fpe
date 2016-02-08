#include <iostream>

#include <array>
#include <tuple>
#include <cstdint>

#include <string>

#include "vdr/byte.h"
#include "vdr/cipher/aes.h"

// TODO: Make a good test suite. Not this hack.


std::string tohex( gsl::span< gsl::byte const > data );
std::string tohex( std::string const & data );


void test_cipher_aes()
{
    {
        constexpr const char rawkey[16] = "SomeKeyRightHer";

        vdr::cipher::aes128 aes;
        aes.set_enc_key( gsl::as_bytes( gsl::as_span( rawkey ) ) );

        auto in = aes.get_empty_block();
        auto out = aes.get_empty_block(); 

        aes.enc( in, out );
        std::cerr   << "enc in : " << tohex(in) << "\n"
                    << "enc out: " << tohex(out) << "\n"
                    << std::endl;

        in = out;

        aes.set_dec_key( gsl::as_bytes( gsl::as_span(rawkey) ) );

        aes.dec( in, out );
        std::cerr   << "dec in : " << tohex(in) << "\n"
                    << "dec out: " << tohex(out) << "\n"
                    << std::endl;

        if( out != decltype(out)() )
        {
            std::cerr << "mismatch, error." << std::endl;
        }
        else
        {
            std::cerr << "ok" << std::endl;
        }
    }

}




int main( int ac, char *av[] )
{
    test_cipher_aes();
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
