#include <iostream>

#include <array>
#include <tuple>
#include <cstdint>

#include <string>

#include "vdr/byte.h"
#include "vdr/hash/sha2.h"
#include "vdr/mac/hmac.h"

// TODO: refine it at least to level of vrd::hash:sha256 test.


std::string tohex( gsl::span< gsl::byte const > data );
std::string tohex( std::string const & data );



void test_hmac_sha256()
{
    {
        const std::string key = "";
        const std::string data = "";


        vdr::mac::hmac<vdr::hash::sha256>::digest_arr expected {
                gsl::byte(0xb6), gsl::byte(0x13), gsl::byte(0x67), gsl::byte(0x9a), 
                gsl::byte(0x08), gsl::byte(0x14), gsl::byte(0xd9), gsl::byte(0xec), 
                gsl::byte(0x77), gsl::byte(0x2f), gsl::byte(0x95), gsl::byte(0xd7), 
                gsl::byte(0x78), gsl::byte(0xc3), gsl::byte(0x5f), gsl::byte(0xc5),
                gsl::byte(0xff), gsl::byte(0x16), gsl::byte(0x97), gsl::byte(0xc4), 
                gsl::byte(0x93), gsl::byte(0x71), gsl::byte(0x56), gsl::byte(0x53), 
                gsl::byte(0xc6), gsl::byte(0xc7), gsl::byte(0x12), gsl::byte(0x14), 
                gsl::byte(0x42), gsl::byte(0x92), gsl::byte(0xc5), gsl::byte(0xad),
            };


        vdr::mac::hmac<vdr::hash::sha256> hmac( gsl::as_bytes( gsl::as_span( key ) ) );
        auto actual = hmac.get_empty_digest();
        hmac << gsl::as_bytes( gsl::as_span( data ) ) >> actual;


        if( expected != actual )
        {
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " fail test on key \"" << key << "\" and data \"" << data << "\"" << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " expected: " << tohex( expected ) << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << "   actual: " << tohex( actual ) << "\n";
            exit(1);
        }
        else
        {
            std::cerr << "ok" << std::endl;
        }
    }

    {

        const std::string key = "key";
        const std::string data = "The quick brown fox jumps over the lazy dog";

        vdr::mac::hmac<vdr::hash::sha256>::digest_arr expected {
            gsl::byte(0xf7), gsl::byte(0xbc), gsl::byte(0x83), gsl::byte(0xf4), 
            gsl::byte(0x30), gsl::byte(0x53), gsl::byte(0x84), gsl::byte(0x24), 
            gsl::byte(0xb1), gsl::byte(0x32), gsl::byte(0x98), gsl::byte(0xe6), 
            gsl::byte(0xaa), gsl::byte(0x6f), gsl::byte(0xb1), gsl::byte(0x43),
            gsl::byte(0xef), gsl::byte(0x4d), gsl::byte(0x59), gsl::byte(0xa1), 
            gsl::byte(0x49), gsl::byte(0x46), gsl::byte(0x17), gsl::byte(0x59), 
            gsl::byte(0x97), gsl::byte(0x47), gsl::byte(0x9d), gsl::byte(0xbc), 
            gsl::byte(0x2d), gsl::byte(0x1a), gsl::byte(0x3c), gsl::byte(0xd8),
        };

        vdr::mac::hmac<vdr::hash::sha256> hmac( gsl::as_bytes( gsl::as_span( key ) ) );
        auto actual = hmac.get_empty_digest();
        hmac << gsl::as_bytes( gsl::as_span( data ) ) >> actual;

        if( expected != actual )
        {
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " fail test on key \"" << key << "\" and data \"" << data << "\"" << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " expected: " << tohex( expected ) << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << "   actual: " << tohex( actual ) << "\n";
            exit(1);
        }
        else
        {
            std::cerr << "ok" << std::endl;
        }
    }

    {

        const std::string key( vdr::mac::hmac<vdr::hash::sha256>::block_size_bytes() * 3, 'H');
        const std::string data = "The quick brown fox jumps over the lazy dog";

        vdr::mac::hmac<vdr::hash::sha256>::digest_arr expected {
            gsl::byte(0x46), gsl::byte(0x1e), gsl::byte(0xbe), gsl::byte(0x05), 
            gsl::byte(0xad), gsl::byte(0x4c), gsl::byte(0x21), gsl::byte(0xe4), 
            gsl::byte(0x7f), gsl::byte(0x82), gsl::byte(0x97), gsl::byte(0x77), 
            gsl::byte(0x5a), gsl::byte(0x01), gsl::byte(0x68), gsl::byte(0x29),
            gsl::byte(0x58), gsl::byte(0x09), gsl::byte(0x27), gsl::byte(0x11), 
            gsl::byte(0xa0), gsl::byte(0xed), gsl::byte(0x91), gsl::byte(0x18), 
            gsl::byte(0x65), gsl::byte(0x7c), gsl::byte(0x43), gsl::byte(0x32), 
            gsl::byte(0x1b), gsl::byte(0xaa), gsl::byte(0x7f), gsl::byte(0xc7),
        };


        vdr::mac::hmac<vdr::hash::sha256> hmac( gsl::as_bytes( gsl::as_span( key ) ) );
        auto actual = hmac.get_empty_digest();
        hmac << gsl::as_bytes( gsl::as_span( data ) ) >> actual;

        if( expected != actual )
        {
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " fail test on key \"" << key << "\" and data \"" << data << "\"" << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " expected: " << tohex( expected ) << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << "   actual: " << tohex( actual ) << "\n";
            exit(1);
        }
        else
        {
            std::cerr << "ok" << std::endl;
        }
    }


}




int main( int ac, char *av[] )
{
    test_hmac_sha256();
    return 0;
}

std::ostream & print_error_details( 
        std::ostream & ostrm,
        std::string const & input,
        vdr::hash::sha256::digest_arr const & expected,
        vdr::hash::sha256::digest_arr const & produced 
    )
{
    return ostrm 
        << "error for input: \"" << input << "\"\n"
        << "expected: " << tohex( expected ) << "\n"
        << "produced: " << tohex( produced ) << "\n"
    ;
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

std::ostream & print_error_details( 
        std::ostream & ostrm,
        std::vector< std::string > const & inputs,
        vdr::hash::sha256::digest_arr const & expected,
        vdr::hash::sha256::digest_arr const & produced 
    )
{
    return ostrm 
        << "error for input: " << vec_to_quoted_str( inputs ) << "\n"
        << "expected: " << tohex( expected ) << "\n"
        << "produced: " << tohex( produced ) << "\n"
    ;
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
