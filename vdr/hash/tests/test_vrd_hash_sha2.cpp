#include <iostream>

#include <array>
#include <tuple>
#include <cstdint>

#include <string>

#include "vdr/byte.h"
#include "vdr/hash/sha2.h"

// TODO: test for fail cases
// TODO: print length of input for check which borders we checking.


typedef std::pair< std::vector< std::string >, vdr::hash::sha256::digest_arr > inputs_n_digest_t;

std::vector< inputs_n_digest_t > const & get_inputs_n_digests();

std::string tohex( gsl::span< gsl::byte const > data );
std::string tohex( std::string const & data );

void test_empty_input();
void test_static_fuzzy_inputs();




int main( int ac, char *av[] )
{
    test_empty_input();
    test_static_fuzzy_inputs();
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

void test_empty_input()
{
    vdr::hash::sha256::digest_arr digest_of_empty {
            gsl::byte(0xe3), gsl::byte(0xb0), gsl::byte(0xc4), gsl::byte(0x42),
            gsl::byte(0x98), gsl::byte(0xfc), gsl::byte(0x1c), gsl::byte(0x14), 
            gsl::byte(0x9a), gsl::byte(0xfb), gsl::byte(0xf4), gsl::byte(0xc8),
            gsl::byte(0x99), gsl::byte(0x6f), gsl::byte(0xb9), gsl::byte(0x24), 
            gsl::byte(0x27), gsl::byte(0xae), gsl::byte(0x41), gsl::byte(0xe4),
            gsl::byte(0x64), gsl::byte(0x9b), gsl::byte(0x93), gsl::byte(0x4c), 
            gsl::byte(0xa4), gsl::byte(0x95), gsl::byte(0x99), gsl::byte(0x1b),
            gsl::byte(0x78), gsl::byte(0x52), gsl::byte(0xb8), gsl::byte(0x55),
        };


    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 >> gsl::as_writeable_bytes( gsl::as_span( digest ) );

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "default constructed sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "default constructed sha256 - ok" << std::endl;
        }
    }

    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 >> gsl::as_writeable_bytes( gsl::as_span( digest ) );
        sha256 >> gsl::as_writeable_bytes( gsl::as_span( digest ) );

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "default constructed, double output sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "default constructed, double output sha256 - ok" << std::endl;
        }
    }

    
    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 
            << gsl::as_bytes( gsl::ensure_z("") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "empty feeded sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "empty feeded sha256 - ok" << std::endl;
        }
    }
    
    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 
            << gsl::as_bytes( gsl::ensure_z("nonempty") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) );

        sha256
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "just after feeded sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "just after feeded sha256 - ok" << std::endl;
        }
    }
    
    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 
            << gsl::as_bytes( gsl::ensure_z("nonempty") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) );

        sha256 >> gsl::as_writeable_bytes( gsl::as_span( digest ) );
        sha256 >> gsl::as_writeable_bytes( gsl::as_span( digest ) );

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "just after feeded, double output sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "just after feeded, double output sha256 - ok" << std::endl;
        }
    }


    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 
            << gsl::as_bytes( gsl::ensure_z("nonempty") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;
        sha256
            << gsl::as_bytes( gsl::ensure_z("") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "after feeded, empty feed sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "after feeded, empty feed sha256 - ok" << std::endl;
        }
    }


    {
        vdr::hash::sha256 sha256;
        vdr::hash::sha256::digest_arr digest = {};

        sha256 
            << gsl::as_bytes( gsl::ensure_z("nonempty") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;
        sha256
            << gsl::as_bytes( gsl::ensure_z("") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;
        sha256
            << gsl::as_bytes( gsl::ensure_z("") )
            >> gsl::as_writeable_bytes( gsl::as_span( digest ) )
            ;

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(digest_of_empty) ) )
        {
            std::cerr << "after feeded, double empty feed sha256 - error\n";
            print_error_details( std::cerr, "", digest_of_empty, digest ) << std::endl;
        }
        else
        {
            std::cerr << "after feeded, double empty feed sha256 - ok" << std::endl;
        }
    }
}


void test_static_fuzzy_inputs()
{
    vdr::hash::sha256 sha256;

    auto const & inputs_n_digests = get_inputs_n_digests();

    for( auto const & inputs_n_digest : inputs_n_digests )
    {
        auto const & inputs = inputs_n_digest.first;
        auto const & expected = inputs_n_digest.second;

        vdr::hash::sha256::digest_arr digest;

        for( auto const & input : inputs )
        {
            sha256 << gsl::as_bytes( gsl::as_span( input ) );
        }

        sha256 >> gsl::as_writeable_bytes( gsl::as_span( digest ) );

        if( not std::equal( std::begin(digest), std::end(digest), std::begin(expected) ) )
        {
            print_error_details( std::cerr, inputs, expected, digest ) << std::endl;
        }
        else
        {
            std::cerr << "fuzzy test ok for input: " << vec_to_quoted_str( inputs ) << std::endl;
        }
    }
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


std::vector< inputs_n_digest_t > const & get_inputs_n_digests()
{
    static const auto inputs_n_digests = std::vector< inputs_n_digest_t > { 
        inputs_n_digest_t{ { std::string("a") }, 
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xca), gsl::byte(0x97), gsl::byte(0x81), gsl::byte(0x12), 
                gsl::byte(0xca), gsl::byte(0x1b), gsl::byte(0xbd), gsl::byte(0xca), 
                gsl::byte(0xfa), gsl::byte(0xc2), gsl::byte(0x31), gsl::byte(0xb3), 
                gsl::byte(0x9a), gsl::byte(0x23), gsl::byte(0xdc), gsl::byte(0x4d), 
                gsl::byte(0xa7), gsl::byte(0x86), gsl::byte(0xef), gsl::byte(0xf8), 
                gsl::byte(0x14), gsl::byte(0x7c), gsl::byte(0x4e), gsl::byte(0x72), 
                gsl::byte(0xb9), gsl::byte(0x80), gsl::byte(0x77), gsl::byte(0x85), 
                gsl::byte(0xaf), gsl::byte(0xee), gsl::byte(0x48), gsl::byte(0xbb), 
            }
        },
        inputs_n_digest_t{ { std::string("b") }, 
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x3e), gsl::byte(0x23), gsl::byte(0xe8), gsl::byte(0x16), 
                gsl::byte(0x00), gsl::byte(0x39), gsl::byte(0x59), gsl::byte(0x4a), 
                gsl::byte(0x33), gsl::byte(0x89), gsl::byte(0x4f), gsl::byte(0x65), 
                gsl::byte(0x64), gsl::byte(0xe1), gsl::byte(0xb1), gsl::byte(0x34), 
                gsl::byte(0x8b), gsl::byte(0xbd), gsl::byte(0x7a), gsl::byte(0x00), 
                gsl::byte(0x88), gsl::byte(0xd4), gsl::byte(0x2c), gsl::byte(0x4a), 
                gsl::byte(0xcb), gsl::byte(0x73), gsl::byte(0xee), gsl::byte(0xae), 
                gsl::byte(0xd5), gsl::byte(0x9c), gsl::byte(0x00), gsl::byte(0x9d),
            }
        },
        inputs_n_digest_t{ { std::string(), std::string("b") }, 
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x3e), gsl::byte(0x23), gsl::byte(0xe8), gsl::byte(0x16), 
                gsl::byte(0x00), gsl::byte(0x39), gsl::byte(0x59), gsl::byte(0x4a), 
                gsl::byte(0x33), gsl::byte(0x89), gsl::byte(0x4f), gsl::byte(0x65), 
                gsl::byte(0x64), gsl::byte(0xe1), gsl::byte(0xb1), gsl::byte(0x34), 
                gsl::byte(0x8b), gsl::byte(0xbd), gsl::byte(0x7a), gsl::byte(0x00), 
                gsl::byte(0x88), gsl::byte(0xd4), gsl::byte(0x2c), gsl::byte(0x4a), 
                gsl::byte(0xcb), gsl::byte(0x73), gsl::byte(0xee), gsl::byte(0xae), 
                gsl::byte(0xd5), gsl::byte(0x9c), gsl::byte(0x00), gsl::byte(0x9d),
            }
        },
        inputs_n_digest_t{ { std::string(), std::string("b"), std::string() }, 
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x3e), gsl::byte(0x23), gsl::byte(0xe8), gsl::byte(0x16), 
                gsl::byte(0x00), gsl::byte(0x39), gsl::byte(0x59), gsl::byte(0x4a), 
                gsl::byte(0x33), gsl::byte(0x89), gsl::byte(0x4f), gsl::byte(0x65), 
                gsl::byte(0x64), gsl::byte(0xe1), gsl::byte(0xb1), gsl::byte(0x34), 
                gsl::byte(0x8b), gsl::byte(0xbd), gsl::byte(0x7a), gsl::byte(0x00), 
                gsl::byte(0x88), gsl::byte(0xd4), gsl::byte(0x2c), gsl::byte(0x4a), 
                gsl::byte(0xcb), gsl::byte(0x73), gsl::byte(0xee), gsl::byte(0xae), 
                gsl::byte(0xd5), gsl::byte(0x9c), gsl::byte(0x00), gsl::byte(0x9d),
            }
        },
        inputs_n_digest_t{ { std::string(), std::string("b"), std::string(), std::string() }, 
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x3e), gsl::byte(0x23), gsl::byte(0xe8), gsl::byte(0x16), 
                gsl::byte(0x00), gsl::byte(0x39), gsl::byte(0x59), gsl::byte(0x4a), 
                gsl::byte(0x33), gsl::byte(0x89), gsl::byte(0x4f), gsl::byte(0x65), 
                gsl::byte(0x64), gsl::byte(0xe1), gsl::byte(0xb1), gsl::byte(0x34), 
                gsl::byte(0x8b), gsl::byte(0xbd), gsl::byte(0x7a), gsl::byte(0x00), 
                gsl::byte(0x88), gsl::byte(0xd4), gsl::byte(0x2c), gsl::byte(0x4a), 
                gsl::byte(0xcb), gsl::byte(0x73), gsl::byte(0xee), gsl::byte(0xae), 
                gsl::byte(0xd5), gsl::byte(0x9c), gsl::byte(0x00), gsl::byte(0x9d),
            }
        },
        inputs_n_digest_t{ { "QWllWEoMg+u/+5/1G1CJs4bOe4YNfwO" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x77), gsl::byte(0x6e), gsl::byte(0x7c), gsl::byte(0x41), 
                gsl::byte(0xa4), gsl::byte(0x37), gsl::byte(0xd3), gsl::byte(0xc8), 
                gsl::byte(0x8c), gsl::byte(0x6c), gsl::byte(0x6e), gsl::byte(0x7c), 
                gsl::byte(0x47), gsl::byte(0x77), gsl::byte(0xcd), gsl::byte(0x03), 
                gsl::byte(0xe5), gsl::byte(0x57), gsl::byte(0x38), gsl::byte(0x3d), 
                gsl::byte(0xd3), gsl::byte(0xe3), gsl::byte(0x9b), gsl::byte(0xe4), 
                gsl::byte(0x82), gsl::byte(0x04), gsl::byte(0x66), gsl::byte(0xdc), 
                gsl::byte(0x45), gsl::byte(0x7f), gsl::byte(0x88), gsl::byte(0x6c), 
            }
        },
        inputs_n_digest_t{ { "3d5AVE1M", "hDLyznXHh0lnUjSYg6", "l5R7U" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xca), gsl::byte(0xf1), gsl::byte(0xd9), gsl::byte(0x58), 
                gsl::byte(0x93), gsl::byte(0xcb), gsl::byte(0x6a), gsl::byte(0x5a), 
                gsl::byte(0x4a), gsl::byte(0x50), gsl::byte(0xe4), gsl::byte(0xa3), 
                gsl::byte(0xdf), gsl::byte(0x46), gsl::byte(0xd3), gsl::byte(0xa1), 
                gsl::byte(0x73), gsl::byte(0xb0), gsl::byte(0x72), gsl::byte(0x9d), 
                gsl::byte(0x46), gsl::byte(0xa3), gsl::byte(0xbf), gsl::byte(0x61), 
                gsl::byte(0x86), gsl::byte(0x14), gsl::byte(0xaa), gsl::byte(0xb1), 
                gsl::byte(0x5a), gsl::byte(0xff), gsl::byte(0xbf), gsl::byte(0x80),
            }
        },
        inputs_n_digest_t{ { 
                "R", "V", "u", "6", "A", "6", "P", "v", "C", "/", "B", "M", "0", 
                "N", "k", "R", "K", "S", "P", "z", "6", "b", "5", "r", "o", "2", 
                "X", "e", "2", "D", "/" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x0a), gsl::byte(0x79), gsl::byte(0x0f), gsl::byte(0xf8),
                gsl::byte(0xf7), gsl::byte(0xa5), gsl::byte(0x94), gsl::byte(0xc2),
                gsl::byte(0x94), gsl::byte(0x15), gsl::byte(0x56), gsl::byte(0xd8),
                gsl::byte(0xbe), gsl::byte(0xe9), gsl::byte(0xf2), gsl::byte(0xfc),
                gsl::byte(0x43), gsl::byte(0x61), gsl::byte(0x5b), gsl::byte(0x37),
                gsl::byte(0x26), gsl::byte(0xbe), gsl::byte(0x42), gsl::byte(0xbd),
                gsl::byte(0x03), gsl::byte(0x99), gsl::byte(0xa2), gsl::byte(0x1e),
                gsl::byte(0x6b), gsl::byte(0x19), gsl::byte(0xd9), gsl::byte(0x4f),
            }
        },
        inputs_n_digest_t{ { "mUSbgg4fMyRqQt+wadlZ04DOVHbhvnLF" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x7f), gsl::byte(0x62), gsl::byte(0xc2), gsl::byte(0x8b),
                gsl::byte(0x03), gsl::byte(0xa0), gsl::byte(0x79), gsl::byte(0xa0),
                gsl::byte(0x1e), gsl::byte(0xe6), gsl::byte(0x61), gsl::byte(0x27),
                gsl::byte(0x77), gsl::byte(0xba), gsl::byte(0x11), gsl::byte(0x27),
                gsl::byte(0xc8), gsl::byte(0x7c), gsl::byte(0xbb), gsl::byte(0xf9),
                gsl::byte(0x0a), gsl::byte(0x0e), gsl::byte(0xe1), gsl::byte(0x1c),
                gsl::byte(0x72), gsl::byte(0x6e), gsl::byte(0xfe), gsl::byte(0x5d),
                gsl::byte(0xda), gsl::byte(0xaa), gsl::byte(0x94), gsl::byte(0xcf),
            }
        },
        inputs_n_digest_t{ { "AObNDNZK+dDj1mEg0kHbFwGoWka85V5i" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xbd), gsl::byte(0x54), gsl::byte(0x8b), gsl::byte(0x1f),
                gsl::byte(0xac), gsl::byte(0x8c), gsl::byte(0x1b), gsl::byte(0x75),
                gsl::byte(0x13), gsl::byte(0x06), gsl::byte(0x2d), gsl::byte(0xfc),
                gsl::byte(0x3c), gsl::byte(0x7f), gsl::byte(0x92), gsl::byte(0xd6),
                gsl::byte(0xe2), gsl::byte(0xaa), gsl::byte(0xa2), gsl::byte(0x63),
                gsl::byte(0x18), gsl::byte(0x4f), gsl::byte(0x82), gsl::byte(0xa2),
                gsl::byte(0x66), gsl::byte(0x7f), gsl::byte(0x6f), gsl::byte(0x69),
                gsl::byte(0xa5), gsl::byte(0x4d), gsl::byte(0x95), gsl::byte(0x91),
            }
        },
        inputs_n_digest_t{ { "TistA+4Klkgl+/OP6/m89N5xFmKY2ltV" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xc5), gsl::byte(0xb9), gsl::byte(0x4a), gsl::byte(0x2d),
                gsl::byte(0x24), gsl::byte(0x9f), gsl::byte(0xba), gsl::byte(0x0e),
                gsl::byte(0x03), gsl::byte(0xdf), gsl::byte(0x4a), gsl::byte(0x30),
                gsl::byte(0xb0), gsl::byte(0x1d), gsl::byte(0x98), gsl::byte(0xb6),
                gsl::byte(0xd0), gsl::byte(0x2d), gsl::byte(0x68), gsl::byte(0x10),
                gsl::byte(0x32), gsl::byte(0x15), gsl::byte(0x46), gsl::byte(0x1a),
                gsl::byte(0x48), gsl::byte(0xbc), gsl::byte(0xc1), gsl::byte(0x4c),
                gsl::byte(0xb4), gsl::byte(0xd4), gsl::byte(0x53), gsl::byte(0xfe),
            }
        },
        inputs_n_digest_t{ { "3PgKx4ppntU6Khfzb3G0KvgI34dwCZFX8" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x2b), gsl::byte(0x4b), gsl::byte(0x4a), gsl::byte(0xd8),
                gsl::byte(0x1d), gsl::byte(0xa7), gsl::byte(0xfb), gsl::byte(0x16),
                gsl::byte(0x4b), gsl::byte(0xe2), gsl::byte(0x89), gsl::byte(0x0e),
                gsl::byte(0x34), gsl::byte(0x9c), gsl::byte(0x81), gsl::byte(0x54),
                gsl::byte(0xa2), gsl::byte(0x56), gsl::byte(0x48), gsl::byte(0xa9),
                gsl::byte(0x76), gsl::byte(0x41), gsl::byte(0x0f), gsl::byte(0xf8),
                gsl::byte(0x2d), gsl::byte(0x05), gsl::byte(0xec), gsl::byte(0x66),
                gsl::byte(0xff), gsl::byte(0x42), gsl::byte(0x85), gsl::byte(0xb4),
            }
        },
        inputs_n_digest_t{ { "kBRzUVsBCVXkITNS73L0zXvtcVvsximDJ" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xe4), gsl::byte(0xf1), gsl::byte(0x3e), gsl::byte(0xa3),
                gsl::byte(0xb3), gsl::byte(0x74), gsl::byte(0x6b), gsl::byte(0x29),
                gsl::byte(0x53), gsl::byte(0x67), gsl::byte(0x9b), gsl::byte(0xaf),
                gsl::byte(0xe6), gsl::byte(0x91), gsl::byte(0xc1), gsl::byte(0x92),
                gsl::byte(0xa6), gsl::byte(0x78), gsl::byte(0xdc), gsl::byte(0x41),
                gsl::byte(0xd3), gsl::byte(0x66), gsl::byte(0xab), gsl::byte(0x05),
                gsl::byte(0xb8), gsl::byte(0x94), gsl::byte(0x0e), gsl::byte(0x94),
                gsl::byte(0x26), gsl::byte(0x8a), gsl::byte(0x0c), gsl::byte(0x1f),
            }
        },
        inputs_n_digest_t{ { "waBjbQUotgTN9GDJHuh0N4B7sYxT/poHU" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x9f), gsl::byte(0xc0), gsl::byte(0xf1), gsl::byte(0xda),
                gsl::byte(0xf0), gsl::byte(0x1d), gsl::byte(0xc8), gsl::byte(0x90),
                gsl::byte(0x55), gsl::byte(0x99), gsl::byte(0x79), gsl::byte(0x6b),
                gsl::byte(0xcb), gsl::byte(0xea), gsl::byte(0x03), gsl::byte(0x51),
                gsl::byte(0x54), gsl::byte(0x7e), gsl::byte(0x44), gsl::byte(0x81),
                gsl::byte(0x50), gsl::byte(0xf3), gsl::byte(0xe2), gsl::byte(0x23),
                gsl::byte(0x46), gsl::byte(0x7e), gsl::byte(0x0f), gsl::byte(0x70),
                gsl::byte(0x1c), gsl::byte(0xd4), gsl::byte(0x9a), gsl::byte(0xcb),
            }
        },
        inputs_n_digest_t{ { "vcOrrxWCKiZT/8MduuDm7hZu7vp/WEiGLVa6dCMWcgUZ3OKp2DlKdYb5S0oSuZW" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x53), gsl::byte(0xd3), gsl::byte(0xfe), gsl::byte(0xe6),
                gsl::byte(0xc1), gsl::byte(0x7f), gsl::byte(0xb4), gsl::byte(0x25),
                gsl::byte(0xcb), gsl::byte(0x58), gsl::byte(0x15), gsl::byte(0x7f),
                gsl::byte(0xf2), gsl::byte(0xb2), gsl::byte(0x37), gsl::byte(0xdf),
                gsl::byte(0xa2), gsl::byte(0x77), gsl::byte(0x10), gsl::byte(0xe9),
                gsl::byte(0x7f), gsl::byte(0x95), gsl::byte(0xbf), gsl::byte(0x9e),
                gsl::byte(0x60), gsl::byte(0xde), gsl::byte(0x35), gsl::byte(0x55),
                gsl::byte(0x2f), gsl::byte(0xbf), gsl::byte(0xcd), gsl::byte(0x8a),
            }
        },
        inputs_n_digest_t{ { "KURVK0IZf7+DbaVg71XYylOpNDIZWGViMTvdHOlyn8lsl4fbO3SwiK+iuNkcumf" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x6c), gsl::byte(0x2d), gsl::byte(0x26), gsl::byte(0x89),
                gsl::byte(0x9d), gsl::byte(0xdf), gsl::byte(0xd9), gsl::byte(0xfa),
                gsl::byte(0x50), gsl::byte(0xb1), gsl::byte(0x05), gsl::byte(0x65),
                gsl::byte(0xe9), gsl::byte(0xa5), gsl::byte(0xe6), gsl::byte(0xb2),
                gsl::byte(0x56), gsl::byte(0x1a), gsl::byte(0x6b), gsl::byte(0x75),
                gsl::byte(0xaf), gsl::byte(0x7f), gsl::byte(0xb7), gsl::byte(0xd0),
                gsl::byte(0x52), gsl::byte(0xb8), gsl::byte(0xa9), gsl::byte(0x7e),
                gsl::byte(0xef), gsl::byte(0x1a), gsl::byte(0x1a), gsl::byte(0x1f),
            }
        },
        inputs_n_digest_t{ { "SEK5iVfh0gJwKKEtYnVdCjO/cfYhUaSrCMgIpOWA0QAZzO4Z9LnU6pLAcQjrHUo" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xb6), gsl::byte(0xd2), gsl::byte(0xcd), gsl::byte(0x07),
                gsl::byte(0xff), gsl::byte(0x57), gsl::byte(0xa3), gsl::byte(0x37),
                gsl::byte(0x39), gsl::byte(0x0a), gsl::byte(0x99), gsl::byte(0x5c),
                gsl::byte(0x2b), gsl::byte(0xef), gsl::byte(0xaa), gsl::byte(0x1b),
                gsl::byte(0x55), gsl::byte(0x82), gsl::byte(0x16), gsl::byte(0x36),
                gsl::byte(0x46), gsl::byte(0x5c), gsl::byte(0xa6), gsl::byte(0x39),
                gsl::byte(0x5e), gsl::byte(0x31), gsl::byte(0x1c), gsl::byte(0xe9),
                gsl::byte(0x85), gsl::byte(0x5e), gsl::byte(0xdc), gsl::byte(0xce),
            }
        },
        inputs_n_digest_t{ { "QTqvZvwZDyjsD+6q3yFjHVcG5Zt4Ck8CW2CBin0nOYQau05pcU1XJ/j4rZ8WOfi" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x48), gsl::byte(0x63), gsl::byte(0x07), gsl::byte(0xfb),
                gsl::byte(0x78), gsl::byte(0xa7), gsl::byte(0xf2), gsl::byte(0x6e),
                gsl::byte(0x70), gsl::byte(0x94), gsl::byte(0xab), gsl::byte(0xfa),
                gsl::byte(0xfd), gsl::byte(0x7f), gsl::byte(0x42), gsl::byte(0xd4),
                gsl::byte(0x12), gsl::byte(0xad), gsl::byte(0x4f), gsl::byte(0xa7),
                gsl::byte(0x60), gsl::byte(0x4b), gsl::byte(0x64), gsl::byte(0xdb),
                gsl::byte(0xa0), gsl::byte(0xba), gsl::byte(0xb0), gsl::byte(0x61),
                gsl::byte(0xcb), gsl::byte(0xe9), gsl::byte(0x1d), gsl::byte(0x13),
            }
        },
        inputs_n_digest_t{ { "WOfq9oq3Alaxnhe5lUG94Q0gQaN/+W3T4nzY+NQKoTj4WSDY+Hs0VFfozlSrfKk" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x20), gsl::byte(0x2e), gsl::byte(0x31), gsl::byte(0xcb),
                gsl::byte(0x58), gsl::byte(0xce), gsl::byte(0xef), gsl::byte(0x45),
                gsl::byte(0x91), gsl::byte(0x36), gsl::byte(0x1f), gsl::byte(0xd4),
                gsl::byte(0x2b), gsl::byte(0xb2), gsl::byte(0xe7), gsl::byte(0xd3),
                gsl::byte(0x98), gsl::byte(0xd3), gsl::byte(0x21), gsl::byte(0x1e),
                gsl::byte(0x46), gsl::byte(0xc2), gsl::byte(0x84), gsl::byte(0x4d),
                gsl::byte(0xee), gsl::byte(0xc2), gsl::byte(0x3b), gsl::byte(0xcf),
                gsl::byte(0x29), gsl::byte(0xe1), gsl::byte(0xaf), gsl::byte(0xa9),
            }
        },
        inputs_n_digest_t{ { "8ZuWeHeLMHs0utonZhW8ltlObQ+xRPEnQdc1SuhG4zPJEesK4rUi6vUrJrQRI3HA" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x4b), gsl::byte(0x43), gsl::byte(0x81), gsl::byte(0x08),
                gsl::byte(0x6b), gsl::byte(0xf4), gsl::byte(0xe4), gsl::byte(0x65),
                gsl::byte(0x57), gsl::byte(0xf6), gsl::byte(0xb3), gsl::byte(0xf8),
                gsl::byte(0x87), gsl::byte(0x02), gsl::byte(0xed), gsl::byte(0xb3),
                gsl::byte(0xe6), gsl::byte(0xc3), gsl::byte(0x81), gsl::byte(0x35),
                gsl::byte(0x0d), gsl::byte(0xd1), gsl::byte(0xba), gsl::byte(0x2d),
                gsl::byte(0xb3), gsl::byte(0x2b), gsl::byte(0x04), gsl::byte(0x5d),
                gsl::byte(0x66), gsl::byte(0x07), gsl::byte(0x7c), gsl::byte(0xd2),
            }
        },
        inputs_n_digest_t{ { "IaAvmyF9SLzxE5wbhscZlkqGhs+u+ToviovJuICOC/+x8VLu+RQNnbbGJdRS+Z1d" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xeb), gsl::byte(0x3c), gsl::byte(0x83), gsl::byte(0xcc),
                gsl::byte(0x96), gsl::byte(0xc0), gsl::byte(0x2c), gsl::byte(0x64),
                gsl::byte(0xf2), gsl::byte(0xb3), gsl::byte(0x3e), gsl::byte(0xa3),
                gsl::byte(0x4a), gsl::byte(0x35), gsl::byte(0xd5), gsl::byte(0x42),
                gsl::byte(0x15), gsl::byte(0x73), gsl::byte(0xe1), gsl::byte(0x75),
                gsl::byte(0x6a), gsl::byte(0x79), gsl::byte(0xa2), gsl::byte(0x2a),
                gsl::byte(0x52), gsl::byte(0xf2), gsl::byte(0xd2), gsl::byte(0x96),
                gsl::byte(0x55), gsl::byte(0xb0), gsl::byte(0xc9), gsl::byte(0xdb),
            }
        },
        inputs_n_digest_t{ { "5jUIU1RTJ833em0EPV5S0tG5cb49+A+9b1vzm2Bui2Kuh7FUgkYaA4Pt+M26Omnd" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xb0), gsl::byte(0x1c), gsl::byte(0x17), gsl::byte(0xe2),
                gsl::byte(0x5f), gsl::byte(0xb9), gsl::byte(0x25), gsl::byte(0xed),
                gsl::byte(0x82), gsl::byte(0x1a), gsl::byte(0xd6), gsl::byte(0x5d),
                gsl::byte(0x09), gsl::byte(0xf5), gsl::byte(0x5a), gsl::byte(0x94),
                gsl::byte(0x70), gsl::byte(0x57), gsl::byte(0xb2), gsl::byte(0x80),
                gsl::byte(0x17), gsl::byte(0xf0), gsl::byte(0x81), gsl::byte(0x70),
                gsl::byte(0xc3), gsl::byte(0xf3), gsl::byte(0x4f), gsl::byte(0x87),
                gsl::byte(0x58), gsl::byte(0x90), gsl::byte(0x2f), gsl::byte(0x41),
            }
        },
        inputs_n_digest_t{ { "fxGhUWmgeUFolIZfcMVWh/7KMYlShLGL5SYH+l0GF6wGFgOntbBirS7pWJuyUDpH" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x0f), gsl::byte(0x52), gsl::byte(0xce), gsl::byte(0x6a),
                gsl::byte(0x6c), gsl::byte(0x1d), gsl::byte(0xb7), gsl::byte(0x8b),
                gsl::byte(0x47), gsl::byte(0x3e), gsl::byte(0x2e), gsl::byte(0x01),
                gsl::byte(0x32), gsl::byte(0x54), gsl::byte(0x6e), gsl::byte(0x42),
                gsl::byte(0x18), gsl::byte(0xa0), gsl::byte(0xa8), gsl::byte(0x88),
                gsl::byte(0x29), gsl::byte(0x02), gsl::byte(0xda), gsl::byte(0x62),
                gsl::byte(0x3e), gsl::byte(0x11), gsl::byte(0x23), gsl::byte(0x6b),
                gsl::byte(0x59), gsl::byte(0xf9), gsl::byte(0x37), gsl::byte(0xb5),
            }
        },
        inputs_n_digest_t{ { "ANfLfy3OMKtbvvKTBPqrL4iVlJF4zFowqvJfl+TiH3wPFtm0FH6HVbLJhnMyRDfp" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xa2), gsl::byte(0x1b), gsl::byte(0x14), gsl::byte(0x7a),
                gsl::byte(0x38), gsl::byte(0x15), gsl::byte(0x80), gsl::byte(0x8a),
                gsl::byte(0xe1), gsl::byte(0x14), gsl::byte(0x61), gsl::byte(0x9e),
                gsl::byte(0x02), gsl::byte(0xf6), gsl::byte(0xbd), gsl::byte(0x07),
                gsl::byte(0x7f), gsl::byte(0xc9), gsl::byte(0x3a), gsl::byte(0x3b),
                gsl::byte(0x89), gsl::byte(0x95), gsl::byte(0x96), gsl::byte(0x0b),
                gsl::byte(0xdb), gsl::byte(0xd0), gsl::byte(0xe9), gsl::byte(0x97),
                gsl::byte(0x78), gsl::byte(0xf1), gsl::byte(0x7b), gsl::byte(0x47),
            }
        },
        inputs_n_digest_t{ { "rO9HZgYWcQNUSNdp7ahrwiOKTypOaOjYjPS7+IKUQPVNdaibMJaZh1hz7Xl5589eb" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x4e), gsl::byte(0x9c), gsl::byte(0x8e), gsl::byte(0x6f),
                gsl::byte(0x98), gsl::byte(0xa2), gsl::byte(0xf8), gsl::byte(0x0a),
                gsl::byte(0xfa), gsl::byte(0x31), gsl::byte(0xae), gsl::byte(0x89),
                gsl::byte(0x28), gsl::byte(0xc5), gsl::byte(0x1e), gsl::byte(0x2d),
                gsl::byte(0xf1), gsl::byte(0x98), gsl::byte(0x9c), gsl::byte(0xab),
                gsl::byte(0xc9), gsl::byte(0xa2), gsl::byte(0x47), gsl::byte(0x13),
                gsl::byte(0x34), gsl::byte(0x04), gsl::byte(0xc3), gsl::byte(0xc2),
                gsl::byte(0xf7), gsl::byte(0xac), gsl::byte(0xe4), gsl::byte(0x32),
            }
        },
        inputs_n_digest_t{ { "EsjtX8leFlohGq2U0v/jnB5Vspgpl7ZkJXqXwQEIv8VIN4RBFngXfkx3MUTvmyCKi" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xba), gsl::byte(0xb0), gsl::byte(0x28), gsl::byte(0xed),
                gsl::byte(0x12), gsl::byte(0x10), gsl::byte(0x94), gsl::byte(0xad),
                gsl::byte(0xb1), gsl::byte(0x6f), gsl::byte(0xcd), gsl::byte(0xb1),
                gsl::byte(0x57), gsl::byte(0xb0), gsl::byte(0x03), gsl::byte(0x83),
                gsl::byte(0xab), gsl::byte(0xe6), gsl::byte(0xa1), gsl::byte(0xc3),
                gsl::byte(0xeb), gsl::byte(0x17), gsl::byte(0x9e), gsl::byte(0x06),
                gsl::byte(0xb0), gsl::byte(0xe3), gsl::byte(0x6c), gsl::byte(0x9f),
                gsl::byte(0x3d), gsl::byte(0x89), gsl::byte(0xb7), gsl::byte(0x1d),
            }
        },
        inputs_n_digest_t{ { "HvO3+v+BVETYT/EVZVcAgqODDO9xrD3kfsExUjEq2NdCVZRZdbzdpfEJRaiMNcNn4" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x21), gsl::byte(0x6e), gsl::byte(0x1e), gsl::byte(0xd3),
                gsl::byte(0xb7), gsl::byte(0xe1), gsl::byte(0xa7), gsl::byte(0x84),
                gsl::byte(0xec), gsl::byte(0xd2), gsl::byte(0x3d), gsl::byte(0x41),
                gsl::byte(0x46), gsl::byte(0xfd), gsl::byte(0x53), gsl::byte(0x00),
                gsl::byte(0xec), gsl::byte(0x82), gsl::byte(0x86), gsl::byte(0x95),
                gsl::byte(0x28), gsl::byte(0x9c), gsl::byte(0x5b), gsl::byte(0xed),
                gsl::byte(0x42), gsl::byte(0x8a), gsl::byte(0x94), gsl::byte(0x7f),
                gsl::byte(0xeb), gsl::byte(0x86), gsl::byte(0x70), gsl::byte(0x15),
            }
        },
        inputs_n_digest_t{ { "LFs+T5vdkE17gdkH5QP5LZsDYNNCAgnpB5/NJO41/oZDomQuHtddhl3YjRJgMk4gv" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x83), gsl::byte(0x0b), gsl::byte(0xbd), gsl::byte(0x54),
                gsl::byte(0xec), gsl::byte(0xea), gsl::byte(0x6b), gsl::byte(0xf4),
                gsl::byte(0xee), gsl::byte(0x37), gsl::byte(0xc1), gsl::byte(0x00),
                gsl::byte(0xad), gsl::byte(0xb3), gsl::byte(0xd6), gsl::byte(0x46),
                gsl::byte(0x08), gsl::byte(0xd8), gsl::byte(0x31), gsl::byte(0x21),
                gsl::byte(0x00), gsl::byte(0xda), gsl::byte(0x7e), gsl::byte(0xab),
                gsl::byte(0xca), gsl::byte(0xfb), gsl::byte(0xbf), gsl::byte(0xcd),
                gsl::byte(0xf9), gsl::byte(0xfa), gsl::byte(0xa8), gsl::byte(0x5e),
            }
        },
        inputs_n_digest_t{ { "sZiRwDipjB6iDMjEhMcWlolOZDLctanVJOHZm1OPCdfHcnnEO/xrLzG9N56iN89EY" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x1b), gsl::byte(0x4a), gsl::byte(0x3f), gsl::byte(0xc2),
                gsl::byte(0x9b), gsl::byte(0x4d), gsl::byte(0x51), gsl::byte(0xfa),
                gsl::byte(0x3c), gsl::byte(0xb1), gsl::byte(0xc2), gsl::byte(0x77),
                gsl::byte(0xa4), gsl::byte(0x5e), gsl::byte(0x01), gsl::byte(0x7f),
                gsl::byte(0x2c), gsl::byte(0xae), gsl::byte(0x24), gsl::byte(0x78),
                gsl::byte(0x56), gsl::byte(0xd5), gsl::byte(0xe3), gsl::byte(0xb9),
                gsl::byte(0x5a), gsl::byte(0x88), gsl::byte(0xaf), gsl::byte(0xb7),
                gsl::byte(0x30), gsl::byte(0x18), gsl::byte(0x2c), gsl::byte(0x93),
            }
        },
        inputs_n_digest_t{ { "EVAnPJ0nZwjb81gl/Rlre5gG0gsspWsNN+jLJ0LSYC6aJYAlQ25zsRH4oEXXargHjGspibNTG9NKTKVE1CpjpEpW4vEREKk/Jwo2zsglq4NlCZ8zdoA5VJjwhUledT" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x77), gsl::byte(0x6f), gsl::byte(0x61), gsl::byte(0xb8),
                gsl::byte(0xae), gsl::byte(0xbe), gsl::byte(0xef), gsl::byte(0x45),
                gsl::byte(0x39), gsl::byte(0xe2), gsl::byte(0x9e), gsl::byte(0xc8),
                gsl::byte(0xb0), gsl::byte(0x0b), gsl::byte(0xa6), gsl::byte(0x81),
                gsl::byte(0x40), gsl::byte(0xfd), gsl::byte(0x11), gsl::byte(0x8c),
                gsl::byte(0x5c), gsl::byte(0x55), gsl::byte(0x5a), gsl::byte(0xce),
                gsl::byte(0x90), gsl::byte(0x02), gsl::byte(0x3c), gsl::byte(0x86),
                gsl::byte(0xa4), gsl::byte(0x8a), gsl::byte(0x28), gsl::byte(0x8c),
            }
        },
        inputs_n_digest_t{ { "LyAVzYvBOoOE+ht2KmzYE7pdj3fsInLBtiTpNFs7+mmlPU9sFjp8Tf+mDsIGEGfX1hNBjalRojuYBd44RCMJsf0VkkqyBKYR57Uf5qH4WlHV4FUBsFC1wqVZM03eov" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x51), gsl::byte(0xce), gsl::byte(0x6e), gsl::byte(0xe7),
                gsl::byte(0xd8), gsl::byte(0x05), gsl::byte(0xd1), gsl::byte(0x27),
                gsl::byte(0xea), gsl::byte(0x24), gsl::byte(0x3f), gsl::byte(0x32),
                gsl::byte(0x35), gsl::byte(0xef), gsl::byte(0x24), gsl::byte(0xf2),
                gsl::byte(0xe2), gsl::byte(0x94), gsl::byte(0x01), gsl::byte(0x7f),
                gsl::byte(0x3b), gsl::byte(0xbd), gsl::byte(0x35), gsl::byte(0x12),
                gsl::byte(0xee), gsl::byte(0x0a), gsl::byte(0x8f), gsl::byte(0xe4),
                gsl::byte(0xb5), gsl::byte(0x0b), gsl::byte(0xb5), gsl::byte(0xfd),
            }
        },
        inputs_n_digest_t{ { "tnINGz3xX+7OGmYPM0eX1QoPTAIAdg4jpEnHNJ+0N8ZZ00sMrkcxBrXUIN81E3GK0eK/meT3gBjA6lAQYdqS9UwYEZLuzZjPzUsYIlqKV30wJlfZJc+xxDw3SPR/GY" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x1c), gsl::byte(0xdc), gsl::byte(0x41), gsl::byte(0x25),
                gsl::byte(0xc9), gsl::byte(0xa7), gsl::byte(0xb7), gsl::byte(0x32),
                gsl::byte(0x96), gsl::byte(0xfe), gsl::byte(0x79), gsl::byte(0xe6),
                gsl::byte(0xf8), gsl::byte(0xb9), gsl::byte(0x89), gsl::byte(0x2a),
                gsl::byte(0x29), gsl::byte(0x77), gsl::byte(0x72), gsl::byte(0xb3),
                gsl::byte(0xa3), gsl::byte(0xe2), gsl::byte(0xf8), gsl::byte(0x63),
                gsl::byte(0x02), gsl::byte(0x1f), gsl::byte(0x65), gsl::byte(0xb8),
                gsl::byte(0xf8), gsl::byte(0xdc), gsl::byte(0x82), gsl::byte(0xb4),
            }
        },
        inputs_n_digest_t{ { "nP510KqwAFsk1xhoGk3GCXNvn4DscDnI3uQRnpkYC4+WvQPJ1UOmrLJ5aPye0rAcWgMoX4ldS6nq8Di06NR6GNOc6qsPGDMQvNJMfoPF//sRKJL9InXXbLjCa4z56do" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x85), gsl::byte(0xe3), gsl::byte(0xe0), gsl::byte(0x2d),
                gsl::byte(0x3e), gsl::byte(0xa7), gsl::byte(0x1f), gsl::byte(0x23),
                gsl::byte(0xc4), gsl::byte(0x9e), gsl::byte(0x48), gsl::byte(0xc0),
                gsl::byte(0x56), gsl::byte(0x4b), gsl::byte(0x6e), gsl::byte(0x97),
                gsl::byte(0x16), gsl::byte(0xf2), gsl::byte(0x26), gsl::byte(0xc6),
                gsl::byte(0x6c), gsl::byte(0x12), gsl::byte(0xea), gsl::byte(0x98),
                gsl::byte(0x18), gsl::byte(0x86), gsl::byte(0x1b), gsl::byte(0xb9),
                gsl::byte(0xcf), gsl::byte(0x60), gsl::byte(0xb9), gsl::byte(0x5a),
            }
        },
        inputs_n_digest_t{ { "LFJ0Po6st7qHnBo9caX6+WJGdDkoCynna6ER4cSecrO9Sol4jNmeAOoyhyByRBk1F7p2hcZlY0+MDxjzRxI87HW8r6oK7mBpM5os3UQhj6ZQANCYassaWZCNHpJo9hU" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0xc0), gsl::byte(0xa8), gsl::byte(0x59), gsl::byte(0x6b),
                gsl::byte(0x92), gsl::byte(0x0d), gsl::byte(0xf4), gsl::byte(0xa8),
                gsl::byte(0xb7), gsl::byte(0x6c), gsl::byte(0xdb), gsl::byte(0xf8),
                gsl::byte(0x01), gsl::byte(0x79), gsl::byte(0xb0), gsl::byte(0xe4),
                gsl::byte(0x60), gsl::byte(0xe5), gsl::byte(0xae), gsl::byte(0x1a),
                gsl::byte(0xe8), gsl::byte(0xb3), gsl::byte(0xbb), gsl::byte(0x32),
                gsl::byte(0xdc), gsl::byte(0x23), gsl::byte(0xad), gsl::byte(0xe5),
                gsl::byte(0x93), gsl::byte(0xd0), gsl::byte(0x28), gsl::byte(0x72),
            }
        },
        inputs_n_digest_t{ { "cFJ91hkhIXeOploZuV12nTnGdouJpPtoNkQGdGDPQ43R+bfh/mg82lSkP4fDPFo5q1OdyVQr0KmE+Wi2NPev7H+P+8aTzLnEVH0xTP9CSO5WdCE0z7S6VoMIchhued5" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x45), gsl::byte(0x34), gsl::byte(0x85), gsl::byte(0x51),
                gsl::byte(0x2b), gsl::byte(0x61), gsl::byte(0xc9), gsl::byte(0xcb),
                gsl::byte(0x4f), gsl::byte(0xf2), gsl::byte(0x60), gsl::byte(0xa5),
                gsl::byte(0xc6), gsl::byte(0x10), gsl::byte(0x44), gsl::byte(0xaf),
                gsl::byte(0x34), gsl::byte(0x4a), gsl::byte(0x73), gsl::byte(0x2d),
                gsl::byte(0x95), gsl::byte(0x2e), gsl::byte(0xf5), gsl::byte(0xb7),
                gsl::byte(0x80), gsl::byte(0x3e), gsl::byte(0x9b), gsl::byte(0x72),
                gsl::byte(0x6e), gsl::byte(0xd0), gsl::byte(0xb7), gsl::byte(0x7e),
            }
        },
        inputs_n_digest_t{ { "m2KNmOaie3cpcHa2+HQQvC90HW/wHgSZcBmQlvACbUd6DFkPQO8cIlshnijCm4noNgB1FPmuSpmGz6IOcYx/5NOHIiTYmXNM3LvqmyxGmW+UES97+4eC6U+ZaLc0ExK7" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x71), gsl::byte(0x4b), gsl::byte(0x08), gsl::byte(0x92),
                gsl::byte(0x97), gsl::byte(0xc1), gsl::byte(0x50), gsl::byte(0x71),
                gsl::byte(0x0b), gsl::byte(0x50), gsl::byte(0x49), gsl::byte(0x1d),
                gsl::byte(0x0e), gsl::byte(0x02), gsl::byte(0xc2), gsl::byte(0x70),
                gsl::byte(0x12), gsl::byte(0x4f), gsl::byte(0xea), gsl::byte(0x8c),
                gsl::byte(0x4c), gsl::byte(0x8f), gsl::byte(0x46), gsl::byte(0x75),
                gsl::byte(0x55), gsl::byte(0x22), gsl::byte(0xdd), gsl::byte(0x8d),
                gsl::byte(0xd6), gsl::byte(0x30), gsl::byte(0xff), gsl::byte(0x17),
            }
        },
        inputs_n_digest_t{ { "QkGb3OpEt+wBDJo+t1v/A+lzZ2nClpNnGTHjxqdxOr8dz1qF/x2HivWV2AyTjdVP3SeSVfyqLSrfh6n0MXNmk7nPxVamZHY0cVH+mbSrbg3HJ3+egf2w1nolh4LuFHOe" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x1c), gsl::byte(0x68), gsl::byte(0xa0), gsl::byte(0x99),
                gsl::byte(0xf8), gsl::byte(0xe6), gsl::byte(0xc4), gsl::byte(0xa0),
                gsl::byte(0xcc), gsl::byte(0x49), gsl::byte(0x41), gsl::byte(0x20),
                gsl::byte(0x58), gsl::byte(0x4c), gsl::byte(0x0d), gsl::byte(0x97),
                gsl::byte(0x4f), gsl::byte(0x44), gsl::byte(0x4f), gsl::byte(0x2a),
                gsl::byte(0xa0), gsl::byte(0x19), gsl::byte(0x74), gsl::byte(0xd0),
                gsl::byte(0x95), gsl::byte(0xf1), gsl::byte(0x7a), gsl::byte(0x0a),
                gsl::byte(0xdb), gsl::byte(0x76), gsl::byte(0xd2), gsl::byte(0x74),
            }
        },
        inputs_n_digest_t{ { "x/QCRzoBvZpGxdqi2SaFff2MPXETqbMAztEsD7AVB9cNAmObxouwaOG4jGeS1l2kxgQZrBj8OQfyY735wilBJY9XHgDXRT2V2As/L/JreW1HG3FQS14aF15D4bkDdFOI" },
            vdr::hash::sha256::digest_arr{
                gsl::byte(0x50), gsl::byte(0x87), gsl::byte(0x52), gsl::byte(0xa5),
                gsl::byte(0xa5), gsl::byte(0x18), gsl::byte(0xde), gsl::byte(0x80),
                gsl::byte(0x37), gsl::byte(0x4d), gsl::byte(0x62), gsl::byte(0x4f),
                gsl::byte(0xaf), gsl::byte(0xb7), gsl::byte(0x03), gsl::byte(0xe3),
                gsl::byte(0xa5), gsl::byte(0x55), gsl::byte(0x19), gsl::byte(0x69),
                gsl::byte(0x97), gsl::byte(0xca), gsl::byte(0xd7), gsl::byte(0x2d),
                gsl::byte(0xc0), gsl::byte(0xd1), gsl::byte(0x33), gsl::byte(0x14),
                gsl::byte(0x59), gsl::byte(0xe6), gsl::byte(0x71), gsl::byte(0xa8),
            }
        },
    };

    return inputs_n_digests;
}
