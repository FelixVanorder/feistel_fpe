#ifndef CRYPTO
#define CRYPTO

#include <limits>
#include <stdexcept>
#include <array>

#include <openssl/sha.h>

class sha256_t
{
public:
    enum : size_t { digest_bytes = SHA256_DIGEST_LENGTH };
    static constexpr size_t get_digest_bytes() { return digest_bytes; }

    enum : size_t { digest_bits = digest_bytes * std::numeric_limits<uint8_t>::digits };
    static constexpr size_t get_digest_bits() { return digest_bits; }

    enum : size_t { block_bytes = SHA256_CBLOCK };
    static constexpr size_t get_block_bytes() { return block_bytes; }

    enum : size_t { block_bits = block_bytes * std::numeric_limits<uint8_t>::digits };
    static constexpr size_t get_block_bits() { return block_bits; }

public:
    sha256_t()
    {
        clear();
    }

    ~sha256_t()
    {
        clear();
    }

    sha256_t( void const * ptr, size_t const size )
    {
        clear();
        update( ptr, size );
    }

    sha256_t( std::string const & data )
    {
        clear();
        update( data );
    }

    sha256_t & update( void const * ptr, size_t const size )
    {
        if( _failure == SHA256_Update( &_ctx, ptr, size ) )
        {
            throw std::runtime_error("Can't update SHA-256.");
        }
        return *this;
    }

    sha256_t & update( std::string const & data )
    {
        return update( &data[0], data.size() );
    }

    void final( void * result )
    {
        static_assert( std::is_same< unsigned char, uint8_t >::value, "We need to unsigned char to be the 8-bit unsigned value." );
        if( _failure == SHA256_Final( reinterpret_cast< unsigned char * >( result ), &_ctx ) )
        {
            throw std::runtime_error("Can't finalize SHA-256.");
        }
        clear();
    }

    std::string final()
    {
        std::string result;
        result.resize( digest_bytes );
        this->final( &result[0] );
        return result;
    }

    sha256_t & clear()
    {
        if( _failure == SHA256_Init( &_ctx ) )
        {
            throw std::runtime_error("Can't init SHA-256.");
        }
        return *this;
    }

private:

    enum : int { _success = 1 };
    enum : int { _failure = 0 };

    SHA256_CTX _ctx;

};

template< class Value >
void clear_var( Value & value )
{
    value = Value();
}

#include <algorithm>

template<class Hash>
class hmac_t
{
public:
    enum : size_t { digest_bytes = Hash::digest_bytes };
    constexpr size_t get_digest_bytes() { return digest_bytes; }

    enum : size_t { digest_bits = Hash::digest_bits };
    constexpr size_t get_digest_bits() { return digest_bits; }

    enum : size_t { block_bytes = Hash::block_bytes };
    constexpr size_t get_block_bytes() { return block_bytes; }

    enum : size_t { block_bits = Hash::block_bits };
    constexpr size_t get_block_bits() { return block_bits; }

public:
    enum : uint8_t { inner_pad = 0x36 };
    enum : uint8_t { outer_pad = 0x5C };

public:
    hmac_t()
    {
        std::fill( _key.begin(), _key.end(), inner_pad );
    }

    ~hmac_t()
    {
        std::fill( _key.begin(), _key.end(), 0 );
    }

    hmac_t & set_key( std::string const & raw_key )
    {
        _hash.clear();

        if( raw_key.size() > _key.size() )
        {
            {
                auto trans_end = _key.begin();
                static_assert( Hash::get_digest_bytes() <= std::tuple_size<decltype(_key)>::value, "Hash digest must be less or equal to key size." );
                _hash
                    .update( raw_key )
                    .final( _key.data() );
                std::advance( trans_end, _hash.get_digest_bytes() );

                std::for_each( _key.begin(), trans_end, []( uint8_t & byte ) { byte ^= inner_pad; } );
                std::fill( trans_end, _key.end(), inner_pad );

                clear_var( trans_end );
            }
            _hash.update( _key.data(), _key.size() );
        }
        else
        {
            {
                auto trans_end = std::transform( raw_key.begin(), raw_key.end(), _key.begin(), []( uint8_t const byte ) { return byte ^ inner_pad; } );
                std::fill( trans_end, _key.end(), inner_pad );
                clear_var( trans_end );
            }

            _hash.update( _key.data(), _key.size() );
        }

        return *this;
    }

    hmac_t & update( void const * ptr, size_t const size )
    {
        _hash.update( ptr, size );
        return *this;
    }

    hmac_t & update( std::string const & data )
    {
        return update( &data[0], data.size() );
    }


    void final( void * result )
    {
        {
            std::array<uint8_t, Hash::digest_bytes> inner_hash;
            _hash.final( inner_hash.data() );

            std::for_each( _key.begin(), _key.end(), []( uint8_t & byte ) { byte ^= inner_pad ^ outer_pad; } );

            _hash
                .update( _key.data(), _key.size() )
                .update( &inner_hash[0], inner_hash.size() )
                .final( result );

            std::fill( inner_hash.begin(), inner_hash.end(), 0 );
        }

        std::for_each( _key.begin(), _key.end(), []( uint8_t & byte ) { byte ^= outer_pad ^ inner_pad; } );
        _hash.update( _key.data(), _key.size() );
    }

    std::string final()
    {
        std::string result;
        result.resize( digest_bytes );
        final( &result[0] );
        return result;
    }


    hmac_t & clear()
    {
        std::fill( _key.begin(), _key.end(), inner_pad );
        _hash.clear();
        return *this;
    }


private:
    Hash _hash;
    std::array<uint8_t, Hash::block_bytes> _key;
};

std::string tohex( const std::string & data )
{
    std::string result;
    result.resize( data.size() * 2 );

    static constexpr char hexes[] = "0123456789abcdef";

    for( size_t i = 0; i < result.size(); )
    {
        static_assert( std::is_same< unsigned char, uint8_t >::value, "We need to unsigned char to be the 8-bit unsigned value." );
        uint8_t const byte = data[ i / 2 ];
        result[ i ] = hexes[ byte >> 4  ]; ++i;
        result[ i ] = hexes[ byte & 0xf ]; ++i;
    }

    return result;
}

void test_hmac_sha256()
{
    {
        const std::string key = "";
        const std::string data = "";

        const std::string expected {
            '\xb6', '\x13', '\x67', '\x9a', '\x08', '\x14', '\xd9', '\xec', '\x77', '\x2f', '\x95', '\xd7', '\x78', '\xc3', '\x5f', '\xc5',
            '\xff', '\x16', '\x97', '\xc4', '\x93', '\x71', '\x56', '\x53', '\xc6', '\xc7', '\x12', '\x14', '\x42', '\x92', '\xc5', '\xad',
        };

        std::string actual = hmac_t<sha256_t>().set_key( key ).update( data ).final();

        if( expected != actual )
        {
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " fail test on key \"" << key << "\" and data \"" << data << "\"" << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " expected: " << tohex( expected ) << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << "   actual: " << tohex( actual ) << "\n";
            exit(1);
        }
    }

    {

        const std::string key = "key";
        const std::string data = "The quick brown fox jumps over the lazy dog";

        const std::string expected {
            '\xf7', '\xbc', '\x83', '\xf4', '\x30', '\x53', '\x84', '\x24', '\xb1', '\x32', '\x98', '\xe6', '\xaa', '\x6f', '\xb1', '\x43',
            '\xef', '\x4d', '\x59', '\xa1', '\x49', '\x46', '\x17', '\x59', '\x97', '\x47', '\x9d', '\xbc', '\x2d', '\x1a', '\x3c', '\xd8',
        };

        std::string actual = hmac_t<sha256_t>().set_key( key ).update( data ).final();

        if( expected != actual )
        {
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " fail test on key \"" << key << "\" and data \"" << data << "\"" << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " expected: " << tohex( expected ) << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << "   actual: " << tohex( actual ) << "\n";
            exit(1);
        }
    }

    {
        auto hmac = hmac_t<sha256_t>();

        const std::string key( hmac.get_block_bytes() * 3, 'H');
        const std::string data = "The quick brown fox jumps over the lazy dog";

        const std::string expected {
            '\x46', '\x1e', '\xbe', '\x05', '\xad', '\x4c', '\x21', '\xe4', '\x7f', '\x82', '\x97', '\x77', '\x5a', '\x01', '\x68', '\x29',
            '\x58', '\x09', '\x27', '\x11', '\xa0', '\xed', '\x91', '\x18', '\x65', '\x7c', '\x43', '\x32', '\x1b', '\xaa', '\x7f', '\xc7',
        };

        std::string actual = hmac.set_key( key ).update( data ).final();

        if( expected != actual )
        {
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " fail test on key \"" << key << "\" and data \"" << data << "\"" << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << " expected: " << tohex( expected ) << "\n";
            std::cerr << __FILE__ << "::" << __FUNCTION__ << ":" << __LINE__ << "   actual: " << tohex( actual ) << "\n";
            exit(1);
        }
    }


}

#include <openssl/aes.h>

template< size_t KeyBits = 128 >
class aes_t
{
    static_assert( KeyBits == 128 or KeyBits == 192 or KeyBits == 256, "Byte must be an 8-bit value." );

public:
    static_assert( std::numeric_limits<uint8_t>::digits == 8, "Byte must be an 8-bit value." );

    enum : size_t { key_bits = KeyBits };
    constexpr size_t get_key_bits() { return key_bits; }

    enum : size_t { key_bytes = key_bits / std::numeric_limits<uint8_t>::digits };
    constexpr size_t get_key_bytes() { return key_bytes; }

    enum : size_t { block_bytes = AES_BLOCK_SIZE };
    constexpr size_t get_block_bytes() { return block_bytes; }

    enum : size_t { block_bits = block_bytes * std::numeric_limits<uint8_t>::digits };
    constexpr size_t get_block_bits() { return block_bits; }

public:

    aes_t()
    {
        clear();
    }

    ~aes_t()
    {
        clear();
    }

    aes_t & set_enc_key( std::string const & raw_key )
    {
        if( _failure == AES_set_encrypt_key( &raw_key[0], key_bits, &_key ) )
        {
            throw std::runtime_error("Can't set encryption AES key.");
        }
        return *this;
    }

    aes_t & set_enc_key( void const * ptr )
    {
        if( _failure == AES_set_encrypt_key( reinterpret_cast< unsigned char const * >( ptr ), key_bits, &_key ) )
        {
            throw std::runtime_error("Can't set encryption AES key.");
        }
        return *this;
    }

    aes_t & set_dec_key( std::string const & raw_key )
    {
        if( _failure == AES_set_decrypt_key( &raw_key[0], key_bits, &_key ) )
        {
            throw std::runtime_error("Can't set decrypion AES key.");
        }
        return *this;
    }

    aes_t & enc( void const * in, void * out )
    {
        AES_encrypt( reinterpret_cast< unsigned char const * > ( in ), reinterpret_cast< unsigned char * > ( out ), &_key );
        return *this;
    }

    aes_t & dec( void const * in, void * out )
    {
        AES_decrypt( reinterpret_cast< unsigned char const * > ( in ), reinterpret_cast< unsigned char * > ( out ), &_key );
        return *this;
    }

    aes_t & clear()
    {
        std::array< uint8_t, key_bytes > zero_key;
        std::fill( zero_key.begin(), zero_key.end(), 0 );
        if( _failure == AES_set_encrypt_key( zero_key.data(), key_bits, &_key) )
        {
            throw std::runtime_error("Can't set empty AES key.");
        }
        return *this;
    }

private:
    enum : int { _success = 1 };
    enum : int { _failure = 1 };

private:
    AES_KEY _key;

};

typedef aes_t<128> aes128_t;


enum : size_t { bits_in_byte = std::numeric_limits< uint8_t >::digits };



template< size_t Base, size_t Pow >
struct static_pow
{
    enum : size_t { value = Base * static_pow< Base, Pow - 1 >::value };
};

template< size_t Base >
struct static_pow< Base, 0 >
{
    enum : size_t { value = 1 };
};

template< >
struct static_pow< 0, 0 >
{
};

namespace
{

    std::string tobin( uint8_t byte )
    {
        std::string result;
        result.resize( std::numeric_limits< decltype( byte ) >::digits );

        result[ 0 ] = ( byte & ( 1 << 7 ) ? '1' : '0' );
        result[ 1 ] = ( byte & ( 1 << 6 ) ? '1' : '0' );
        result[ 2 ] = ( byte & ( 1 << 5 ) ? '1' : '0' );
        result[ 3 ] = ( byte & ( 1 << 4 ) ? '1' : '0' );
        result[ 4 ] = ( byte & ( 1 << 3 ) ? '1' : '0' );
        result[ 5 ] = ( byte & ( 1 << 2 ) ? '1' : '0' );
        result[ 6 ] = ( byte & ( 1 << 1 ) ? '1' : '0' );
        result[ 7 ] = ( byte & ( 1 << 0 ) ? '1' : '0' );

        return result;
    }

    template< size_t arr_size >
    std::string tobin( std::array< uint8_t, arr_size > const & arr )
    {
        std::string result;
        result.reserve( arr.size() * 8 + arr.size() );

        for( auto byte : arr )
        {
            result += tobin(byte);
            result += ' ';
        }

        if( not arr.empty() )
        {
            result.pop_back();
        }

        return result;
    }
}

#define TO_STR(x) #x

template< class Type, size_t size >
std::array< Type, size > operator ^ ( std::array< Type, size > const & left, std::array< Type, size > const & right )
{
    std::array< Type, size > result;
    static_assert( std::is_integral< Type >::value, "" );
    static_assert( std::is_same< decltype( left ), decltype( right ) >::value, "Need to arrays have same size." );
    for( size_t i = 0; i < left.size(); ++i )
    {
        result[ i ] = left[ i ] ^ right[ i ];
    }
    return result;
}

size_t int_log2( uintmax_t value )
{
    register unsigned int result; // result of log2(v) will go here
    register unsigned int shift;

    static_assert( std::numeric_limits< unsigned char >::digits == 8, "" );
    static_assert( sizeof( value ) == 8, "" );
    result = (value > 0xFFFFFFFFUL ) << 5; value >>= result;
    shift  = (value > 0xFFFF       ) << 4; value >>= shift; result |= shift;
    shift  = (value > 0xFF         ) << 3; value >>= shift; result |= shift;
    shift  = (value > 0xF          ) << 2; value >>= shift; result |= shift;
    shift  = (value > 0x3          ) << 1; value >>= shift; result |= shift;
                                                            result |= (value >> 1);

    return result;
}

uintmax_t up_to_pow2( uintmax_t v )
{
    static_assert( std::numeric_limits< unsigned char >::digits == 8, "" );
    static_assert( sizeof( v ) == 8, "" );
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

class thorp_shuffle
{
private:
    typedef aes128_t block_cipher_t;

public:
    thorp_shuffle( uintmax_t domain_size, std::string const & raw_key )
        : _domain_size( domain_size )
        , _target_bits( 1 )
        , _source_bits( int_log2( up_to_pow2( domain_size) ) - _target_bits )
    {
        hmac_t< sha256_t > hash;
        {
            std::array< uint8_t, decltype(hash)::digest_bytes > derived_key;
            hash.set_key( raw_key ).update( "for key" ).final( derived_key.data() );
            //std::cout << "source key: " << tobin( derived_key ) << "\n";
            _source_cipher.set_enc_key( derived_key.data() );
        }
        {
            std::array< uint8_t, decltype(hash)::digest_bytes > derived_key;
            hash.set_key( raw_key ).update( "for round" ).final( derived_key.data() );
            //std::cout << "round key: " << tobin( derived_key ) << "\n";
            _round_cipher.set_enc_key( derived_key.data() );
        }
    }

private:
    typedef std::array< uint8_t, block_cipher_t::block_bytes > block_t;


public:
    uintmax_t operator () ( uintmax_t const & source, size_t const round )
    {
        //std::cout << "thorp_shuffle(): "  << "              round: " << round << "\n";

        block_t const & round_block = round_to_block( round );
        //std::cout << "thorp_shuffle(): "  << "        round block: " << tobin( round_block ) << "\n";

        block_t round_cipher;
        _round_cipher.enc( round_block.data(), round_cipher.data() );
        //std::cout << "thorp_shuffle(): "  << "       round cipher: " << tobin( round_cipher ) << "\n";


        //std::cout << "thorp_shuffle(): "  << "             source: " << source << "\n";

        block_t const & source_block = source_to_block( source );
        //std::cout << "thorp_shuffle(): "  << "       source block: " << tobin( source_block ) << "\n";

        block_t masked_source_block = source_block ^ round_cipher;
        //std::cout << "thorp_shuffle(): "  << "masked source block: " << tobin( masked_source_block ) << "\n";

        block_t target_block;
        _round_cipher.enc( masked_source_block.data(), target_block.data() );
        //std::cout << "thorp_shuffle(): "  << "      source cipher: " << tobin( target_block ) << "\n";

        uintmax_t const target = block_to_target( target_block );
        //std::cout << "thorp_shuffle(): "  << "        full target: " << target << "\n";

        uintmax_t const target_bit = target & uintmax_t(1);
        //std::cout << "thorp_shuffle(): "  << "             target: " << target_bit << "\n";

        return target_bit;
    }

    uintmax_t get_domain_size() const
    {
        return _domain_size;
    }

    uintmax_t get_source_bits() const
    {
        return _source_bits;
    }

    uintmax_t get_target_bits() const
    {
        return _target_bits;
    }

private:
    block_t round_to_block( size_t const round )
    {
        block_t block;
        std::fill( block.begin(), block.end(), 0 );

        static_assert( sizeof( block ) >= sizeof( round ), "" );
        for( size_t i = 0; i < sizeof( round ); ++i )
        {
            block[ i ] = ( round >> ( i * bits_in_byte ) ) & 0xff;
        }

        return block;
    }

    block_t source_to_block( uintmax_t const source )
    {
        block_t block;
        std::fill( block.begin(), block.end(), 0 );

        static_assert( sizeof( block ) >= sizeof( source ), "" );
        static_assert( std::is_same< block_t::value_type, uint8_t >::value, "" );
        for( size_t i = 0; i < sizeof( source ); ++i )
        {
            block[ i ] = ( source >> ( i * bits_in_byte ) ) & 0xff;
        }

        return block;
    }

    uintmax_t block_to_target( block_t const & block )
    {
        uintmax_t result = 0;

        static_assert( sizeof( block ) >= sizeof( result ), "" );
        for( size_t i = 0; i < sizeof(result); ++i)
        {
            result |= uintmax_t( block[ i ] ) << ( i * bits_in_byte );
        }

        return result;
    }

private:
    const uintmax_t _domain_size;
    const size_t _target_bits;
    const size_t _source_bits;

    block_cipher_t _source_cipher;
    block_cipher_t _round_cipher;
};

template< class FFunction >
class small_feistel_cipher
{
public:
    typedef FFunction f_function;

public:
    small_feistel_cipher( uintmax_t _domain_size, std::string const & raw_key)
        : _f_function( _domain_size, raw_key )
        , _domain_size( _f_function.get_domain_size() )
        , _source_bits( _f_function.get_source_bits() )
        , _target_bits( _f_function.get_target_bits() )
        , _domain_bits( _source_bits + _target_bits )
    {}


    /// [[target][source]]
    /// [[source][target ^ f_function(source)]]
    uintmax_t encrypt( uintmax_t value )
    {
        if( value >= _domain_size )
        {
            throw std::overflow_error( TO_STR( small_feistel_cipher ) "::" + std::string( __FUNCTION__ ) + ": value is out of domain" );
        }

        do
        {
            for( size_t round = 0; round < _domain_bits * 4; ++round )
            {
                //std::cout << "      value: " << ::tobin( value ) << "\n";

                uintmax_t const source = value & ( ( uintmax_t(1) << _source_bits ) - 1 );
                //std::cout << "     source: " << ::tobin( source ) << "\n";

                uintmax_t target = value >> _source_bits;
                //std::cout << "     target: " << ::tobin( target ) << "\n";

                target ^= _f_function( source, round );
                value = ( source << _target_bits ) | target;
                //std::cout << "     result: " << ::tobin( value ) << "\n";

                //std::cout << "\n";
            }
            if( value >= _domain_size )
            {
                //std::cout << "domain size: " << ::tobin( domain_size ) << "\n";
                //std::cout << "value >= domain size, apply F-function again" << "\n";
            }
        }
        while( value >= _domain_size );


        return value;
    }

    uintmax_t decrypt( uintmax_t value )
    {
        if( value >= _domain_size )
        {
            throw std::overflow_error( TO_STR( small_feistel_cipher ) ": value is out of domain" );
        }

        do
        {
            for( ssize_t round = _domain_bits * 4 - 1; round >= 0; --round )
            {
                //std::cout << "      value: " << ::tobin( value ) << "\n";
                //std::cout << " orig value: " << ::tobin( value ) << "\n";

                //uintmax_t const source = value & ( ( uintmax_t( 1 ) << source_bits ) - 1 );
                uintmax_t const source = value >> _target_bits;
                //std::cout << "     source: " << ::tobin( source ) << "\n";

                uintmax_t target = value & 1;
                //std::cout << "     target: " << ::tobin( target ) << "\n";

                target ^= _f_function( source, round );
                value = source | ( target << _source_bits );
                //std::cout << "     result: " << ::tobin( value ) << "\n";

                //std::cout << "\n";
            }
            if( value >= _domain_size )
            {
                //std::cout << "domain size: " << ::tobin( domain_size ) << "\n";
                //std::cout << "value >= domain size, apply F-function again" << "\n";
            }
        }
        while( value >= _domain_size );
        return value;
    }

private:
    f_function _f_function;
    const uintmax_t _domain_size;
    const size_t _source_bits;
    const size_t _target_bits;
    const size_t _domain_bits;
};

typedef small_feistel_cipher<thorp_shuffle> thorp_feistel_cipher_t;


#endif // CRYPTO

