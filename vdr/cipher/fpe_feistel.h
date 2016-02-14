#ifndef INCLUDED__VDR_CIPHER_FPE_FEISTEL_H
#define INCLUDED__VDR_CIPHER_FPE_FEISTEL_H

#include "vdr/cipher/aes.h"
#include "vdr/mac/hmac.h"
#include "vdr/hash/sha2.h"

namespace vdr
{
    namespace cipher
    {


        namespace
        {

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
            typedef vdr::cipher::aes128 block_cipher_t;

        public:
            thorp_shuffle( uintmax_t domain_size, std::string const & raw_key )
                : _domain_size( domain_size )
                , _target_bits( 1 )
                , _source_bits( int_log2( up_to_pow2( domain_size) ) - _target_bits )
            {
                vdr::mac::hmac< vdr::hash::sha256 > mac( gsl::as_bytes( gsl::as_span(raw_key) ) );
                {
                    auto derived_key = mac.get_empty_digest();
                    mac
                        << gsl::as_bytes( gsl::ensure_z("for key") )
                        >> derived_key;
                    //std::cout << "source key: " << tobin( derived_key ) << "\n";
                    _source_cipher.set_enc_key( derived_key );
                    vdr::wipe( derived_key );
                }
                {
                    auto derived_key = mac.get_empty_digest();
                    mac
                        << gsl::as_bytes( gsl::ensure_z("for round") )
                        >> derived_key;
                    //std::cout << "round key: " << tobin( derived_key ) << "\n";
                    _round_cipher.set_enc_key( derived_key );
                    vdr::wipe( derived_key );
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
                _round_cipher.enc( gsl::as_bytes( gsl::as_span( round_block ) ), gsl::as_writeable_bytes( gsl::as_span( round_cipher ) ) );
                //std::cout << "thorp_shuffle(): "  << "       round cipher: " << tobin( round_cipher ) << "\n";


                //std::cout << "thorp_shuffle(): "  << "             source: " << source << "\n";

                block_t const & source_block = source_to_block( source );
                //std::cout << "thorp_shuffle(): "  << "       source block: " << tobin( source_block ) << "\n";

                block_t masked_source_block = source_block ^ round_cipher;
                //std::cout << "thorp_shuffle(): "  << "masked source block: " << tobin( masked_source_block ) << "\n";

                block_t target_block;
                _source_cipher.enc( gsl::as_bytes( gsl::as_span( masked_source_block ) ), gsl::as_writeable_bytes( gsl::as_span( target_block ) ) );
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

                        uintmax_t target = value & ( ( uintmax_t(1) << _target_bits ) - 1 );
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



    }
}






#endif // INCLUDED__VDR_CIPHER_FPE_FEISTEL_H