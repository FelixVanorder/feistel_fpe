#ifndef INCLUDED__VDR_MAC_HMAC_H
#define INCLUDED__VDR_MAC_HMAC_H


#include <algorithm>
#include <array>

#include "microsoft/gsl.h"

#include "vdr/wipe.h"


namespace vdr
{
    namespace mac
    {
        template<class Hash>
        class hmac
        {
        public:
            enum : size_t {
                digest_bytes = Hash::digest_bytes,
                digest_bits = Hash::digest_bits,
                block_bytes = Hash::block_bytes,
                block_bits = Hash::block_bits,
            };

        public:
            typedef std::array< gsl::byte, digest_bytes > digest_arr;
            typedef std::array< gsl::byte, block_bytes > block_arr;

        public:
            hmac();
            hmac( gsl::span< gsl::byte const > rawkey );
            ~hmac();

            hmac & operator << ( gsl::span< gsl::byte const > input  );
            void   operator >> ( gsl::span< gsl::byte, digest_bytes > output );

            void clear();

        public:
            static digest_arr get_empty_digest() { return digest_arr(); }
            static block_arr get_empty_block() { return block_arr(); }

            static constexpr size_t digest_size_bytes() { return digest_bytes; }
            static constexpr size_t digest_size_bits() { return digest_bits; }
            static constexpr size_t block_size_bytes() { return block_bytes; }
            static constexpr size_t block_size_bits() { return block_bits; }


        private:
            Hash _hash;
            std::array<gsl::byte, Hash::block_bytes> _key;
        };

    }
}


namespace vdr
{
    namespace mac
    {



        namespace
        {
            template< class Value >
            void clear_var( Value & value )
            {
                value = Value();
            }

            static constexpr auto const inner_pad = gsl::byte(0x36);
            static constexpr auto const outer_pad = gsl::byte(0x5C);

            gsl::byte operator ^ ( gsl::byte const lhs, gsl::byte const rhs )
            {
                return gsl::byte( static_cast< uint8_t >( lhs ) ^ static_cast< uint8_t >( rhs ) );
            }

            gsl::byte & operator ^= ( gsl::byte & lhs, gsl::byte const rhs )
            {
                lhs = gsl::byte( static_cast< uint8_t >( lhs ) ^ static_cast< uint8_t >( rhs ) );
                return lhs;
            }
        }



        template< class Hash >
        hmac< Hash >::hmac()
        {
            std::fill( _key.begin(), _key.end(), inner_pad );
        }


        template< class Hash >
        hmac< Hash >::hmac( gsl::span< gsl::byte const > rawkey )
        {
            if( rawkey.size_bytes() > _key.size() )
            {
                _hash << rawkey >> _key;
                auto nonempty_key_span = gsl::as_span( _key ).first( _hash.digest_size_bytes() );
                auto empty_key_span = gsl::as_span( _key ).subspan( _hash.digest_size_bytes() );

                std::for_each(
                    nonempty_key_span.begin(), nonempty_key_span.end(),
                    []( gsl::byte & byte ) { byte ^= inner_pad; }
                );

                std::fill( empty_key_span.begin(), empty_key_span.end(), inner_pad );
            }
            else
            {
                auto nonempty_end = std::transform(
                    rawkey.begin(), rawkey.end(),
                    _key.begin(),
                    []( gsl::byte const byte ) { return byte ^ inner_pad; }
                );
                std::fill( nonempty_end, _key.end(), inner_pad );
            }
            _hash << _key;
        }


        template< class Hash >
        hmac< Hash >::~hmac()
        {
            vdr::wipe( _key );
        }


        template< class Hash >
        hmac< Hash > & hmac< Hash >::operator << ( gsl::span< gsl::byte const > input )
        {
            _hash << input;
            return *this;
        }

        template< class Hash >
        void hmac< Hash >::operator >> ( gsl::span< gsl::byte, digest_bytes > output )
        {
            {
                {
                    std::array<gsl::byte, Hash::digest_bytes> inner_hash;
                    _hash >> inner_hash;

                    std::for_each(
                        _key.begin(), _key.end(),
                        []( gsl::byte & byte ) { byte ^= inner_pad ^ outer_pad; }
                    );

                    _hash << _key << inner_hash;
                    vdr::wipe( inner_hash );
                }
                _hash >> output;
            }

            std::for_each(
                _key.begin(), _key.end(),
                []( gsl::byte & byte ) { byte ^= outer_pad ^ inner_pad; }
            );

            _hash << _key;
        }

        template< class Hash >
        void hmac<Hash>::clear()
        {
            _hash.clear();
            _hash << _key;
        }
    }
}


#endif // INCLUDED__VDR_MAC_HMAC_H