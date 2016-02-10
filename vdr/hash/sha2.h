#ifndef INCLUDED__VDR_HASH_SHA2_H
#define INCLUDED__VDR_HASH_SHA2_H


#include <openssl/sha.h>

#include "microsoft/gsl.h"

#include "vdr/byte.h"
#include "vdr/wipe.h"


namespace vdr
{
    namespace hash
    {
        class sha256
        {
        public:
            enum : size_t {
                digest_bytes = SHA256_DIGEST_LENGTH,
                digest_bits = digest_bytes * std::numeric_limits< gsl::byte >::digits,
                block_bytes = SHA256_CBLOCK,
                block_bits = block_bytes * std::numeric_limits< gsl::byte >::digits,
            };

        public:
            typedef std::array< gsl::byte, digest_bytes > digest_arr;
            typedef std::array< gsl::byte, block_bytes > block_arr;

        public:
            sha256();
            ~sha256();

            sha256( gsl::span< gsl::byte const > input );

            sha256 & operator << ( gsl::span< gsl::byte const >         input  );
            void     operator >> ( gsl::span< gsl::byte, digest_bytes > output );

            void clear();

        public:
            static digest_arr get_empty_digest() { return digest_arr(); }
            static block_arr get_empty_block() { return block_arr(); }
            
            static constexpr size_t digest_size_bytes() { return digest_bytes; }
            static constexpr size_t digest_size_bits() { return digest_bits; }
            static constexpr size_t block_size_bytes() { return block_bytes; }
            static constexpr size_t block_size_bits() { return block_bits; }

        private:
            void wipe_context();

        private:
            SHA256_CTX _ctx;
        };

    }

}






namespace vdr
{
    namespace hash
    {

        sha256::sha256()
        {
            clear();
        }


        void sha256::wipe_context()
        {
            vdr::wipe( { reinterpret_cast< gsl::byte* >( &_ctx ), sizeof( _ctx ) } );
        }

        sha256::~sha256()
        {
            wipe_context();
        }

        sha256::sha256( gsl::span< gsl::byte const > input )
        {
            *this << input;
        }

        namespace
        {
            namespace openssl
            {
                enum : int { success = 1 };
                enum : int { failure = 0 };
            }
        }

        sha256 & sha256::operator << ( gsl::span< gsl::byte const > input )
        {
            if( openssl::failure == SHA256_Update( &_ctx, input.data(), input.size_bytes() ) )
            {
                throw std::runtime_error("Can't update SHA-256.");
            }
            return *this;
        }

        void sha256::operator >> ( gsl::span< gsl::byte, digest_bytes > output )
        {
            Expects( output.size_bytes() >= digest_bytes );

            if( openssl::failure == SHA256_Final( reinterpret_cast< unsigned char * >( output.data() ), &_ctx ) )
            {
                throw std::runtime_error("Can't finalize SHA-256.");
            }
            clear();
        }

        void sha256::clear()
        {
            wipe_context();
            if( openssl::failure == SHA256_Init( &_ctx ) )
            {
                throw std::runtime_error("Can't init SHA-256.");
            }
        }

    }
}


#endif // INCLUDED__VDR_HASH_SHA2_H