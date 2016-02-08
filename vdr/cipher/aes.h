#ifndef INCLUDED__VDR_CIPHER_AES_H
#define INCLUDED__VDR_CIPHER_AES_H

#include "microsoft/gsl.h"
#include "vdr/wipe.h"

#include <openssl/aes.h>

namespace vdr
{
    namespace cipher
    {

        template< size_t KeyBits = 128 >
        class aes
        {
            static_assert( KeyBits == 128 or KeyBits == 192 or KeyBits == 256, "Byte must be an 8-bit value." );

        public:
            enum : size_t { key_bits = KeyBits };
            enum : size_t { key_bytes = key_bits / 8 };
            enum : size_t { block_bytes = AES_BLOCK_SIZE };
            enum : size_t { block_bits = block_bytes * 8 };
        
        public:
            typedef std::array< gsl::byte, key_bytes > key_arr;
            typedef std::array< gsl::byte, block_bytes > block_arr;

        public:
            aes();
            ~aes();

            aes & set_enc_key( gsl::span< gsl::byte const, key_bytes > enckey );
            aes & set_dec_key( gsl::span< gsl::byte const, key_bytes > deckey );

            aes & enc( gsl::span< gsl::byte const, block_bytes > in, gsl::span< gsl::byte, block_bytes > out );
            aes & dec( gsl::span< gsl::byte const, block_bytes > in, gsl::span< gsl::byte, block_bytes > out );

            aes & clear();

        public:
            static constexpr key_arr get_empty_key() { return key_arr{}; }
            static constexpr block_arr get_empty_block() { return block_arr{}; }

            static constexpr size_t get_key_bits() { return key_bits; }
            static constexpr size_t get_key_bytes() { return key_bytes; }
            static constexpr size_t get_block_bytes() { return block_bytes; }
            static constexpr size_t get_block_bits() { return block_bits; }

        private:
            AES_KEY _key;

        };

        typedef aes<128> aes128;

    }
}


namespace vdr
{
    namespace cipher
    {

        namespace
        { 
            namespace openssl
            {
                enum : int { success = 0 };
                enum : int { failure = 1 };
            }
        }

        template< size_t KeyBits >
        aes<KeyBits>::aes()
        {
            clear();
        }

        
        template< size_t KeyBits >
        aes<KeyBits>::~aes()
        {
            clear();
        }


        template< size_t KeyBits >
        aes<KeyBits> & 
        aes<KeyBits>::set_enc_key( gsl::span< gsl::byte const, key_bytes > enckey )
        {
            if( openssl::failure == AES_set_encrypt_key( reinterpret_cast< unsigned char const * >( enckey.data() ), enckey.size_bytes() * 8, &_key ) )
            {
                throw std::runtime_error("Can't set encryption AES key.");
            }
            return *this;
        }



        template< size_t KeyBits >
        aes<KeyBits> & 
        aes<KeyBits>::set_dec_key( gsl::span< gsl::byte const, key_bytes > deckey )
        {
            if( openssl::failure == AES_set_decrypt_key( reinterpret_cast< unsigned char const * >( deckey.data() ), deckey.size_bytes() * 8, &_key ) )
            {
                throw std::runtime_error("Can't set decrypion AES key.");
            }
            return *this;
        }

        template< size_t KeyBits >
        aes<KeyBits> & 
        aes<KeyBits>::enc( gsl::span< gsl::byte const, block_bytes > in, gsl::span< gsl::byte, block_bytes > out )
        {
            AES_encrypt( 
                reinterpret_cast< unsigned char const * >( in.data() ), 
                reinterpret_cast< unsigned char * >( out.data() ),
                &_key
            );
            return *this;
        }

        template< size_t KeyBits >
        aes<KeyBits> & 
        aes<KeyBits>::dec( gsl::span< gsl::byte const, block_bytes > in, gsl::span< gsl::byte, block_bytes > out )
        {
            AES_decrypt( 
                reinterpret_cast< unsigned char const * >( in.data() ),
                reinterpret_cast< unsigned char * >( out.data() ), 
                &_key
            );
            return *this;
        }

        template< size_t KeyBits >
        aes<KeyBits> & 
        aes<KeyBits>::clear()
        {
            vdr::wipe( gsl::as_writeable_bytes( gsl::as_span( &_key, 1 ) ) );
            {
                // NOTE: Following is just in case, if somebody will `enc`/`dec` something right
                //   after `clear`. Not sure if all will be ok in this case after zerofying AES_KEY.
                std::array< gsl::byte, aes<KeyBits>::key_bytes > zero_key{};
                this->set_enc_key( zero_key ); 
            }
            return *this;
        }


    }
}


#endif // INCLUDED__VDR_CIPHER_AES_H