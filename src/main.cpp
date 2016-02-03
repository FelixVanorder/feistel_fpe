#include <iostream>
#include <iomanip>

#include "feistel_fpe.hpp"


int main()
{
	std::cout << "Test Format Preserving Feistel Cipher: \n";


	enum { domain_size = 17 };
	thorp_feistel_cipher_t feistel( domain_size, "secret key" );
	
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

	return 0;
}