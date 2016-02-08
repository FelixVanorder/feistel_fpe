#ifndef INCLUDED__VDR_WIPE_H
#define INCLUDED__VDR_WIPE_H


#include <algorithm>

#include "microsoft/gsl.h"

#include "vdr/byte.h"



namespace vdr
{
	namespace // Speical thanks to Chandler Carruth (@chandlerc1024)! (CppCon 2015 -- Tuning C++: Benchmarks, and CPUs, and Compilers! Oh My!)
	{			
		static void enforce_presence( void * p )
		{
			asm volatile( "" : : "g"(p) : "memory" );
		}

		static void clobber()
		{
			asm volatile( "" : : : "memory" );
		}
	}


	inline void wipe( gsl::span< gsl::byte > secret )
	{
		enforce_presence( secret.data() );
		std::fill( std::begin(secret), std::end(secret), gsl::byte(0) );
		clobber();
	}
}


#endif // INCLUDED__VDR_WIPE_H