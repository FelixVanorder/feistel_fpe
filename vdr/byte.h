#ifndef INCLUDED__VDR_BYTE_H
#define INCLUDED__VDR_BYTE_H

#ifndef __byte_t_defined

#include <cstdint>
#include <limits>
#include <type_traits>

typedef std::uint8_t byte_t;

#endif // __byte_t_defined


#ifndef __sbyte_t_defined
typedef std::make_signed< byte_t >::type sbyte_t;
#endif // __sbyte_t_defined


static_assert(
		std::numeric_limits< byte_t >::is_signed == false
		and
		std::numeric_limits< byte_t >::digits == 8, 
		"Byte must be an unsigned integer type of 8 bits." 
	);

static_assert(
		std::numeric_limits< sbyte_t >::is_signed == true
		and
		std::numeric_limits< sbyte_t >::digits == 7, 
		"SByte must be a signed integer type of valuable 7 bits." 
	);





#endif // INCLUDED__VDR_BYTE_H