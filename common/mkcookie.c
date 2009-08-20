#include "config.h"

#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>

#include "fbase64.h"
#include "mkcookie.h"

static char	valid_tab[ 256 ] = {
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 1, 1, 0,	/*             '+'     '-' '.'     */
 1, 1, 1, 1, 1, 1, 1, 1,	/* '0' '1' '2' '3' '4' '5' '6' '7' */
 1, 1, 0, 0, 0, 1, 0, 0,	/* '8' '9'             '='         */
 1, 1, 1, 1, 1, 1, 1, 1,	/* '@' 'A' 'B' 'C' 'D' 'E' 'F' 'G' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'H' 'I' 'J' 'K' 'L' 'M' 'N' 'O' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'P' 'Q' 'R' 'S' 'T' 'U' 'V' 'W' */
 1, 1, 1, 0, 0, 0, 0, 1,	/* 'X' 'Y' 'Z'                 '_' */
 0, 1, 1, 1, 1, 1, 1, 1,	/*     'a' 'b' 'c' 'd' 'e' 'f' 'g' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'p' 'q' 'r' 's' 't' 'u' 'v' 'w' */
 1, 1, 1, 0, 0, 0, 0, 0,	/* 'x' 'y' 'z'                     */
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
};

    int
validchars( char *s )
{
    char	*p;

    for ( p = s; *p != '\0'; p++ ) {
	if ( !valid_tab[ (unsigned char)*p ] ) {
	    return( 0 );
	}
    }
    return( 1 );
}

    int
mkcookie( int len, char *buf )
{
    unsigned char	tmp[ 1024 ];
    int			randbytes;			

    len -= 3; /* XXX why? */
    randbytes = SZ_FBASE64_D( len );
    if (( randbytes <= 0 ) || ( randbytes > sizeof( tmp ))) {
	return( -1 );
    }

    if ( RAND_bytes( tmp, randbytes ) != 1 ) {
        return( -2 );
    }

    fbase64_e( tmp, randbytes, buf );
    return( 0 );
}
