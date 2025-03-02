<?php

namespace deemru;

if( !function_exists( 'random_bytes' ) )
{
    function random_bytes( $length )
    {
        if( function_exists( 'openssl_random_pseudo_bytes' ) )
        {
            $strong = false;
            $random = openssl_random_pseudo_bytes( $length, $strong );
            if( $random !== false && $strong === true)
                return $random;
        }
        
        if( function_exists( 'mcrypt_create_iv' ) )
        {
            $random = mcrypt_create_iv( $length );
            if( $random !== false )
                return $random;
        }
        
        $random = '';
        for( $i = 0; $i < $length; ++$i )
            $random .= chr( mt_rand( 0, 255 ) );
        return $random;
    }
}

class Shamir255
{
    static private $prime;
    static private function init()
    {
        if( !isset( self::$prime ) )
        {
            // 2048-bit MODP Group @ https://www.ietf.org/rfc/rfc3526.html#section-3
            self::$prime = gmp_init( '
                FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
                29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
                EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
                E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
                EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
                C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
                83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
                670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
                E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
                DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
                15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
            ', 16 );
        }
    }

    static private function coefficient()
    {
        for( ;; )
        {
            $coefficient = gmp_init( bin2hex( random_bytes( 256 ) ), 16 );
            if( gmp_sign( gmp_sub( self::$prime, $coefficient ) ) === 1 )
                return $coefficient;
        }
    }

    /**
     * Splits a secret into multiple shares.
     *
     * @param string $secret Secret to be shared.
     * @param int    $needed Minimum number of shares required to recover the secret.
     * @param int    $total  Total number of shares to generate.
     *
     * @return array|false Array of shares on success, or false on failure.
     */
    static public function share( $secret, $needed, $total )
    {
        if( strlen( $secret ) > 255 )
            return false;

        if( $needed > $total )
            return false;

        if( $needed < 2 )
            return false;

        self::init();

        $secret = gmp_init( bin2hex( 'S' . $secret ), 16 );
        $coefficients = [ $secret ];
        for( $i = 1; $i < $needed; $i++ )
            $coefficients[] = self::coefficient();

        $shares = [];
        for( $x = 1; $x <= $total; ++$x )
        {
            $y = gmp_init( '0' );
            for( $i = 0; $i < $needed; $i++ )
                $y = gmp_add( $y, gmp_mul( $coefficients[$i], gmp_pow( $x, $i ) ) );
            $y = gmp_mod( $y, self::$prime );
            $y = str_pad( gmp_strval( $y, 16 ), 512, '0', STR_PAD_LEFT );
            $shares[$x] = hex2bin( $y );
        }

        return $shares;
    }

    /**
    * Recovers the original secret from a set of shares.
    *
    * @param array $shares Array of shares with X => Y.
    *
    * @return string|false Recovered secret on success, or false on failure.
    */
    static public function recover( $shares )
    {
        self::init();

        $secret = gmp_init( '0' );
        $runners = $shares;
        foreach( $shares as $xi => $yi )
        {
            $numerator = 1;
            $denominator = 1;
            foreach( $runners as $xj => $_ )
                if( $xi != $xj )
                {
                    $numerator = gmp_mul( $numerator, -$xj );
                    $denominator = gmp_mul( $denominator, $xi - $xj );
                }
            $lagrange_coefficient = gmp_mod( gmp_mul( $numerator, gmp_invert( $denominator, self::$prime ) ), self::$prime );
            $term = gmp_mod( gmp_mul( gmp_init( bin2hex( $yi ), 16 ), $lagrange_coefficient ), self::$prime );
            $secret = gmp_mod( gmp_add( $secret, $term ), self::$prime );
        }

        $secret = gmp_strval( $secret, 16 );
        $secretlen = strlen( $secret );
        if( $secretlen < 2 || $secretlen % 2 !== 0 )
            return false;
        $secret = hex2bin( $secret );
        if( $secret[0] !== 'S' )
            return false;
        return substr( $secret, 1 );
    }
}
