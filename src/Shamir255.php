<?php

namespace deemru;

class Shamir255
{
    // GF(256) with primitive polynomial 0x11D
    // RFC 6330, Section 5.7.3 (https://www.rfc-editor.org/rfc/rfc6330#section-5.7.3)
    // OCT_EXP[i] = 2 ^ i in GF(256), stored as binary string (510 bytes)
    static private $OCT_EXP =
        "\x01\x02\x04\x08\x10\x20\x40\x80\x1d\x3a\x74\xe8\xcd\x87\x13\x26" .
        "\x4c\x98\x2d\x5a\xb4\x75\xea\xc9\x8f\x03\x06\x0c\x18\x30\x60\xc0" .
        "\x9d\x27\x4e\x9c\x25\x4a\x94\x35\x6a\xd4\xb5\x77\xee\xc1\x9f\x23" .
        "\x46\x8c\x05\x0a\x14\x28\x50\xa0\x5d\xba\x69\xd2\xb9\x6f\xde\xa1" .
        "\x5f\xbe\x61\xc2\x99\x2f\x5e\xbc\x65\xca\x89\x0f\x1e\x3c\x78\xf0" .
        "\xfd\xe7\xd3\xbb\x6b\xd6\xb1\x7f\xfe\xe1\xdf\xa3\x5b\xb6\x71\xe2" .
        "\xd9\xaf\x43\x86\x11\x22\x44\x88\x0d\x1a\x34\x68\xd0\xbd\x67\xce" .
        "\x81\x1f\x3e\x7c\xf8\xed\xc7\x93\x3b\x76\xec\xc5\x97\x33\x66\xcc" .
        "\x85\x17\x2e\x5c\xb8\x6d\xda\xa9\x4f\x9e\x21\x42\x84\x15\x2a\x54" .
        "\xa8\x4d\x9a\x29\x52\xa4\x55\xaa\x49\x92\x39\x72\xe4\xd5\xb7\x73" .
        "\xe6\xd1\xbf\x63\xc6\x91\x3f\x7e\xfc\xe5\xd7\xb3\x7b\xf6\xf1\xff" .
        "\xe3\xdb\xab\x4b\x96\x31\x62\xc4\x95\x37\x6e\xdc\xa5\x57\xae\x41" .
        "\x82\x19\x32\x64\xc8\x8d\x07\x0e\x1c\x38\x70\xe0\xdd\xa7\x53\xa6" .
        "\x51\xa2\x59\xb2\x79\xf2\xf9\xef\xc3\x9b\x2b\x56\xac\x45\x8a\x09" .
        "\x12\x24\x48\x90\x3d\x7a\xf4\xf5\xf7\xf3\xfb\xeb\xcb\x8b\x0b\x16" .
        "\x2c\x58\xb0\x7d\xfa\xe9\xcf\x83\x1b\x36\x6c\xd8\xad\x47\x8e" .
        // Repeat first 255 elements to avoid mod 255 in multiplication
        "\x01\x02\x04\x08\x10\x20\x40\x80\x1d\x3a\x74\xe8\xcd\x87\x13\x26" .
        "\x4c\x98\x2d\x5a\xb4\x75\xea\xc9\x8f\x03\x06\x0c\x18\x30\x60\xc0" .
        "\x9d\x27\x4e\x9c\x25\x4a\x94\x35\x6a\xd4\xb5\x77\xee\xc1\x9f\x23" .
        "\x46\x8c\x05\x0a\x14\x28\x50\xa0\x5d\xba\x69\xd2\xb9\x6f\xde\xa1" .
        "\x5f\xbe\x61\xc2\x99\x2f\x5e\xbc\x65\xca\x89\x0f\x1e\x3c\x78\xf0" .
        "\xfd\xe7\xd3\xbb\x6b\xd6\xb1\x7f\xfe\xe1\xdf\xa3\x5b\xb6\x71\xe2" .
        "\xd9\xaf\x43\x86\x11\x22\x44\x88\x0d\x1a\x34\x68\xd0\xbd\x67\xce" .
        "\x81\x1f\x3e\x7c\xf8\xed\xc7\x93\x3b\x76\xec\xc5\x97\x33\x66\xcc" .
        "\x85\x17\x2e\x5c\xb8\x6d\xda\xa9\x4f\x9e\x21\x42\x84\x15\x2a\x54" .
        "\xa8\x4d\x9a\x29\x52\xa4\x55\xaa\x49\x92\x39\x72\xe4\xd5\xb7\x73" .
        "\xe6\xd1\xbf\x63\xc6\x91\x3f\x7e\xfc\xe5\xd7\xb3\x7b\xf6\xf1\xff" .
        "\xe3\xdb\xab\x4b\x96\x31\x62\xc4\x95\x37\x6e\xdc\xa5\x57\xae\x41" .
        "\x82\x19\x32\x64\xc8\x8d\x07\x0e\x1c\x38\x70\xe0\xdd\xa7\x53\xa6" .
        "\x51\xa2\x59\xb2\x79\xf2\xf9\xef\xc3\x9b\x2b\x56\xac\x45\x8a\x09" .
        "\x12\x24\x48\x90\x3d\x7a\xf4\xf5\xf7\xf3\xfb\xeb\xcb\x8b\x0b\x16" .
        "\x2c\x58\xb0\x7d\xfa\xe9\xcf\x83\x1b\x36\x6c\xd8\xad\x47\x8e";

    // RFC 6330, Section 5.7.2 (https://www.rfc-editor.org/rfc/rfc6330#section-5.7.2)
    // OCT_LOG[x] = i such that OCT_EXP[i] = x, stored as binary string (256 bytes)
    static private $OCT_LOG =
        "\x00\x00\x01\x19\x02\x32\x1a\xc6\x03\xdf\x33\xee\x1b\x68\xc7\x4b" .
        "\x04\x64\xe0\x0e\x34\x8d\xef\x81\x1c\xc1\x69\xf8\xc8\x08\x4c\x71" .
        "\x05\x8a\x65\x2f\xe1\x24\x0f\x21\x35\x93\x8e\xda\xf0\x12\x82\x45" .
        "\x1d\xb5\xc2\x7d\x6a\x27\xf9\xb9\xc9\x9a\x09\x78\x4d\xe4\x72\xa6" .
        "\x06\xbf\x8b\x62\x66\xdd\x30\xfd\xe2\x98\x25\xb3\x10\x91\x22\x88" .
        "\x36\xd0\x94\xce\x8f\x96\xdb\xbd\xf1\xd2\x13\x5c\x83\x38\x46\x40" .
        "\x1e\x42\xb6\xa3\xc3\x48\x7e\x6e\x6b\x3a\x28\x54\xfa\x85\xba\x3d" .
        "\xca\x5e\x9b\x9f\x0a\x15\x79\x2b\x4e\xd4\xe5\xac\x73\xf3\xa7\x57" .
        "\x07\x70\xc0\xf7\x8c\x80\x63\x0d\x67\x4a\xde\xed\x31\xc5\xfe\x18" .
        "\xe3\xa5\x99\x77\x26\xb8\xb4\x7c\x11\x44\x92\xd9\x23\x20\x89\x2e" .
        "\x37\x3f\xd1\x5b\x95\xbc\xcf\xcd\x90\x87\x97\xb2\xdc\xfc\xbe\x61" .
        "\xf2\x56\xd3\xab\x14\x2a\x5d\x9e\x84\x3c\x39\x53\x47\x6d\x41\xa2" .
        "\x1f\x2d\x43\xd8\xb7\x7b\xa4\x76\xc4\x17\x49\xec\x7f\x0c\x6f\xf6" .
        "\x6c\xa1\x3b\x52\x29\x9d\x55\xaa\xfb\x60\x86\xb1\xbb\xcc\x3e\x5a" .
        "\xcb\x59\x5f\xb0\x9c\xa9\xa0\x51\x0b\xf5\x16\xeb\x7a\x75\x2c\xd7" .
        "\x4f\xae\xd5\xe9\xe6\xe7\xad\xe8\x74\xd6\xf4\xea\xa8\x50\x58\xaf";

    /**
     * Multiply two elements in GF(256)
     */
    static private function gf_mul( $a, $b )
    {
        if( $a === 0 || $b === 0 )
            return 0;
        return ord( self::$OCT_EXP[ord( self::$OCT_LOG[$a] ) + ord( self::$OCT_LOG[$b] )] );
    }

    /**
     * Divide two elements in GF(256)
     * Returns false if $b === 0 (should not happen with valid unique x)
     */
    static private function gf_div( $a, $b )
    {
        if( $b === 0 )
            return false;
        if( $a === 0 )
            return 0;
        return ord( self::$OCT_EXP[ord( self::$OCT_LOG[$a] ) - ord( self::$OCT_LOG[$b] ) + 255] );
    }

    /**
     * Get cryptographically secure random bytes
     * @return string|false Random bytes or false if no CSPRNG available
     */
    static private function random( $length )
    {
        if( function_exists( 'random_bytes' ) )
        {
            try
            {
                return random_bytes( $length );
            }
            catch( \Exception $e )
            {
                return false;
            }
        }

        if( function_exists( 'openssl_random_pseudo_bytes' ) )
        {
            $strong = false;
            $random = openssl_random_pseudo_bytes( $length, $strong );
            if( $random !== false && $strong === true )
                return $random;
        }

        if( function_exists( 'mcrypt_create_iv' ) )
        {
            $random = mcrypt_create_iv( $length, MCRYPT_DEV_URANDOM );
            if( $random !== false )
                return $random;
        }

        return false;
    }

    /**
     * Splits a secret into multiple shares.
     *
     * @param string $secret Secret to be shared.
     * @param int    $needed Minimum number of shares required to recover the secret (2..total).
     * @param int    $total  Total number of shares to generate (needed..255).
     *
     * @return array|false Array of shares [ x => y_bytes ] on success, or false on failure.
     */
    static public function share( $secret, $needed, $total )
    {
        $len = strlen( $secret );

        if( $len === 0 )
            return false;

        if( $needed < 2 )
            return false;

        if( $needed > $total )
            return false;

        if( $total > 255 )
            return false;

        // Generate random coefficients for each byte position
        // For each byte j: f_j( x ) = secret[j] + a1[j] * x + a2[j] * x ^ 2 + ... + a_{needed - 1}[j] * x ^ {needed - 1}
        $rndLen = $len * ( $needed - 1 );
        $rnd = self::random( $rndLen );
        if( $rnd === false )
            return false;

        // Precompute OCT_LOG lookups for x values
        $xLogs = [];
        for( $x = 1; $x <= $total; ++$x )
            $xLogs[$x] = ord( self::$OCT_LOG[$x] );

        // Build shares using inline Horner's method
        $shares = [];
        for( $x = 1; $x <= $total; ++$x )
        {
            $xLog = $xLogs[$x];
            $y = '';
            for( $j = 0; $j < $len; ++$j )
            {
                // Horner: start from highest coefficient a_{needed - 1}
                // res = a_{needed - 1}
                // for k = needed - 2 down to 1: res = a_k XOR gf_mul( res, x )
                // res = secret[j] XOR gf_mul( res, x )
                $base = $j * ( $needed - 1 );
                $res = ord( $rnd[$base + $needed - 2] ); // a_{needed-1}

                for( $k = $needed - 3; $k >= 0; --$k )
                {
                    // res = a_{k + 1} XOR gf_mul( res, x )
                    if( $res !== 0 )
                        $res = ord( self::$OCT_EXP[ord( self::$OCT_LOG[$res] ) + $xLog] );
                    $res ^= ord( $rnd[$base + $k] );
                }

                // Final: res = secret[j] XOR gf_mul( res, x )
                if( $res !== 0 )
                    $res = ord( self::$OCT_EXP[ord( self::$OCT_LOG[$res] ) + $xLog] );
                $res ^= ord( $secret[$j] );

                $y .= chr( $res );
            }
            $shares[$x] = $y;
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
        $count = count( $shares );
        if( $count < 2 )
            return false;

        $xs = [];
        $ys = [];
        $len = null;

        foreach( $shares as $x => $y )
        {
            $xi = (int)$x;

            if( $xi < 1 || $xi > 255 )
                return false;

            if( isset( $xs[$xi] ) )
                return false;

            if( !is_string( $y ) )
                return false;

            $ylen = strlen( $y );
            if( $len === null )
            {
                if( $ylen === 0 )
                    return false;
                $len = $ylen;
            }
            else
            if( $ylen !== $len )
                return false;

            $xs[$xi] = $xi;
            $ys[$xi] = $y;
        }

        // Convert to indexed arrays for easier iteration
        $xList = array_values( $xs );
        $yList = array_values( $ys );

        // Precompute Lagrange coefficients for interpolation at x = 0
        // L_i = prod( j != i ) x_j / ( x_j - x_i ) in GF(256)
        $lambdas = [];
        for( $i = 0; $i < $count; ++$i )
        {
            $xi = $xList[$i];
            $num = 1;
            $den = 1;
            for( $j = 0; $j < $count; ++$j )
            {
                if( $i === $j )
                    continue;
                $xj = $xList[$j];
                $num = self::gf_mul( $num, $xj );
                $den = self::gf_mul( $den, $xj ^ $xi ); // x_j - x_i = x_j XOR x_i in GF(256)
            }
            $lambda = self::gf_div( $num, $den );
            if( $lambda === false )
                return false;
            $lambdas[$i] = $lambda;
        }

        // Interpolate each byte position
        $secret = '';
        for( $j = 0; $j < $len; ++$j )
        {
            $sj = 0;
            for( $i = 0; $i < $count; ++$i )
                $sj ^= self::gf_mul( ord( $yList[$i][$j] ), $lambdas[$i] );
            $secret .= chr( $sj );
        }

        return $secret;
    }
}
