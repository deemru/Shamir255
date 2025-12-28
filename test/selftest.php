<?php

use deemru\Shamir255;

require __DIR__ . '/../vendor/autoload.php';

$sensitive = 'Hello, world!';
$needed = 2;
$total = 3;
$shares = Shamir255::share( $sensitive, $needed, $total );
assert( $sensitive === Shamir255::recover( [ 1 => $shares[1], 2 => $shares[2] ] ) );

class tester
{
    private $successful = 0;
    private $failed = 0;
    private $depth = 0;
    private $info = [];
    private $start = [];
    private $init;

    public function pretest( $info )
    {
        $this->info[$this->depth] = $info;
        $this->start[$this->depth] = microtime( true );
        if( !isset( $this->init ) )
            $this->init = $this->start[$this->depth];
        $this->depth++;
    }

    private function ms( $start )
    {
        $ms = ( microtime( true ) - $start ) * 1000;
        $ms = $ms > 100 ? round( $ms ) : $ms;
        $ms = sprintf( $ms > 10 ? ( $ms > 100 ? '%.00f' : '%.01f' ) : '%.02f', $ms );
        return $ms;
    }

    public function test( $cond )
    {
        $this->depth--;
        $ms = $this->ms( $this->start[$this->depth] );
        echo ( $cond ? 'SUCCESS: ' : 'ERROR:   ' ) . "{$this->info[$this->depth]} ($ms ms)\n";
        $cond ? $this->successful++ : $this->failed++;
    }

    public function finish()
    {
        $total = $this->successful + $this->failed;
        $ms = $this->ms( $this->init );
        echo "  TOTAL: {$this->successful}/$total ($ms ms)\n";
        sleep( 3 );

        if( $this->failed > 0 )
            exit( 1 );
    }
}

if( !function_exists( 'random_bytes' ) ){ function random_bytes( $size ){ $rnd = ''; while( $size-- ) $rnd .= chr( mt_rand() ); return $rnd; } }

echo "   TEST: Shamir255\n";
$t = new tester();

// === Negative tests ===

$t->pretest( 'empty' );
{
    $t->test( false === Shamir255::share( '', 2, 3 ) );
}

$t->pretest( 'needed < 2' );
{
    $t->test( false === Shamir255::share( 'test', 1, 3 ) );
}

$t->pretest( 'needed > total' );
{
    $t->test( false === Shamir255::share( 'test', 5, 3 ) );
}

$t->pretest( 'total > 255' );
{
    $t->test( false === Shamir255::share( 'test', 2, 256 ) );
}

$t->pretest( 'recover < 2' );
{
    $shares = Shamir255::share( 'test', 2, 3 );
    $t->test( false === Shamir255::recover( [ 1 => $shares[1] ] ) );
}

$t->pretest( 'recover x = 0' );
{
    $t->test( false === Shamir255::recover( [ 0 => 'test', 1 => 'test' ] ) );
}

$t->pretest( 'recover x > 255' );
{
    $t->test( false === Shamir255::recover( [ 256 => 'test', 1 => 'test' ] ) );
}

$t->pretest( 'recover different lengths' );
{
    $t->test( false === Shamir255::recover( [ 1 => 'test', 2 => 'longer' ] ) );
}

$t->pretest( 'recover non-string y' );
{
    $ok = ( false === Shamir255::recover( [ 1 => 'test', 2 => 12345 ] ) );
    $ok = $ok && ( false === Shamir255::recover( [ 1 => 'test', 2 => [ 'array' ] ] ) );
    $t->test( $ok );
}

// === Positive tests ===

$t->pretest( 'predefined' );
{
    $sensitive = 'Hello, world!';
    $combine =
    [
        3 => hex2bin( '3285dc7e245cf938d15ca186d0' ),
        7 => hex2bin( 'bcc9468ab6817877f565c39cc7' ),
        9 => hex2bin( 'faae632ae7ef520264b4962108' ),
    ];
    $t->test( $sensitive === Shamir255::recover( $combine ) );
}

$t->pretest( 'string keys' );
{
    $secret = 'String keys test';
    $shares = Shamir255::share( $secret, 2, 3 );
    $stringShares = [ '1' => $shares[1], '3' => $shares[3] ];
    $recovered = Shamir255::recover( $stringShares );
    $t->test( $secret === $recovered );
}

$t->pretest( 'length equals' );
{
    $secret = 'test123';
    $shares = Shamir255::share( $secret, 2, 3 );
    $ok = true;
    foreach( $shares as $share )
        if( strlen( $share ) !== strlen( $secret ) )
            $ok = false;
    $t->test( $ok );
}

$t->pretest( 'single byte secret' );
{
    $secret = 'X';
    $shares = Shamir255::share( $secret, 2, 3 );
    $recovered = Shamir255::recover( [ 1 => $shares[1], 3 => $shares[3] ] );
    $t->test( $secret === $recovered );
}

$t->pretest( 'secret with 0x00' );
{
    $secret = "\x00\x00\xFF\x00\xAB";
    $shares = Shamir255::share( $secret, 2, 3 );
    $recovered = Shamir255::recover( [ 2 => $shares[2], 3 => $shares[3] ] );
    $t->test( $secret === $recovered );
}

$t->pretest( 'all 0x00 secret' );
{
    $secret = str_repeat( "\x00", rand( 32, 128 ) );
    $shares = Shamir255::share( $secret, 2, 3 );
    $recovered = Shamir255::recover( [ 1 => $shares[1], 2 => $shares[2] ] );
    $t->test( $secret === $recovered );
}

$t->pretest( 'all 0xFF secret' );
{
    $secret = str_repeat( "\xFF", rand( 32, 128 ) );
    $shares = Shamir255::share( $secret, 2, 3 );
    $recovered = Shamir255::recover( [ 1 => $shares[1], 2 => $shares[2] ] );
    $t->test( $secret === $recovered );
}

$t->pretest( '3 of 3' );
{
    $secret = 'secret';
    $shares = Shamir255::share( $secret, 3, 3 );
    $recovered = Shamir255::recover( $shares );
    $t->test( $secret === $recovered );
}

$t->pretest( '2 of 5' );
{
    $secret = 'minimal threshold';
    $shares = Shamir255::share( $secret, 2, 5 );
    $recovered = Shamir255::recover( [ 3 => $shares[3], 5 => $shares[5] ] );
    $t->test( $secret === $recovered );
}

$t->pretest( '5 of 7' );
{
    $secret = 'higher threshold test';
    $shares = Shamir255::share( $secret, 5, 7 );
    $recovered = Shamir255::recover( [
        1 => $shares[1],
        3 => $shares[3],
        4 => $shares[4],
        6 => $shares[6],
        7 => $shares[7],
    ] );
    $t->test( $secret === $recovered );
}

$t->pretest( '2 but 3 of 5' );
{
    $secret = 'secret data';
    $shares = Shamir255::share( $secret, 3, 5 );
    $wrong = Shamir255::recover( [ 1 => $shares[1], 2 => $shares[2] ] );
    $t->test( $wrong !== $secret );
}

$t->pretest( '2 of 255' );
{
    $secret = 'max shares test';
    $shares = Shamir255::share( $secret, 2, 255 );
    $recovered = Shamir255::recover( [ 1 => $shares[1], 255 => $shares[255] ] );
    $t->test( $secret === $recovered && count( $shares ) === 255 );
}

$t->pretest( 'large secret (4 KiB)' );
{
    $secret = random_bytes( 4096 );
    $shares = Shamir255::share( $secret, 3, 5 );
    $recovered = Shamir255::recover( [ 1 => $shares[1], 3 => $shares[3], 5 => $shares[5] ] );
    $t->test( $secret === $recovered );
}

$t->pretest( 'all 3 of 5' );
{
    $secret = 'TEST';
    $shares = Shamir255::share( $secret, 3, 5 );

    $combos =
    [
        [ 1, 2, 3 ], [ 1, 2, 4 ], [ 1, 2, 5 ], [ 1, 3, 4 ], [ 1, 3, 5 ],
        [ 1, 4, 5 ], [ 2, 3, 4 ], [ 2, 3, 5 ], [ 2, 4, 5 ], [ 3, 4, 5 ],
    ];

    $ok = true;
    foreach( $combos as $c )
        $ok = $ok && ( $secret === Shamir255::recover( [ $c[0] => $shares[$c[0]], $c[1] => $shares[$c[1]], $c[2] => $shares[$c[2]] ] ) );

    $t->test( $ok );
}

$t->pretest( 'share complex' );
{
    $result = true;
    $tt = microtime( true );
    for( $i = 0;; ++$i )
    {
        $length = mt_rand( 1, 255 );
        $secret = random_bytes( $length );

        $needed = mt_rand( 2, 10 );
        $total = $needed + mt_rand( 0, 10 );

        $shares = Shamir255::share( $secret, $needed, $total );
        if( $shares === false )
        {
            $result = false;
            break;
        }

        $numbers = range( 1, $total );
        shuffle( $numbers );
        $combines = [];
        for( $j = 0; $j < $needed; ++$j )
            $combines[$numbers[$j]] = $shares[$numbers[$j]];

        if( $secret !== Shamir255::recover( $combines ) )
        {
            $result = false;
            break;
        }

        if( microtime( true ) - $tt > 1 )
            break;
    }
    echo "   TEST: $i times\n";
    $t->test( $result );
}

$t->finish();
