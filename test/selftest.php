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

$t->pretest( 'share empty' );
{
    $t->test( true === proc( '', 2, 3 ) );
}

$t->pretest( 'share max' );
{
    $t->test( true === proc( str_repeat( chr( 255 ), 255 ), 2, 3 ) );
}

$t->pretest( 'share over max' );
{
    $t->test( false === proc( str_repeat( chr( 255 ), 256 ), 2, 3 ) );
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

        $result &= proc( $secret, $needed, $total );

        if( microtime( true ) - $tt > 1 )
            break;
    }
    echo "   TEST: $i times\n";
    $t->test( $result );
}

$t->finish();

function proc( $secret, $needed, $total )
{
    $shares = Shamir255::share( $secret, $needed, $total );
    if( $shares === false )
        return false;

    foreach( $shares as $share )
        if( strlen( $share ) !== 256 )
            return false;

    $numbers = [];
    for( $i = 1; $i <= $total; ++$i )
        $numbers[] = $i;
    shuffle( $numbers );

    $combines = [];
    for( $i = 0; $i < $needed; ++$i )
    {
        $number = $numbers[$i];
        $combines[$number] = $shares[$number];
    }

    return $secret === Shamir255::recover( $combines );
}
