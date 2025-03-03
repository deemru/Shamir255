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

$t->pretest( 'predefined' );
{
    $sensitive = 'Hello, world!';
    $combine =
    [
        3 => hex2bin( '90f675126eac8d19c2ac2758e4edf396adac7397a882237bcb65431ab5218baface402d02e6c0f73cc5aa5c21700068a4cbdea78437bde260c86ec992e8a696190ad06db06f26d66768620115786ba32df8b4abbe4d9a1baea83c77167c73089582ac3edc5bb982057d18a5964281786762e44300425353d3617604cc70a2d119c6560728bd9f19f4be9f2c3ba06019431bf582040230ec549953b32b77cf6772c11ddc7cd0ab4bb9014672dfaa965344bc51855953afe05e16176aa41f76beb61b527248b37d88cc4be4871ede80bc2fc230ba83c0595e4105c77261aef3dc3e7952fa13687ddc26c3894626ac7ccaafbdc0faa96fdd39fa80fdf8dcb8d6eda' ),
        7 => hex2bin( '0a19f38a88a5e88da14d980c30e3649cb24ad0f752888c8d0c92c7036c9cb213efdf84c29840b4e30f57512ef3d581936014716e3efb4a913a50f77b8b53e36c9ec28827e83c3571c5a1589cb54ea69a8e3b65d7681e4e67b0e77e829c28f2c0de842459a4fa7a59192dbf0c4f82fec280c56af2cd57e4a6e317911111728ddb7c98b6cc4c334868e1a29314e2bdf58488c4e9c1fc63eeb51de50743f4aa564102399cf2809bac1abc0a5e96b9a508ff8cc56ad5e5c62b053f146bed27524539a397a2d1ecb241880e73f60e1bfa9e013799e5da4fa702dcde9d7bea6cac91fa4cce345ec3ce09026dd829a1cb599d361258c697f1bc360cf75fd0bf8e6f4176' ),
        9 => hex2bin( '5e9bcaa661864845afb7d1cb76370e087d5e0d18ec88d6331605cfc3bb6038b5cd9d55b3da5ed26647f5090b7ad72c8145b4f3db6c7fb3d98270aae192bed435347502817b8a7c6d076237e4a63996536c78c559c1c633f31565c5109619946cb923c030a19dd081cfd3ca25a371c7eb761c5ce9ddad883ee71d3a6e78ad5f258fd1101c0622a554f03d2f1f3f8f68b30a2c048102b4ea4ea2941474d780dc57e56c7e9e32da8d4e1a95a1b7312a02b6565a25019daefc33cf159c2c7921062df637877e25700992caa63b2a836b6b26ae7a5e4dbec7cc716e2037a4c193c4fd1f21a865fd10e37925e0c1d2cdb1268c78f682ecda7186f355a13e5c6be4ec9c' ),
    ];
    $t->test( $sensitive === Shamir255::recover( $combine ) );
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
