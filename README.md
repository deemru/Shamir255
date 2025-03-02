# Shamir255

[![packagist](https://img.shields.io/packagist/v/deemru/shamir255.svg)](https://packagist.org/packages/deemru/shamir255) [![php-v](https://img.shields.io/packagist/php-v/deemru/shamir255.svg)](https://packagist.org/packages/deemru/shamir255) [![GitHub](https://img.shields.io/github/actions/workflow/status/deemru/Shamir255/php.yml?label=github%20actions)](https://github.com/deemru/Shamir255/actions/workflows/php.yml) [![license](https://img.shields.io/packagist/l/deemru/shamir255.svg)](https://packagist.org/packages/deemru/shamir255)

[Shamir255](https://github.com/deemru/Shamir255) implements Shamir's secret sharing algorithm for sensitive information up to 255 bytes via 2048-bit MODP group.

## Usage

```php
$sensitive = 'Hello, world!';
$needed = 2;
$total = 3;
$shares = Shamir255::share( $sensitive, $needed, $total );
assert( $sensitive === Shamir255::recover( [ 1 => $shares[1], 2 => $shares[2] ] ) );
```

## Requirements

- [PHP](http://php.net) >= 5.6

## Installation

```bash
composer require deemru/shamir255
```
