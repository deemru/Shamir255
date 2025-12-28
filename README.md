# Shamir255

[![packagist](https://img.shields.io/packagist/v/deemru/shamir255.svg)](https://packagist.org/packages/deemru/shamir255) [![php-v](https://img.shields.io/packagist/php-v/deemru/shamir255.svg)](https://packagist.org/packages/deemru/shamir255) [![GitHub](https://img.shields.io/github/actions/workflow/status/deemru/Shamir255/php.yml?label=github%20actions)](https://github.com/deemru/Shamir255/actions/workflows/php.yml) [![license](https://img.shields.io/packagist/l/deemru/shamir255.svg)](https://packagist.org/packages/deemru/shamir255)

[Shamir255](https://github.com/deemru/Shamir255) implements [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) algorithm over [GF(256)](https://en.wikipedia.org/wiki/Finite_field_arithmetic).

- Pure PHP implementation (no extensions required)
- Share size equals secret size (efficient storage)
- Supports secrets of any length
- Up to 255 shares with threshold from 2 to 255

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
