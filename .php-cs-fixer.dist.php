<?php

declare(strict_types=1);

$finderClass = 'PhpCsFixer\\Finder';
$configClass = 'PhpCsFixer\\Config';

if (!class_exists($finderClass) || !class_exists($configClass)) {
    return null;
}

$finder = $finderClass::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/bin'])
    ->name('*.php');

$config = new $configClass();

return $config
    ->setRiskyAllowed(false)
    ->setRules([
        '@PSR12' => true,
        'array_syntax' => ['syntax' => 'short'],
        'ordered_imports' => true,
        'single_quote' => true,
    ])
    ->setFinder($finder);
