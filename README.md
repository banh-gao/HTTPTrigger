HTTPTrigger
=========

A small module to capture HTTP traffic and detect matching HTTP headers

## Installation

  npm install HTTPTrigger

## Usage

  var HTTPTrigger = require('HTTPTrigger');

  var headers = {"User-Agent": "Mozilla *"};

  trigger = new HTTPTrigger(headers,"eth0");

  trigger.on("match", function(src, headers) {
      //React to matching http headers from src
  });

## Author

Daniel Zozin <zdenial@gmx.com>

## Release History

* 0.1.0 Initial release
