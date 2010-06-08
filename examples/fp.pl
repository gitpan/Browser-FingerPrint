#!/usr/bin/perl
use strict; use warnings;

use CGI;

use lib '/home/rohan/projects/browser-fingerprint/lib';
use Browser::FingerPrint;

my $q = CGI->new;

my $fp = Browser::FingerPrint->new({
    q   => $q,
    database_path => '/home/rohan/projects/browser-fingerprint/db',
});

print $q->header('text/plain');
print $fp->browser_recon();

