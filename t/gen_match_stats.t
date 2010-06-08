#!/usr/bin/perl
use strict; use warnings;
use feature ':5.10';

use lib 'lib';

use Test::More tests => 1;
#use Test::More qw/ no_plan /;

use_ok('Browser::FingerPrint') or die;

#my $fp = Browser::FingerPrint->new({
    #headers => $headers,
    #database_path => './db',
#});

#isa_ok($fp, 'Browser::FingerPrint');

#say $fp->count_hit_possibilities;
#say $fp->identify_global_fingerprint;
#say $fp->generate_match_statistics($fp->identify_global_fingerprint);
#say $fp->browser_recon(mode => 'list');


