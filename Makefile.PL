use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Browser::FingerPrint',
    AUTHOR              => q{Rohan Almeida <rohan@almeida.in>},
    VERSION_FROM        => 'lib/Browser/FingerPrint.pm',
    ABSTRACT_FROM       => 'lib/Browser/FingerPrint.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Browser-FingerPrint-*' },
);
