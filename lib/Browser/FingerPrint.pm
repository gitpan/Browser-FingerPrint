package Browser::FingerPrint;
use strict;
use warnings;

use version; our $VERSION = qv('0.1');
use Params::Validate qw/ :all /;
use HTML::Entities;

use Apache2::RequestUtil;
use Apache2::RequestRec;

=pod

=head1 NAME
 
Browser::FingerPrint - Web Browser Fingerprinting
 
 
=head1 VERSION
 
This documentation refers to Browser::FingerPrint version 0.1
 
 
=head1 SYNOPSIS
 
    use Browser::FingerPrint;
    use CGI;

    my $q = CGI->new;

    my $fp = Browser::FingerPrint->new({
        q   => $q,
        database_path => 'db',
    });

    my $best_hit = $fp->browser_recon();
    
  
  
=head1 DESCRIPTION
 
A full description of the module and its features.
 
 
=head1 SUBROUTINES/METHODS 
 
=cut

##########################################################################

=pod

=head2 new()

    Constructor

    my $fp = Browser::FingerPrint->new({
        q   => $q,
        database_path   => '/path/to/db',
    });

    q - The CGI object
    database_path - path to the fingerprint database directory

=cut

#############################################################################
sub new
{
    my $proto = shift;

    my %params = validate(
        @_,
        {
            q       => { ias => 'CGI', },
            database_path => {
                callbacks => {
                    is_a_dir => sub {
                        my $p = shift;
                        return -d $p;
                    },
                },
            },
        }
    );

    my $class = ref $proto || $proto;
    my $self = {};
    bless $self, $class;

    $self->{_q} = $params{q};
    $self->{_db_path} = $params{database_path};
    $self->{_headers} = $self->get_http_headers;

    return $self;
} # end sub new

sub get_http_headers
{
    my $self = shift;
    my %ret = map { lc($_) => $self->{_q}->http($_) } $self->{_q}->http;
    return \%ret;
}

##########################################################################

=pod

=head2 SUB/METHOD NAME GOES HERE

    Description of the sub here

=cut

#############################################################################
sub count_hit_possibilities
{
    my $self  = shift;
    my $count = 0;

    if ( exists $self->{_headers}->{http_user_agent} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_accept} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_accept_language} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_accept_encoding} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_accept_charset} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_keep_alive} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_connection} )
    {
        ++$count;
    }
    if ( exists $self->{_headers}->{http_cache_control} )
    {
        ++$count;
    }
    if (get_header_order() ne q{}) {
        ++$count;
    }

	#(getheadervalue($rawheader, 'UA-Pixels') != '' ? ++$count : '');
	#(getheadervalue($rawheader, 'UA-Color') != '' ? ++$count : '');
	#(getheadervalue($rawheader, 'UA-OS') != '' ? ++$count : '');
	#(getheadervalue($rawheader, 'UA-CPU') != '' ? ++$count : '');
	#(getheadervalue($rawheader, 'TE') != '' ? ++$count : '');

    return $count;
} # end sub count_hit_possibilities

##########################################################################

=pod

=head2 SUB/METHOD NAME GOES HERE

    Description of the sub here

=cut

#############################################################################
sub identify_global_fingerprint
{
    my $self = shift;
    my $ml = q{};

    $ml .= $self->find_match_in_database( 'user-agent.fdb',
        $self->{_headers}->{http_user_agent} );
    $ml .= $self->find_match_in_database( 'accept.fdb',
        $self->{_headers}->{http_accept} );
    $ml .= $self->find_match_in_database( 'accept-language.fdb',
        $self->{_headers}->{http_accept_language} );
    $ml .= $self->find_match_in_database( 'accept-encoding.fdb',
        $self->{_headers}->{http_accept_encoding} );
    $ml .= $self->find_match_in_database( 'accept-charset.fdb',
        $self->{_headers}->{http_accept_charset} );
    $ml .= $self->find_match_in_database( 'keep-alive.fdb',
        $self->{_headers}->{http_keep_alive} );
    $ml .= $self->find_match_in_database( 'connection.fdb',
        $self->{_headers}->{http_connection} );
    $ml .= $self->find_match_in_database( 'cache-control.fdb',
        $self->{_headers}->{http_cache_control} );
    #$ml .= $self->find_match_in_database( 'header-order.fdb', 
        #get_header_order() );

	#$matchlist.= findmatchindatabase($database.'ua-pixels.fdb', getheadervalue($rawheader, 'UA-Pixels'));
	#$matchlist.= findmatchindatabase($database.'ua-color.fdb', getheadervalue($rawheader, 'UA-Color'));
	#$matchlist.= findmatchindatabase($database.'ua-os.fdb', getheadervalue($rawheader, 'UA-OS'));
	#$matchlist.= findmatchindatabase($database.'ua-cpu.fdb', getheadervalue($rawheader, 'UA-CPU'));
	#$matchlist.= findmatchindatabase($database.'te.fdb', getheadervalue($rawheader, 'TE'));
	#$matchlist.= findmatchindatabase($database.'header-order.fdb', getheaderorder($rawheader));

    return $ml;
} # end sub identify_global_fingerprint

##########################################################################

=pod

=head2 SUB/METHOD NAME GOES HERE

    Description of the sub here

=cut

#############################################################################
sub find_match_in_database
{
    my ( $self, $db_file, $fp ) = @_;
    my $matches = q{};

    open my $RFH, "<", $self->db_file_path($db_file)
        or die "Can't open $db_file for reading";

    while (<$RFH>)
    {
        chomp;
        my ( $k, $v ) = split /;/, $_, 2;
        if ( $fp eq trim($v) )
        {
            $matches .= $k . ';';
        }
    }

    return $matches;
} # end sub find_match_in_database

sub db_file_path
{
    my ( $self, $f ) = @_;

    return $self->{_db_path} . '/' . $f;
}

sub trim
{
    my $s = shift;
    $s =~ s{^\s*}{};
    $s =~ s{\s*$}{};
    return $s;
}

##########################################################################

=pod

=head2 SUB/METHOD NAME GOES HERE

    Description of the sub here

=cut

#############################################################################
sub generate_match_statistics
{
    my ( $self, $ml ) = @_;
    my $ms = q{};

    my @orig_matches = split ';', $ml;
    my %matches = map { $_ => 1 } @orig_matches;
    my @matches = keys %matches;

    for (@matches)
    {
        $ms .= $_ . '=' . count_if( \@orig_matches, $_ ) . "\n";
    }

    return $ms;
}

sub count_if
{
    my ( $input, $search ) = @_;
    my $sum = 0;

    for (@$input)
    {
        if ( $_ eq $search )
        {
            ++$sum;
        }
    }

    return $sum;
}

##########################################################################

=pod

=head2 SUB/METHOD NAME GOES HERE

    Description of the sub here

=cut

#############################################################################
sub announce_fingerprint_matches
{
    my $self = shift;

    my %params = validate(
        @_,
        {
            full_match_list => { type => SCALAR, },
            mode            => {
                default => 'best_hit',
                regex   => qr/^best_hit|list|best_hit_list|best_hit_detail$/,
            },
            hit_possibilities => { default => 0, },
        }
    );

    my @res = split /\n/, $params{full_match_list};

    my $scan_besthitcount = 0;
    my $scan_besthitname = q{};
    my $scan_resultlist = q{};
    my @scan_resultarray;

    for (@res)
    {
        my @entry = split /=/, $_, 2;

        if ( length $entry[0] )
        {
            if ( $scan_besthitcount < $entry[1] )
            {
                $scan_besthitname  = $entry[0];
                $scan_besthitcount = $entry[1];
            }
            $scan_resultlist .= $entry[0] . ': ' . $entry[1] . "\n";
            push @scan_resultarray,
                $entry[1] . ';' . encode_entities( $entry[0] );
        }
    } # end for (@res)

    if ( $params{mode} eq 'list' )
    {
        return $scan_resultlist;
    }
    elsif ( $params{mode} eq 'best_hit_list' )
    {
        my $scan_hitaccuracy;
        my $scan_hitlist;

        @scan_resultarray = reverse sort @scan_resultarray;
        for ( 0 .. 9 )
        {
            my @scan_resultitem = split /;/, $scan_resultarray[$_], 2;
            if ( $scan_resultitem[0] > 0 )
            {
                if ( $params{hit_possibilities} > 0 )
                {
                    $scan_hitaccuracy = sprintf "%0.*f", 2,
                        ( 100 / $params{hit_possibilities} )
                        * $scan_resultitem[0];
                }
                else
                {
                    $scan_hitaccuracy = sprintf "%0.*f", 2,
                        ( 100 / $scan_besthitcount ) * $scan_resultitem[0];
                }

                $scan_hitlist .=
                      ( $_ + 1 ) . '. '
                    . $scan_resultitem[1] . ' ('
                    . $scan_hitaccuracy
                    . '% with '
                    . $scan_resultitem[0]
                    . ' hits)';

                if ( $_ < 9 )
                {
                    $scan_hitlist .= "\n";
                }
            } # end if ( $scan_resultitem[...])
        } # end for ( 0 .. 9 )

        return $scan_hitlist;
    }
    elsif ( $params{mode} eq 'best_hit_detail' )
    {
        my $scan_hitaccuracy;

        if ( $params{hit_possibilities} > 0 )
        {
            $scan_hitaccuracy = sprintf "%0.*f", 2,
                ( 100 / $params{hit_possibilities} ) * $scan_besthitcount;
        }
        else
        {
            $scan_hitaccuracy = 100;
        }
        return
              $scan_besthitname . ' ('
            . $scan_hitaccuracy
            . '% with '
            . $scan_besthitcount
            . ' hits)';
    }
    else
    {
        return $scan_besthitname;
    }
} # end sub announce_fingerprint_matches

sub round
{
    my $number = shift;
    return int( $number + .5 );
}


##########################################################################
=pod

=head2 browser_recon()

    Description of the sub here

=cut
#############################################################################
sub browser_recon
{
    my $self = shift;

    my %params = validate(
        @_,
        {
            mode => {
                default => 'best_hit',
                regex   => qr/^best_hit|list|best_hit_list|best_hit_detail$/,
            },
        }
    );

    my $ms = $self->generate_match_statistics(
        $self->identify_global_fingerprint );
    my $hit_possibilities = $self->count_hit_possibilities;

    return $self->announce_fingerprint_matches(
        {
            full_match_list   => $ms,
            mode              => $params{mode},
            hit_possibilities => $hit_possibilities,
        }
    );
} # end sub browser_recon


##########################################################################
=pod

=head2 get_header_order()

    Returns a string containing the order in which the HTTP request headers
    were sent

    NOTE: This only works under mod_perl

=cut
#############################################################################
sub get_header_order 
{
    my $r = Apache2::RequestUtil->request;

    return join ", ", map { m{^(.+?):} } grep { m{^.+: .+$} } split "\n",
        $r->as_string;
}

1;

=head1 AUTHOR
 
Rohan Almeida <rohan@almeida.in>
 
 
=head1 LICENCE AND COPYRIGHT
 
Copyright (c) 2010 Rohan Almeida <rohan@almeida.in>. All rights
reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

