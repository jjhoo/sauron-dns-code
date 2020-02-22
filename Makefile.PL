#!/usr/bin/perl -w

use ExtUtils::MakeMaker;

my %config = (
    "ABSTRACT" => "a free DNS & DHCP management system",
    "AUTHOR" => "Timo Kokkonen E<lt>tjko[at]iki.fiE<gt>",
    "CONFIGURE_REQUIRES" => {
        "ExtUtils::MakeMaker" => 0
    },
    "EXE_FILES" => [ qw(sauron
                      addgroup addhosts adduser
                      check-pending
                      deluser
                      moduser modhosts
                      expire-hosts
                      export-networks
                      export-by-group
                      export-ip-list
                      export-vmps
                      import import-ethers import-nets import-zone
                      import-dhcp import-jyu import-roots
                      update-dhcp-info update-hosts)
                 ],
    "LICENSE" => "gpl_2",
    "NAME" => "Sauron",
    "NO_MYMETA" => 1,
    "MIN_PERL_VERSION" => "5.008001",
    "PREREQ_PM" => {
        "CGI" => "4.35",
        "Crypt::RC5" => "2.00",
        "DBD::Pg" => "3.5.3",
        "DBI" => "1.636",
        "Digest::MD5" => "2.54",
        "Exporter" => "5.72",
        "Net::DNS" => "1.07",
        "Net::IP" => "1.26",
        "Net::Netmask" => "1.9022"
    },
    "VERSION" => "0.74",
    );

WriteMakefile(%config);
