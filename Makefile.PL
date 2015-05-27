#!/usr/bin/perl -w

use ExtUtils::MakeMaker;

WriteMakefile(NAME            => 'Sauron',
              VERSION_FROM    => 'Sauron/Sauron.pm',
              AUTHOR          => 'Timo Kokkonen E<lt>tjko[at]iki.fiE<gt>',
              EXE_FILES       => [ qw(
		  sauron
                  addgroup addhosts adduser
                  deluser
                  moduser modhosts
                  expire-hosts
                  export-networks
                  export-by-group
                  export-ip-list
                  export-vmps
		  import import-ethers import-nets import-zone
                  import-dhcp import-jyu import-roots
                  update-dhcp-info update-hosts)],
    );
