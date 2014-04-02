# Sauron::UtilDhcp.pm - ISC DHCPD config file reading/parsing routines
#
# Copyright (c) Timo Kokkonen <tjko@iki.fi> 2002.
#
package Sauron::UtilDhcp;
require Exporter;
use IO::File;
use Sauron::Util;
use Data::Dumper;
use strict;
use vars qw(@ISA @EXPORT);

@ISA = qw(Exporter); # Inherit from Exporter
@EXPORT = qw(process_dhcpdconf);


my $debug = 0;

# parse dhcpd.conf file, build hash of all entries in the file
#
sub process_dhcpdconf($$) {
  my ($filename,$data)=@_;

  my $fh = IO::File->new();
  my ($i,$c,$tmp,$quote,$lend,$fline,$prev,%state);

  print "process_dhcpdconf($filename,DATA)\n" if ($debug);

  fatal("cannot read conf file: $filename") unless (-r $filename);
  open($fh,$filename) || fatal("cannot open conf file: $filename");

  $tmp='';
  while (<$fh>) {
    chomp;
    next if (/^\s*$/);
    next if (/^\s*#/);

    $quote=0;
#    print "line '$_'\n";
    s/\s+/\ /g; s/\s+$//; # s/^\s+//;

    for $i (0..length($_)-1) {
      $prev=($i > 0 ? substr($_,$i-1,1) : ' ');
      $c=substr($_,$i,1);
      $quote=($quote ? 0 : 1)	if (($c eq '"') && ($prev ne '\\'));
      unless ($quote) {
	last if ($c eq '#');
	$lend = ($c =~ /^[;{}]$/ ? 1 : 0);
      }
      $tmp .= $c;
      if ($lend) {
	process_line($tmp,$data,\%state);
	$tmp='';
      }
    }

    fatal("$filename($.): unterminated quoted string!\n") if ($quote);
  }
  process_line($tmp,$data,\%state);

  close($fh);

  return 0;
}

sub process_line($$$) {
  my($line,$data,$state) = @_;

  my($tmp,$block,$rest,$ref);

  return if ($line =~ /^\s*$/);
  $line =~ s/(^\s+|\s+$)//g;
  $line =~ s/\"//g;


  #if ($line =~ /^(\S+)\s+(\S.*)?{$/) {
  if ($line =~ /^(\S+)\s?(\s+\S.*)?{$/) {
    $block=lc($1);
    #print "BLOCK: $block\n";
    ($rest=$2) =~ s/^\s+|\s+$//g;
    #print "REST: $rest\n";
    if ($block =~ /^group/) {
      # generate name for groups
      $$state{groupcounter}++;
      $rest="group-" . $$state{groupcounter};
    }
    elsif ($block =~ /^pool[6]?/) {
      $$state{poolcounter}++;
      $rest="pool-" . $$state{poolcounter};
      
#warn("pools not under shared-network aren't currently supported");
    }
    #print "begin '$block:$rest'\n";
    unshift @{$$state{BLOCKS}}, $block;
    #print "BLOCKS: " . Dumper($$state{BLOCKS});
    unshift @{$$state{$block}}, $rest;
    #print "BLOCK-RESTS: " . Dumper($$state{$block});
    $$data{$block}->{$rest}=[] if ($rest);
    $$state{rest}=$2;

    if ($block =~ /^host/) {
      push @{$$data{$block}->{$rest}}, "GROUP $$state{group}->[0]" if ($$state{group}->[0]);
    }
    if ($block =~ /^subnet[6]?/) {
      if ($$state{'shared-network'}->[0]) {
         push @{$$data{$block}->{$rest}}, "VLAN $$state{'shared-network'}->[0]";
      }
      $$state{lastsubnet} = $rest;
    }

    return 0;
  }

  $block=$$state{BLOCKS}->[0];
  $rest=$$state{$block}->[0];

  if ($line =~ /^\s*}\s*$/) {
    print "end '$block:$rest'\n";
    unless (@{$$state{BLOCKS}} > 0) {
      warn("mismatched parenthesis");
      return -1;
    }
    shift @{$$state{BLOCKS}};
    shift @{$$state{$block}};
    return 0;
  }

  $block='GLOBAL' unless ($block);
  #print "line($block:$rest) '$line'\n";

  if ($block eq 'GLOBAL') {
    #if($line =~ /subclass\s+\"(.*)\"\s+(.*)/) {
    if($line =~ /subclass\s+(.*)\s+(.*)/) {
        push @{$$data{'subclass'}->{$1}}, $2; 
    }
    else {
        push @{$$data{GLOBAL}}, $line;
    }
  }
  elsif ($block =~ /^(subnet[6]?|shared-network|group|class)$/) {
    push @{$$data{$block}->{$rest}}, $line;
  }
  elsif ($block =~ /^pool[6]?/) {
    push @{$$data{$block}->{$rest}}, $line;
  }
  elsif ($block =~ /^host/) {
    push @{$$data{$block}->{$rest}}, $line;
  }


  return 0;
}

1;
# eof
