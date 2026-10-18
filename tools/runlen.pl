#!/usr/bin/perl
# runlen.pl <dir|file> [...]
#
# The zero-width steganography test, fast and content-free. For every UTF-8 text file that
# contains invisible or control characters, prints:   longest-run <TAB> total <TAB> path
#
# Hidden-text encodings spend one invisible character per bit or symbol, so they need RUNS of
# them. A stray zero-width space from copy-and-paste is a run of 1; a hidden message is a run of
# dozens or hundreds. The longest run is therefore what separates hiding from stray markup.
#
# It prints NO file content, by design: use it to answer "is anything hidden?" over material
# you should not be reading into a conversation (attack payloads, prompt-injection catalogues).
# It counts form feeds and vertical tabs, which scan-codepoints.pl deliberately exempts, so it
# can list a file the scanner did not flag. Files containing a NUL byte are skipped as binary
# (run scan-codepoints.pl for UTF-16 text). Read-only.
use strict; use warnings;
use Encode qw(decode);
use File::Find;
binmode(STDOUT, ':encoding(UTF-8)');

my $INV = qr/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\x{AD}\x{034F}\x{180E}\x{200B}-\x{200F}\x{2060}-\x{2064}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{3164}\x{FEFF}\x{FFA0}\x{E0000}-\x{E01EF}]+/;

@ARGV or do { print STDERR "usage: $0 <dir|file> [...]\n"; exit 2 };
find({ no_chdir => 1, wanted => sub {
    my $p = $File::Find::name;
    return unless -f $p && $p !~ m{/\.git/};
    open(my $h, '<:raw', $p) or return;
    my $raw = do { local $/; <$h> } // ''; close $h;
    return if $raw =~ /\x00/;
    my $txt = eval { decode('UTF-8', $raw, Encode::FB_CROAK | Encode::LEAVE_SRC) } // decode('UTF-8', $raw);
    $txt =~ s/\A\x{FEFF}//;                                      # a leading BOM is benign
    my ($max, $total) = (0, 0);
    while ($txt =~ /($INV)/g) { my $n = length $1; $total += $n; $max = $n if $n > $max }
    printf "%d\t%d\t%s\n", $max, $total, $p if $total;
} }, map { tr{\\}{/}r } @ARGV);
