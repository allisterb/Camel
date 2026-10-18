#!/usr/bin/perl
# scan-codepoints.pl <dir|file> [...]
#
# Read-only codepoint-level scan of third-party / reference material, per the
# project guardrails in CLAUDE.md. Reports the codepoint classes that are used
# to smuggle hidden text, mixed-script tokens (homoglyph spoofing), and
# injection phrasing, plus a census of all non-ASCII so a human can judge
# whether it is benign (typography, foreign-language comments, box drawing).
#
# Opens every file with '<:raw' and never writes: this script must not be able
# to re-encode the material it inspects.
#
# Coverage is always reported. A file this script does not read as text is
# COUNTED (binary, too large, unreadable), never silently dropped: a scan that
# skips a file without saying so is indistinguishable from a clean one.
#
# Exit status: 0 = nothing flagged; 1 = needs human review (a suspicious class,
# a mixed-script token, an injection phrase, or incomplete coverage); 2 = usage.
# Phrase hits are common and usually benign in material ABOUT LLMs, so exit 1
# means "read the report", not "this is an attack".
#
# Record $VERSION in the ledger (reference/README.md) with every verdict, so a
# verdict can be traced to what the scanner could detect at the time.
#   v1  initial.
#   v2  decodes UTF-16/UTF-32 instead of skipping it as binary (v1 silently
#       dropped any file containing a NUL byte, so UTF-16 text was never read);
#       reports binary/oversize/unreadable counts; adds invisible-operator,
#       filler-letter, line-separator, supplementary-variation-selector and
#       variation-selector-run classes; adds mixed Latin/Cyrillic tokens.
#   v3  path handling and reporting only; DETECTION IS UNCHANGED, so a v2
#       verdict covers everything v3 detects. Windows backslash paths are
#       normalised (File::Find read C:\x as a relative ./C:\x and scanned
#       nothing); a root that does not exist is a usage error (exit 2) rather
#       than an "unreadable" line; malformed files are listed by name.
use strict; use warnings;
use Encode qw(decode);
use File::Find;

my $VERSION   = 3;
my $MAX_BYTES = 256 * 1024 * 1024;   # larger files are reported, not read
my $LIST_MAX  = 20;                  # per-section cap on listed paths

binmode(STDOUT, ':encoding(UTF-8)');
binmode(STDERR, ':encoding(UTF-8)');
@ARGV or do { print STDERR "usage: $0 <dir|file> [...]\n"; exit 2 };

# Windows perls (Git's MSYS build, Strawberry, Cygwin) accept forward slashes
# everywhere, but File::Find treats a backslashed C:\x root as RELATIVE, looks
# for ./C:\x, and finds nothing. Normalise only on those platforms: on Unix a
# backslash is a legal filename character and must be left alone.
my @args    = map { $^O =~ /\A(?:MSWin32|msys|cygwin)\z/ ? tr{\\}{/}r : $_ } @ARGV;
my @missing = grep { !-e $_ } @args;
my @roots   = grep {  -e $_ } @args;

# class => [label, matcher]. First match wins, so order only matters for
# overlapping ranges (there are none at present).
my @DANGER = (
    ['bidi override / isolate',  sub { my $c=shift; ($c>=0x202A && $c<=0x202E) || ($c>=0x2066 && $c<=0x2069) || $c==0x061C }],
    ['zero-width / joiner',      sub { my $c=shift; ($c>=0x200B && $c<=0x200F) || $c==0x2060 || $c==0xFEFF || $c==0x180E || $c==0x034F }],
    ['invisible operator',       sub { my $c=shift; $c>=0x2061 && $c<=0x2064 }],
    ['filler / blank letter',    sub { my $c=shift; $c==0x115F || $c==0x1160 || $c==0x3164 || $c==0xFFA0 }],
    ['soft hyphen',              sub { my $c=shift; $c==0x00AD }],
    ['line / paragraph separator', sub { my $c=shift; $c==0x2028 || $c==0x2029 }],
    ['Unicode Tag block',        sub { my $c=shift; $c>=0xE0000 && $c<=0xE007F }],
    # Rare in benign text (CJK ideographic variation sequences aside), and the
    # carrier for data smuggled behind a single emoji.
    ['variation selector (supplementary)', sub { my $c=shift; $c>=0xE0100 && $c<=0xE01EF }],
    ['private use area',         sub { my $c=shift; ($c>=0xE000 && $c<=0xF8FF) || ($c>=0xF0000 && $c<=0x10FFFD) }],
    # 0x0B/0x0C (VT/FF) are deliberately not flagged: form feeds are ordinary in old source.
    ['C0/C1 control',            sub { my $c=shift; ($c<0x09) || ($c>=0x0E && $c<0x20) || ($c>=0x7F && $c<0xA0) }],
);

my @PHRASE = (
    qr/ignore\s+(all\s+)?previous\s+instructions/i, qr/disregard\s+(the\s+)?above/i,
    qr/you\s+are\s+now\s+/i, qr/system\s*prompt/i, qr/<\|[a-z_]+\|>/i,
    qr/\[INST\]|\[\/INST\]/i, qr/###\s*(instruction|system)/i,
    qr/\bAI\s+(assistant|agent)\b.{0,40}\b(must|should|shall)\b/i,
);

my (%census, %hits, %phrases, %mixed, %binary_ext, %encodings, @large, @unreadable, @malformed);
my ($nfiles, $nbytes, $nbad, $nbinary) = (0, 0, 0, 0);

sub ext_of { my $p = shift; $p =~ m{\.([^./\\]{1,10})\z} ? lc ".$1" : '(no ext)' }

# Returns (encoding, bom_length), or () when the bytes are not text.
sub detect_encoding {
    my $raw = shift;
    return ('UTF-32LE', 4) if $raw =~ /\A\xFF\xFE\x00\x00/;   # before UTF-16LE: same first two bytes
    return ('UTF-32BE', 4) if $raw =~ /\A\x00\x00\xFE\xFF/;
    return ('UTF-16LE', 2) if $raw =~ /\A\xFF\xFE/;
    return ('UTF-16BE', 2) if $raw =~ /\A\xFE\xFF/;
    return ('UTF-8',    0) unless $raw =~ /\x00/;
    # NULs and no BOM. BOM-less UTF-16 puts the NUL half of each ASCII
    # character on one parity of byte offset; binary scatters them.
    my $s = substr($raw, 0, 8192);
    my ($odd, $even) = (0, 0);
    while ($s =~ /\x00/g) { (pos($s) - 1) % 2 ? $odd++ : $even++ }
    my $half = int(length($s) / 2) || 1;
    return ('UTF-16LE', 0) if $odd  >= 0.3 * $half && $even <= 0.02 * $half;
    return ('UTF-16BE', 0) if $even >= 0.3 * $half && $odd  <= 0.02 * $half;
    return;
}

sub scan_file {
    my $p = shift;
    return if -d $p || -l $p;
    my $size = -s $p;
    if (defined $size && $size > $MAX_BYTES) {
        push @large, sprintf('%s (%.0f MB)', $p, $size / 1048576);
        return;
    }
    open(my $h, '<:raw', $p) or do { push @unreadable, "$p: $!"; return };
    my $raw = do { local $/; <$h> } // ''; close $h;

    my ($enc, $bomlen) = detect_encoding($raw);
    if (!defined $enc) { $nbinary++; $binary_ext{ext_of($p)}++; return }
    $nfiles++; $nbytes += length $raw; $encodings{$enc}++;

    my $body = $bomlen ? substr($raw, $bomlen) : $raw;
    # LEAVE_SRC: Encode may otherwise consume the input in place, and the
    # lenient fallback must decode the whole file, not what is left of it.
    my $txt = eval { decode($enc, $body, Encode::FB_CROAK | Encode::LEAVE_SRC) };
    if (!defined $txt) { $nbad++; push @malformed, "$p ($enc)"; $txt = decode($enc, $body) }

    # Walk only the non-printable-ASCII characters: the regex engine skips
    # ASCII far faster than a per-character loop, and nothing is materialised.
    my ($vsrun, $vsend) = (0, -1);
    while ($txt =~ /([^\x20-\x7E\x09\x0A\x0D])/g) {
        my $c = ord $1; my $at = pos($txt) - 1;
        $census{$c}++;
        next if $at == 0 && $c == 0xFEFF;                # leading BOM is benign
        if ($c >= 0xFE00 && $c <= 0xFE0F) {
            # One selector after an emoji or CJK character is ordinary (U+FE0F
            # follows most emoji). A run of them renders as nothing and is the
            # signature of variation-selector data smuggling.
            $vsrun = $at == $vsend ? $vsrun + 1 : 1;
            $vsend = $at + 1;
            push @{ $hits{'variation selector run'} }, sprintf('%s U+%04X', $p, $c) if $vsrun == 2;
            next;
        }
        for my $d (@DANGER) {
            next unless $d->[1]->($c);
            push @{ $hits{$d->[0]} }, sprintf('%s U+%04X', $p, $c);
            last;
        }
    }

    # Homoglyph spoofing: Latin and Cyrillic in ONE token (paypal with its first "a"
    # swapped for Cyrillic U+0430). Greek is deliberately not paired with Latin here, because
    # notation such as "delta-t" (Greek capital delta, then t) is common and benign in technical text.
    if ($txt =~ /\p{Cyrillic}/) {
        my $n = 0;
        while ($txt =~ /([\p{L}\p{M}]+)/g) {
            my $w = $1;
            next unless $w =~ /\p{Latin}/ && $w =~ /\p{Cyrillic}/;
            push @{ $mixed{$p} }, $w;
            last if ++$n >= 20;
        }
    }

    for my $re (@PHRASE) {
        push @{ $phrases{$p} }, $1 while $txt =~ /($re)/g;
    }
}

find({ wanted => sub { scan_file($File::Find::name) }, no_chdir => 1 }, @roots) if @roots;

# Prints up to $LIST_MAX entries, then a count of the rest.
sub list_paths {
    my @p = @_;
    print "     $_\n" for @p[0 .. ($#p < $LIST_MAX ? $#p : $LIST_MAX - 1)];
    printf "     ... and %d more\n", @p - $LIST_MAX if @p > $LIST_MAX;
}

if (@missing) {
    # Before everything else: a typo'd root must not pass for a clean scan.
    printf "!! root not found (usage error, exit 2): %d\n", scalar @missing;
    list_paths(@missing);
}
printf "scan-codepoints v%d: scanned %d text file(s), %d bytes", $VERSION, $nfiles, $nbytes;
printf " [%s]", join(', ', map { "$_ $encodings{$_}" } sort keys %encodings) if %encodings;
print "\n";
if ($nbinary) {
    my @top = (sort { $binary_ext{$b} <=> $binary_ext{$a} || $a cmp $b } keys %binary_ext)[0 .. 7];
    printf "skipped as binary: %d file(s) (%s)\n", $nbinary,
        join(', ', map { "$_ $binary_ext{$_}" } grep { defined } @top);
}
if ($nbad)       { printf "!! not well-formed in their detected encoding (scanned leniently): %d\n", $nbad; list_paths(@malformed) }
if (@large)      { printf "!! skipped as too large (> %d MB): %d\n", $MAX_BYTES / 1048576, scalar @large; list_paths(@large) }
if (@unreadable) { printf "!! unreadable: %d\n", scalar @unreadable; list_paths(@unreadable) }

print "\n-- non-ASCII census (codepoint, count, char) --\n";
for my $c (sort { $census{$b} <=> $census{$a} || $a <=> $b } keys %census) {
    printf "  U+%04X  %7d  %s\n", $c, $census{$c},
        ($c >= 0x20 && $c != 0x7F ? chr($c) : '.');
}

print "\n-- suspicious codepoint classes --\n";
if (!%hits) { print "  none\n" }
else { for my $k (sort keys %hits) {
    my %u; $u{$_}++ for @{$hits{$k}};
    my @keys = sort keys %u;
    printf "  %-36s %d occurrence(s)\n", $k, scalar @{$hits{$k}};
    printf "      %s (x%d)\n", $_, $u{$_} for @keys[0 .. ($#keys > 4 ? 4 : $#keys)];
    printf "      ... and %d more\n", @keys - 5 if @keys > 5;
} }

print "\n-- mixed-script tokens (possible homoglyphs) --\n";
if (!%mixed) { print "  none\n" }
else { for my $p (sort keys %mixed) { printf "  %s: %s\n", $p, join(', ', @{$mixed{$p}}) } }

print "\n-- injection phrasing --\n";
if (!%phrases) { print "  none\n" }
else { for my $p (sort keys %phrases) { printf "  %s: %s\n", $p, join('; ', @{$phrases{$p}}) } }

exit(@missing ? 2 : (%hits || %mixed || %phrases || @large || @unreadable) ? 1 : 0);
