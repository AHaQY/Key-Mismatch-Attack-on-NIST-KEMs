my @all[4] = 0,0,0,0;
my $n = 10000;
my @p;
sub subsum($k, $n) {
    for 1..$n -> $i {
        my $rand = 50000.rand.Int;
        my $run = run './PQCgenKAT_kem',  ~$rand, :out;
        $run = $run.out.slurp(:close);
        if $run ~~ /fact \s queries\:\s (.*) \n/ {
            $run = ~$0;
            #say $i, ' ', $run;
            @all[$k] += +$run;
        }
        else {
            say 'poor s';
        }
    }
}
for 0..3 -> $k {
    push @p, start subsum($k, $n/4);
}

await Promise.allof(@p);
say @all.sum, ' ', @all.sum/$n;
# my $rand = 1000.rand.Int;
# my $start  = now;
# run './PQCgenKAT_kem',  ~$rand;

# say now - $start;
