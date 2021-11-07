my $n = 10000;
sub gettime($n) {
    my $time = 0;
    for 1..$n -> \i {
        my $rand = 50000.rand.Int;
        my $start = now;
        run './PQCgenKAT_kem',  ~$rand;
        $time += now - $start;
    }
    return $time;
}
my @p;

for 0..3 -> \n {
    @p[n] = start gettime($n/4);
}

my @alltime = await |@p;
say "all time is ", @alltime;
say 'average ', @alltime.sum/$n;

# say gettime(100)/$n;
