use ExtUtils::MakeMaker;
use Config;

sub configure {
    $ENV{'CC'} = $Config{'cc'};
    $ENV{'CPP'} = $Config{'cpprun'};

    system "./configure";

    # returns a reference to anonymous hash which is then interpreted as
    # additional options to the WriteMakeFile
    $options = require "pam.cfg";

    if ( $Config{'osname'} eq 'solaris' && $Config{'osvers'} eq '2.6') {
      print "Adding a workaround for a bug in the Solaris 2.6 pam library\n";
      ${$options}{'DEFINE'} .= ' -DSTATIC_CONV_FUNC ';
    }

    foreach (@ARGV) {
      print "Adding a definition '$_' from the command line\n";
      ${$options}{'DEFINE'} .= " $_ " if /-D.+/;
    }

    return $options;
}

sub MY::postamble {
    my $TARG = MM->catfile('d','PAM.pm');
qq!$TARG: Makefile
\techo '#This is a dummy file so CPAN will find a VERSION' > $TARG
\techo 'package Authen::PAM;' >> $TARG
\techo '\$\$VERSION = "\$(VERSION)";' >>$TARG
\techo '#This is to make sure require will return an error' >>$TARG
\techo '0;' >>$TARG
\tperl -ne 'print if /^=\\w/ ... /^=cut/' PAM.pm.in >>$TARG

!
}


WriteMakefile(
    'NAME'	=> 'Authen::PAM',
    'VERSION_FROM' => 'PAM.pm.in',
    'LIBS'	=> ['-lpam'],
    'CONFIGURE' => \&configure,
    'PREREQ_PM' => { POSIX => 0 }, # module dependenices
    'dist'      => {
        COMPRESS => 'gzip -9f',
        SUFFIX => 'gz',
        DIST_DEFAULT => 'd/PAM.pm tardist'
    },
    'clean'     => { FILES => "PAM.pm" },
    'realclean' => { FILES => "config.* pam.cfg" }
);

