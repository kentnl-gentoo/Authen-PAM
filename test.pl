# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; $^W = 1; print "1..12\n"; }
END { print "not ok 1\n" unless $loaded; }

use strict;
use vars qw($loaded $fd_status);
use POSIX;
use Authen::PAM; # qw(:functions :constants);

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

sub ok {
    my ($no, $ok) = @_ ;
    print "ok $no\n" if $ok ;
    print "not ok $no\n" unless $ok ;
}

sub pam_ok {
    my ($no, $pamh, $pam_ret_val, $other_test) = @_ ;
    if ($pam_ret_val != PAM_SUCCESS()) {
        print "not ok $no ($pam_ret_val - ",
	  pam_strerror($pamh, $pam_ret_val),")\n";
    }
    elsif (defined($other_test) && !$other_test) {
        print "not ok $no\n";
    }
    else {
        print "ok $no\n";
    }
}

sub skip {
  my ($no, $msg) = @_ ;
  print "skipped $no: $msg\n";
}

sub my_fail_delay {
  $fd_status = shift;
  my $delay = shift;

#  print "Status: $fd_status, Delay: $delay\n";
}

  my ($pamh, $item);
  my $res = -1;

  my $pam_service = "login";
  my $login_name = getpwuid($<);
  my $tty_name = ttyname(fileno(STDIN));

  if (!$login_name) {
    print "Can't obtain your login name!\n";
  }
  elsif (!$tty_name) {
    print "Can't obtain the tty name!\n";
  } else {
    print "---- The remaining tests will be run for service '$pam_service', ",
		"user '$login_name' and\n---- device '$tty_name'.\n";
  }

#  $res = pam_start($pam_service, $login_name, \&Authen::PAM::pam_default_conv, $pamh);
  $res = pam_start($pam_service, $login_name, $pamh);
  pam_ok(2, $pamh, $res);

  $res = pam_get_item($pamh, PAM_SERVICE(), $item);
  pam_ok(3, $pamh, $res, $item eq $pam_service);

  $res = pam_get_item($pamh, PAM_USER(), $item);
  pam_ok(4, $pamh, $res, $item eq $login_name);

#  $res = pam_set_item($pamh, PAM_CONV(), \&Authen::PAM::pam_default_conv);
#  pam_ok(4.99, $pamh, $res);

  $res = pam_get_item($pamh, PAM_CONV(), $item);
  pam_ok(5, $pamh, $res, $item == \&Authen::PAM::pam_default_conv);

  $res = pam_set_item($pamh, PAM_TTY(), $tty_name);
  pam_ok(6, $pamh, $res);

  $res = pam_get_item($pamh, PAM_TTY(), $item);
  pam_ok(7, $pamh, $res, $item eq $tty_name);

  if (HAVE_PAM_ENV_FUNCTIONS()) {
    $res = pam_putenv($pamh, "_ALPHA=alpha");
    pam_ok(8, $pamh, $res);

    my %en = pam_getenvlist($pamh);
    ok(9, $en{"_ALPHA"} eq "alpha");
  }
  else {
    skip(8, 'environment functions are not supported by your PAM library');
    skip(9, 'environment functions are not supported by your PAM library');
  }

#  if (HAVE_PAM_FAIL_DELAY()) {
#    $res = pam_set_item($pamh, PAM_FAIL_DELAY(), \&my_fail_delay);
#    pam_ok(10, $pamh, $res);
#  } else {
#    skip(10, 'custom fail delay function is not supported by your PAM library');
#  }

  print
"---- Now you will be prompted to enter your unix password.";
  if ($login_name eq "root") {
    print "\n";
  } else {
    print " On some systems
---- this test will succeed only if you are running as 'root'.
"
  }

  $res = pam_authenticate($pamh, 0);
  pam_ok(10, $pamh, $res);

#  if (HAVE_PAM_FAIL_DELAY()) {
#    ok(12, $res == $fd_status);
#  } else {
#    skip(12, 'custom fail delay function is not supported by your PAM library');
#  }

#  $res = pam_chauthtok($pamh, 0);
#  pam_ok(10.1, $pamh, $res);

  $res = pam_end($pamh, 0);
  ok(11, $res == PAM_SUCCESS());

  # Checking the OO interface
  $pamh = new Authen::PAM($pam_service, $login_name);
  ok(12, ref($pamh));

#  $res = $pamh->pam_authenticate;
#  $res = $pamh->pam_chauthtok;
#  pam_ok(111, $pamh, $res);

  $pamh = 0;  # this will destroy the object (and call pam_end)

  print "\n";

1;
