# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use Authen::PAM;
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

sub skip {
    my ($no, $msg) = @_ ;
    print "skipped $no: $msg\n";
}

# $\ = "\n";
  $res = -1;

  $pam_service = "login";
  $login_name = getlogin || getpwuid($<);
  if ($login_name) {
      print "\nThe remaining tests will be run for service '$pam_service' ",
		"and user name '$login_name'.\n";
      print "To complete the test 8 you will be prompted to enter your ",
		"UNIX password.\n\n";
  }
  else { print "Can't obtain a login name!\n"; }

#  $res = pam_start($pam_service, $login_name, \&Authen::PAM::pam_default_conv, $pamh);
  $res = pam_start($pam_service, $login_name, $pamh);
  ok(2, $res == PAM_SUCCESS);

  $res = pam_get_item($pamh, PAM_SERVICE, $item);
  ok(3, $res == PAM_SUCCESS && $item eq $pam_service);

  $res = pam_get_item($pamh, PAM_USER, $item);
  ok(4, $res == PAM_SUCCESS && $item eq $login_name);

  $res = pam_get_item($pamh, PAM_CONV, $item);
  ok(5, $res == PAM_SUCCESS && $item == \&Authen::PAM::pam_default_conv);

  if (HAVE_PAM_ENV_FUNCTIONS) {
    $res = pam_putenv($pamh, "_ALPHA=alpha");
    ok(6, $res == PAM_SUCCESS);

    %en = pam_getenvlist($pamh);
    ok(7, $en{"_ALPHA"} eq "alpha");
  }
  else {
    skip(6, 'environment functions are not supported by your PAM library');
    skip(7, 'environment functions are not supported by your PAM library');
  }

#  $res = pam_chauthtok($pamh, 0);
#  print "chauthtok returned ", pam_strerror ($pamh, $res);

  $res = pam_authenticate($pamh, 0);
  ok(8, $res == PAM_SUCCESS);
#  print "authenticate returned ", pam_strerror ($pamh, $res);

  $res = pam_end($pamh, 0);
  ok(9, $res == PAM_SUCCESS);

  # Checking the OO interface
  $pamh = new Authen::PAM($pam_service, $login_name);
  ok(10, ref($pamh));

#  $res = $pamh->pam_chauthtok;
#  print "chauthtok returned ", $pamh->pam_strerror($res);

  $pamh = 0;

  print "\n";

  1;
