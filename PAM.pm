package Authen::PAM;

use strict;
#no strict "subs";

use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	pam_start pam_end
	pam_authenticate pam_setcred pam_acct_mgmt pam_chauthtok
	pam_open_session pam_close_session
	pam_set_item pam_get_item
	pam_strerror
	pam_getenv pam_putenv pam_getenvlist

	PAM_SUCCESS PAM_PERM_DENIED PAM_BUF_ERR PAM_BAD_ITEM PAM_AUTH_ERR

	PAM_CRED_INSUFFICIENT PAM_AUTHINFO_UNAVAIL PAM_USER_UNKNOWN
	PAM_MAXTRIES PAM_CRED_UNAVAIL PAM_CRED_EXPIRED PAM_CRED_ERR
	PAM_AUTHTOKEN_REQD PAM_NEW_AUTHTOK_REQD PAM_ACCT_EXPIRED 
	PAM_AUTHTOK_ERR PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
	PAM_AUTHTOK_LOCK_BUSY PAM_AUTHTOK_DISABLE_AGING PAM_TRY_AGAIN 
	PAM_ABORT

	PAM_SERVICE PAM_USER PAM_TTY PAM_RHOST PAM_CONV PAM_RUSER 
	PAM_USER_PROMPT PAM_AUTHTOK PAM_OLDAUTHTOK

	PAM_SILENT PAM_DISALLOW_NULL_AUTHTOK

	PAM_ESTABLISH_CRED PAM_DELETE_CRED PAM_REINITIALIZE_CRED
	PAM_REFRESH_CRED PAM_CHANGE_EXPIRED_AUTHTOK
	PAM_CRED_ESTABLISH PAM_CRED_DELETE PAM_CRED_REINITIALIZE
	PAM_CRED_REFRESH

	PAM_PROMPT_ECHO_OFF PAM_PROMPT_ECHO_ON PAM_ERROR_MSG PAM_TEXT_INFO

	HAVE_PAM_FAIL_DELAY
);

$VERSION = '0.02';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined Authen::PAM macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

sub dl_load_flags { 0x01 }

bootstrap Authen::PAM $VERSION;

# Preloaded methods go here.

sub pam_getenvlist ($) {
    my @env = _pam_getenvlist($_[0]);
    my %env;
    for (@env) {
        my ($name, $value) = /(.*)=(.*)/;
        $env{$name} = $value;
    }
    return %env;
}

# Support for Objects

sub new {
    my $this = shift;
    my $class = ref($this) || $this;
    my $pamh;
    my $retval = pam_start (@_, $pamh);
    return $retval if $retval != &PAM_SUCCESS;
    bless $pamh, $class;
    return $pamh;
}

sub DESTROY {
    my $pamh = shift;
    my $retval = pam_end($pamh, 0);
}

sub pam_default_conv {
    my @res;
    local $\ = "";
    while ( @_ ) {
        my $code = shift;
        my $msg = shift;
        my $ans = "";

        print $msg;
        push @res, &PAM_SUCCESS;

        if ($code == &PAM_PROMPT_ECHO_OFF ) {
            system "stty -echo";
            chomp( $ans = <STDIN> ); print "\n";
            system "stty echo";
        }
        elsif ($code == &PAM_PROMPT_ECHO_ON ) { chomp( $ans = <STDIN> ); }
        elsif ($code == &PAM_ERROR_MSG )      { print "\n"; }
        elsif ($code == &PAM_TEXT_INFO )      { print "\n"; }
        push @res, $ans;
    }
    push @res, &PAM_SUCCESS;
    return @res;
}

sub pam_start {
    return _pam_start(@_) if @_ == 4;
    return _pam_start(@_[0], @_[1], \&pam_default_conv, @_[2]) if @_ == 3;
    croak("Wrong number of arguments in pam_start function");
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Authen::PAM - Perl interface to PAM library

=head1 SYNOPSIS

  use Authen::PAM;

  $retval = pam_start($service_name, $user, $pamh);
  $retval = pam_start($service_name, $user, $conv_func, $pamh);
  $retval = pam_end($pamh, $pam_status);

  $retval = pam_authenticate($pamh, $flags);
  $retval = pam_setcred($pamh, $flags);
  $retval = pam_acct_mgmt($pamh, $flags);
  $retval = pam_open_session($pamh, $flags);
  $retval = pam_close_session($pamh, $flags);
  $retval = pam_chauthtok($pamh, $flags);

  $error_str = pam_strerror($pamh, $errnum);

  $retval = pam_set_item($pamh, $item_type, $item);
  $retval = pam_get_item($pamh, $item_type, $item);

  $retval = pam_putenv($pamh, $name_value);
  $val = pam_getenv($pamh, $name);
  %env = pam_getenvlist($pamh);

  if (HAVE_PAM_FAIL_DELAY)
	$retval = pam_fail_delay($pamh, $musec_delay);

=head1 DESCRIPTION

The I<Authen::PAM> module provides a Perl interface to the I<PAM>
library. The only difference with the standart PAM interface is that 
instead of passing a pam_conv struct which has an additional 
context parameter appdata_ptr, you must only give an address to a 
conversation function written in Perl (see below). 
If you use the 3 argument version of pam_start then a default conversation
function is used (Authen::PAM::pam_default_conv).

The $flags argument is optional for all functions which use it
except for pam_setcred. The $pam_status argument is also optional for
pam_end function.

The names of some constants from the PAM library have changed over the
time. You can use any of the known names for a given constant although
it is advisable to use the latest one.

When this module supports some of the additional features of the PAM
library (e.g. pam_fail_delay) then the coresponding HAVE_PAM_XXX
constant will have a value 1 otherwise it will return 0.

=head2 Object Oriented Style

If you prefer to use an object oriented style for accessing the PAM
library you can use the following interface:

  $pamh = new Authen::PAM($service_name, $user);
  $pamh = new Authen::PAM($service_name, $user, $conv_func);

  $retval = $pamh->pam_authenticate($flags);
  $retval = $pamh->pam_setcred($flags);
  $retval = $pamh->pam_acct_mgmt($flags);
  $retval = $pamh->pam_open_session($flags);
  $retval = $pamh->pam_close_session($flags);
  $retval = $pamh->pam_chauthtok($flags);

  $error_str = $pamh->pam_strerror($errnum);

  $retval = $pamh->pam_set_item($item_type, $item);
  $retval = $pamh->pam_get_item($item_type, $item);

  $retval = $pamh->pam_putenv($name_value);
  $val = $pamh->pam_getenv($name);
  %env = $pamh->pam_getenvlist;

The constructor new will call the pam_start function and if successfull
will return an object reference. Otherwise the $pamh will contain the
error number returned by pam_start.
The pam_end function will be called automatically when the object is no
longer referenced.

=head2 Examples

Here is an example of using PAM for changing the password of the current
user:

  use Authen::PAM;

  $login_name = getlogin || getpwuid($<);

  pam_start("passwd", $login_name, $pamh);
  pam_chauthtok($pamh);
  pam_end($pamh);


or the same thing but using OO style:

  $pamh = new Authen::PAM("passwd", $login_name);
  $pamh->pam_chauthtok;
  $pamh = 0;  # Force perl to call the destructor for the $pamh

=head2 Conversation function format

When starting the PAM the user must supply a conversation function.
It is used for interaction between the PAM modules and the user.
The function takes as arguments a list of pairs ($msg_type, $msg)
and must return a list with the same number of pairs ($resp_retcode, $resp)
with replies to the input messages. For now the $resp_retcode is not used 
and must be always set to 0.  In addition the user must append to
the end of the resulting list the return code of the conversation function
(usually PAM_SUCCESS).

Here is a sample form of the PAM conversation function:

sub pam_conv_func {
    my @res;
    while ( @_ ) {
        my $code = shift;
        my $msg = shift;

        print $msg;

	# switch ($code) { obtain value for $ans; }
      
        push @res, 0;
        push @res, $ans;
    }
    push @res, PAM_SUCCESS;
    return @res;
}
 

=head1 COMPATIBILITY

This module was tested with the following versions of the Linux-PAM library:
0.56, 0.59 and 0.65.

This module still does not support some of the new Linux-PAM 
functions such as pam_system_log. This will be added in the near future
if necessary.

Lupe Christoph <lupe@alanya.m.isar.de> ported this module to work
with Solaris 2.6 PAM library.

=head1 AUTHOR

Nikolay Pelov <nikip@iname.com>

=head1 SEE ALSO

PAM Application developer's Manual

=cut