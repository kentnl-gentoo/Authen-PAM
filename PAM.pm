package Authen::PAM;

use strict;
no strict "subs";

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
	PAM_NEW_AUTHTOK_REQD PAM_ACCT_EXPIRED PAM_AUTHTOK_ERR
	PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_LOCK_BUSY
	PAM_AUTHTOK_DISABLE_AGING PAM_TRY_AGAIN PAM_ABORT

	PAM_SERVICE PAM_USER PAM_TTY PAM_RHOST PAM_CONV PAM_RUSER 
	PAM_USER_PROMPT

	PAM_SILENT PAM_DISALLOW_NULL_AUTHTOK

	PAM_ESTABLISH_CRED PAM_DELETE_CRED PAM_REINITIALIZE_CRED
	PAM_REFRESH_CRED PAM_CHANGE_EXPIRED_AUTHTOK

	PAM_PROMPT_ECHO_OFF PAM_PROMPT_ECHO_ON PAM_ERROR_MSG PAM_TEXT_INFO

	HAVE_PAM_FAIL_DELAY HAVE_PAM_SYSTEM_LOG
);

$VERSION = '0.01';

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
    if ($retval != PAM_SUCCESS) {
	return $retval;
    }
    bless \$pamh, $class;
    return \$pamh;
}

sub DESTROY {
    my $pamh = shift;
    my $retval = pam_end($$pamh, 0);
}

sub pam_default_conv {
    my @res;
    local $\ = "";
    while ( @_ ) {
        my $code = shift;
        my $msg = shift;
        my $ans = "";

        print $msg;
        push @res, PAM_SUCCESS;

        if ($code == PAM_PROMPT_ECHO_OFF ) {
            system "stty -echo";
            chomp( $ans = <STDIN> ); print "\n";
            system "stty echo";
        }
        elsif ($code == PAM_PROMPT_ECHO_ON ) { chomp( $ans = <STDIN> ); }
        elsif ($code == PAM_ERROR_MSG )      { print "\n"; }
        elsif ($code == PAM_TEXT_INFO )      { print "\n"; }
        push @res, $ans;
    }
    push @res, PAM_SUCCESS;
    return @res;
}

sub pam_start {
    return _pam_start(@_[0], @_[1], @_[2], @_[3]) if @_ == 4;
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

=head1 DESCRIPTION

The I<Authen::PAM> module provides a Perl interface to the I<PAM>
library. The only difference with the standart PAM interface is that 
instead of passing a pam_conv struct which has an additional 
context parameter appdata_ptr, you must only give an address to a 
conversation function written in Perl (see below). You can pass
a context to the conversation function using the Perl function local.
If you use the 3 argument version of pam_start then a default conversation
function is used (Authen::PAM::pam_default_conv).

=head2 Examples

Here is an example of using PAM for changing the password of the current
user:

  use Authen::PAM;

  $login_name = getlogin || getpwuid($<);

  pam_start("passwd", $login_name, \&pam_default_conv, $pamh);
  pam_chauthtok($pamh, 0);
  pam_end($pamh, 0);

=head2 Conversation function format

When starting the PAM the user must supply a conversation function.
It is used for interaction between the PAM modules and the user.
The function takes as arguments a list of pairs ($msg_type, $msg)
and must return a list with the same number of pairs ($resp_retcode, $resp)
with replies to the input messages. For now the $resp_retcode is not used 
and must be always set to 0.  In addition the user must append to
the end of the resulting list the return code of the conversation function
(usualy PAM_SUCCESS).

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
0.56, 0.59 and 0.65. This means that it supports the pre 0.58 interface of the 
PAM functions and constants as well as the latest (0.65) constant 
definitions. 

This module still does not support some of the new Linux-PAM 
functions such as pam_system_log. This will be added in the near future
if necessary.

=head1 AUTHOR

Nikolay Pelov <nikip@iname.com>

=head1 SEE ALSO

PAM Application developer's Manual

=cut
