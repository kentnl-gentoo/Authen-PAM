use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Authen::PAM',
    'VERSION_FROM' => 'PAM.pm', # finds $VERSION
    'LIBS'	=> ['-lpam'],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
    'dist'      => {COMPRESS=>'gzip', SUFFIX=>'gz'}
);
