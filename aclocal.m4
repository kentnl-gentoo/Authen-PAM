dnl-----------------------------------
dnl PAM_LIB_DL
dnl
AC_DEFUN(PAM_LIB_DL,
[AC_CACHE_CHECK(do we need -ldl when linking pam programs, pam_cv_lib_dl,
AC_TRY_LINK([
#include <security/pam_appl.h>],[pam_get_item((pam_handle_t*)0, 0, 0);],
pam_cv_lib_dl=no, pam_cv_lib_dl=yes))
if test $pam_cv_lib_dl = yes; then
    LIBS="$LIBS -ldl"
fi])

dnl-----------------------------------
dnl PAM_FUNC_ENV
dnl
AC_DEFUN(PAM_FUNC_ENV,
[AC_CACHE_CHECK(for environment handling functions, pam_cv_func_env,
AC_TRY_LINK([
#include <security/pam_appl.h>],[pam_getenv((pam_handle_t*)0, 0);],
pam_cv_func_env=yes, pam_cv_func_env=no))
if test $pam_cv_func_env = yes; then
    AC_DEFINE(HAVE_PAM_ENV_FUNCTIONS)
fi])

dnl-----------------------------------
dnl PAM_DECL_RTLD_GLOBAL
dnl
AC_DEFUN(PAM_DECL_RTLD_GLOBAL,
[AC_CACHE_CHECK(for RTLD_GLOBAL flag, pam_cv_decl_rtld_global,
AC_EGREP_CPP(have_rtld_global,
[#include <dlfcn.h>
#ifdef RTLD_GLOBAL
have_rtld_global
#endif],
pam_cv_decl_rtld_global=yes, pam_cv_decl_rtld_global=no))
if test $pam_cv_decl_rtld_global = yes; then
    DL_LOAD_FLAGS='sub dl_load_flags { 0x01 }'
else
    DL_LOAD_FLAGS=''
fi
AC_SUBST(DL_LOAD_FLAGS)
])
