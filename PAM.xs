#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include <security/pam_appl.h>

/* 
   Comment the following line if your PAM library doesn't have the 
   pam_get/putenv set of functions (i.e. PAM versions before 0.54).
   Please tell me if you know some automatic way to determine this.
*/

/* #define HAVE_PAM_ENV_FUNCTIONS */


#ifdef sun
/* The Solaris 2.6 and the Linux header file differ here. */
#define PAM_GET_ITEM_ARG3_TYPE	void **
#else
#define PAM_GET_ITEM_ARG3_TYPE	const void **
#endif

static int
conv_func(num_msg, msg, resp, appdata_ptr)
        int num_msg;
        const struct pam_message **msg;
        struct pam_response **resp;
        void *appdata_ptr;
{
        int i,res_cnt,res;
	STRLEN len;
        struct pam_response* reply = NULL;
        SV * strSV;
        char * str;
        dSP;

        ENTER;
        SAVETMPS;

        PUSHMARK(sp);
        for (i = 0; i < num_msg; i++) {
            XPUSHs(sv_2mortal(newSViv(msg[i]->msg_style)));
            XPUSHs(sv_2mortal(newSVpv(msg[i]->msg, 0)));
        }
        PUTBACK;

        res_cnt = perl_call_sv(appdata_ptr, G_ARRAY);

        SPAGAIN;

        if (res_cnt & 1 != 0) {
	    res = POPi;
	    res_cnt --;
	    if (res_cnt > 0) {
		res_cnt /= 2;
        	reply = malloc( res_cnt * sizeof(struct pam_response));
        	for (i = res_cnt - 1; i >= 0; i--) {
        	    strSV = POPs;
        	    str = SvPV(strSV, len);
        	    reply[i].resp_retcode = POPi;
        	    if (len == 0)
        		reply[i].resp = NULL;
        	    else {
        		reply[i].resp = malloc(len+1);
    			memcpy(reply[i].resp, str, len);
  			reply[i].resp[len] = 0;
	            }
/*
		printf("Code %d and str %s\n",  reply[i].resp_retcode, 
						reply[i].resp);
*/
           	}
	    }
        } 
        else {
	    croak("The PAM conversation function must return an odd number"
		  "of values!");
	    res = PAM_CONV_ERR;
	}

        PUTBACK;

        FREETMPS;
        LEAVE;

        if (reply != NULL) {
            *resp = reply;
        }

	return res;
}

void set_conv_func(conv, func)
	struct pam_conv *	conv;
	SV *	func;
{
    if (conv == 0 || func == 0)
	croak("Error in setting conv function");

    conv->conv = conv_func;
    if (conv->appdata_ptr == 0) {
        conv->appdata_ptr = newSVsv(func);
    }
    else {
        sv_setsv(conv->appdata_ptr, func);
    }
}

void free_conv_func(conv)
	struct pam_conv *       conv;
{
    if (conv == 0)
	croak("Error in freeing conv function");

    if (conv->appdata_ptr != 0) {
	SvREFCNT_dec((SV*)conv->appdata_ptr); 
	conv->appdata_ptr = 0;
    }
}


static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
  
    /* error codes */
    if (strcmp(name, "PAM_SUCCESS") == 0)
	return PAM_SUCCESS;
    else if (strcmp(name, "PAM_OPEN_ERR") == 0)
	return PAM_OPEN_ERR;
    else if (strcmp(name, "PAM_SYMBOL_ERR") == 0)
	return PAM_SYMBOL_ERR;
    else if (strcmp(name, "PAM_SERVICE_ERR") == 0)
	return PAM_SERVICE_ERR;
    else if (strcmp(name, "PAM_SYSTEM_ERR") == 0)
	return PAM_SYSTEM_ERR;
    else if (strcmp(name, "PAM_BUF_ERR") == 0)
	return PAM_BUF_ERR;
    else if (strcmp(name, "PAM_PERM_DENIED") == 0)
	return PAM_PERM_DENIED;
    else if (strcmp(name, "PAM_AUTH_ERR") == 0)
        return PAM_AUTH_ERR;
    else if (strcmp(name, "PAM_CRED_INSUFFICIENT") == 0)
        return PAM_CRED_INSUFFICIENT;
    else if (strcmp(name, "PAM_AUTHINFO_UNAVAIL") == 0)
        return PAM_AUTHINFO_UNAVAIL;
    else if (strcmp(name, "PAM_USER_UNKNOWN") == 0)
        return PAM_USER_UNKNOWN;
    else if (strcmp(name, "PAM_MAXTRIES") == 0)
        return PAM_MAXTRIES;
    else if (strcmp(name, "PAM_NEW_AUTHTOK_REQD") == 0 ||
	     strcmp(name, "PAM_AUTHTOKEN_REQD") == 0)
#if defined(PAM_NEW_AUTHTOK_REQD)
        return PAM_NEW_AUTHTOK_REQD;
#elif defined(PAM_AUTHTOKEN_REQD)
	return PAM_AUTHTOKEN_REQD;
#else
	goto not_there;
#endif
    else if (strcmp(name, "PAM_ACCT_EXPIRED") == 0)
        return PAM_ACCT_EXPIRED;
    else if (strcmp(name, "PAM_SESSION_ERR") == 0)
        return PAM_SESSION_ERR;
    else if (strcmp(name, "PAM_CRED_UNAVAIL") == 0)
        return PAM_CRED_UNAVAIL;
    else if (strcmp(name, "PAM_CRED_EXPIRED") == 0)
        return PAM_CRED_EXPIRED;
    else if (strcmp(name, "PAM_CRED_ERR") == 0)
        return PAM_CRED_ERR;
    else if (strcmp(name, "PAM_NO_MODULE_DATA") == 0)
        return PAM_NO_MODULE_DATA;
    else if (strcmp(name, "PAM_CONV_ERR") == 0)
        return PAM_CONV_ERR;
    else if (strcmp(name, "PAM_AUTHTOK_ERR") == 0)
        return PAM_AUTHTOK_ERR;
    else if (strcmp(name, "PAM_AUTHTOK_RECOVER_ERR") == 0 ||
	     strcmp(name, "PAM_AUTHTOK_RECOVERY_ERR") == 0)
#if defined(PAM_AUTHTOK_RECOVER_ERR)
        return PAM_AUTHTOK_RECOVER_ERR;
#elif defined(PAM_AUTHTOK_RECOVERY_ERR)
	return PAM_AUTHTOK_RECOVERY_ERR;
#else
	goto not_there;
#endif
    else if (strcmp(name, "PAM_AUTHTOK_LOCK_BUSY") == 0)
        return PAM_AUTHTOK_LOCK_BUSY;
    else if (strcmp(name, "PAM_AUTHTOK_DISABLE_AGING") == 0)
        return PAM_AUTHTOK_DISABLE_AGING;
    else if (strcmp(name, "PAM_TRY_AGAIN") == 0)
        return PAM_TRY_AGAIN;
    else if (strcmp(name, "PAM_IGNORE") == 0)
        return PAM_IGNORE;
    else if (strcmp(name, "PAM_ABORT") == 0)
        return PAM_ABORT;
    else if (strcmp(name, "PAM_AUTHTOK_EXPIRED") == 0)
#if defined(PAM_AUTHTOK_EXPIRED)
        return PAM_AUTHTOK_EXPIRED;
#else
	goto not_there;
#endif
    else if (strcmp(name, "PAM_BAD_ITEM") == 0)
#if defined(PAM_BAD_ITEM)
	return PAM_BAD_ITEM;
#else
	goto not_there;
#endif


    /* set/get_item constants */
    else if (strcmp(name, "PAM_SERVICE") == 0)
	return PAM_SERVICE;
    else if (strcmp(name, "PAM_USER") == 0)
        return PAM_USER;
    else if (strcmp(name, "PAM_TTY") == 0)
        return PAM_TTY;
    else if (strcmp(name, "PAM_RHOST") == 0)
        return PAM_RHOST;
    else if (strcmp(name, "PAM_CONV") == 0)
        return PAM_CONV;
    /* module flags */
    else if (strcmp(name, "PAM_AUTHTOK") == 0)
        return PAM_CONV;
    else if (strcmp(name, "PAM_OLDAUTHTOK") == 0)
        return PAM_CONV;

    else if (strcmp(name, "PAM_RUSER") == 0)
	return PAM_RUSER;
    else if (strcmp(name, "PAM_USER_PROMPT") == 0)
	return PAM_USER_PROMPT;

    /* global flag */
    else if (strcmp(name, "PAM_SILENT") == 0)
        return PAM_SILENT;
    /* pam_authenticate falgs */
    else if (strcmp(name, "PAM_DISALLOW_NULL_AUTHTOK") == 0)
	return PAM_DISALLOW_NULL_AUTHTOK;
    /* pam_set_cred flags */
    else if (strcmp(name, "PAM_ESTABLISH_CRED") == 0 ||
	     strcmp(name, "PAM_CRED_ESTABLISH") == 0)
#if defined(PAM_ESTABLISH_CRED)
        return PAM_ESTABLISH_CRED;
#elif defined(PAM_CRED_ESTABLISH)
	return PAM_CRED_ESTABLISH;
#else
	goto not_there;
#endif
    else if (strcmp(name, "PAM_DELETE_CRED") == 0 ||
	     strcmp(name, "PAM_CRED_DELETE") == 0)
#if defined(PAM_DELETE_CRED)
        return PAM_DELETE_CRED;
#elif defined(PAM_CRED_DELETE)
	return PAM_CRED_DELETE;
#else
	goto not_there;
#endif
    else if (strcmp(name, "PAM_REINITIALIZE_CRED") == 0 ||
	     strcmp(name, "PAM_CRED_REINITIALIZE") == 0)
#if defined(PAM_REINITIALIZE_CRED)
        return PAM_REINITIALIZE_CRED;
#elif defined(PAM_CRED_REINITIALIZE)
	return PAM_CRED_REINITIALIZE;
#else
	goto not_there;
#endif
    else if (strcmp(name, "PAM_REFRESH_CRED") == 0 ||
	     strcmp(name, "PAM_CRED_REFRESH") == 0)
#if defined(PAM_REFRESH_CRED)
        return PAM_REFRESH_CRED;
#elif defined(PAM_CRED_REFRESH)
	return PAM_CRED_REFRESH;
#else
	goto not_there;
#endif
    /* pam_chauthtok flags */
    else if (strcmp(name, "PAM_CHANGE_EXPIRED_AUTHTOK") == 0)
        return PAM_CHANGE_EXPIRED_AUTHTOK;

    /* message style constants */
    else if (strcmp(name, "PAM_PROMPT_ECHO_OFF") == 0)
        return PAM_PROMPT_ECHO_OFF;
    else if (strcmp(name, "PAM_PROMPT_ECHO_ON") == 0)
        return PAM_PROMPT_ECHO_ON;
    else if (strcmp(name, "PAM_ERROR_MSG") == 0)
        return PAM_ERROR_MSG;
    else if (strcmp(name, "PAM_TEXT_INFO") == 0)
        return PAM_TEXT_INFO;
    else if (strcmp(name, "PAM_RADIO_TYPE") == 0)
#if defined(PAM_RADIO_TYPE)
        return PAM_RADIO_TYPE;
#else
	goto not_there;
#endif

    /* additional features */
    else if (strcmp(name, "HAVE_PAM_FAIL_DELAY") == 0)
#if defined(HAVE_PAM_FAIL_DELAY)
	return 1;
#else
	return 0;
#endif
    else if (strcmp(name, "HAVE_PAM_ENV_FUNCTIONS") == 0)
#if defined(HAVE_PAM_ENV_FUNCTIONS)
	return 1;
#else
	return 0;
#endif
/*
    else if (strcmp(name, "HAVE_PAM_SYSTEM_LOG") == 0)
#if defined(HAVE_PAM_SYSTEM_LOG)
	return 1;
#else
	return 0;
#endif
*/

    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = Authen::PAM	PACKAGE = Authen::PAM

PROTOTYPES: ENABLE


double
constant(name,arg)
	char *		name
	int		arg


int
pam_set_item(pamh, item_type, item)
	pam_handle_t *	pamh
	int	item_type
	char *	item
	PREINIT:
	  struct pam_conv *conv_st;
	  int res;
	CODE:
	  if (item_type == PAM_CONV) {
	    res = pam_get_item( pamh, PAM_CONV, 
				(PAM_GET_ITEM_ARG3_TYPE)&conv_st);
	    if (res == PAM_SUCCESS) {
	        set_conv_func(conv_st, item);
	        RETVAL = pam_set_item( pamh, PAM_CONV, conv_st);
	    } 
	    else
	        RETVAL = res;
	  }
	  else
	    RETVAL = pam_set_item( pamh, item_type, item);
	OUTPUT:
	RETVAL
	
int
pam_get_item(pamh, item_type, item)
	pam_handle_t * 	pamh
	int	item_type
	SV *	item
	PREINIT:
	  char * c;
	  struct pam_conv * conv_st;
	  int res;
	CODE:
	  if (item_type == PAM_CONV) {
	      res = pam_get_item( pamh, PAM_CONV, 
					(PAM_GET_ITEM_ARG3_TYPE)&conv_st);
	      if (res == PAM_SUCCESS) 
	          sv_setsv(item, conv_st->appdata_ptr);
	      RETVAL = res;
	  }
	  else {
	      RETVAL = pam_get_item( pamh, item_type, 
					(PAM_GET_ITEM_ARG3_TYPE)&c);
	      sv_setpv(item, c);
	  }
	OUTPUT:
	item
	RETVAL

const char *
pam_strerror(pamh, errnum)
	pam_handle_t *	pamh
	int	errnum
	CODE:
#if defined(PAM_NEW_AUTHTOK_REQD)
	  RETVAL = pam_strerror(pamh, errnum);
#else
	  RETVAL = pam_strerror(errnum);
#endif
	OUTPUT:
	RETVAL

#if defined(HAVE_PAM_ENV_FUNCTIONS)
int
pam_putenv(pamh, name_value)
	pam_handle_t * pamh
	const char *	name_value
	CODE:
	  RETVAL = pam_putenv(pamh, name_value);
	OUTPUT:
	RETVAL

const char *
pam_getenv(pamh, name)
	pam_handle_t *	pamh
	const char *	name
	CODE:
	  RETVAL = pam_getenv(pamh, name);
	OUTPUT:
	RETVAL

void
_pam_getenvlist(pamh)
	pam_handle_t *	pamh
	PREINIT:
	  char ** res;
	  int i;
	  int c;
	PPCODE:
	  res = pam_getenvlist(pamh);
	  c = 0;
	  while (res[c] != 0)
	      c++;
	  EXTEND(sp, c);
	  for (i = 0; i < c; i++)
	      PUSHs(sv_2mortal(newSVpv(res[i],0)));

#else

int
pam_putenv(pamh, name_value)
	pam_handle_t * pamh
	const char *	name_value
	CODE:
	  not_here("pam_putenv");

const char *
pam_getenv(pamh, name)
	pam_handle_t *	pamh
	const char *	name
	CODE:
	  not_here("pam_getenv");


void
_pam_getenvlist(pamh)
	pam_handle_t *	pamh
	CODE:
	  not_here("pam_getenvlist");


#endif


#if defined(HAVE_PAM_FAIL_DELAY)

int
pam_fail_delay(pamh, musec_delay)
	pam_handle_t *	pamh
	unsigned int	musec_delay
	CODE:
	  RETVAL = pam_fail_delay(pamh,musec_delay);
	OUTPUT:
	RETVAL

#else

void
pam_fail_delay(pamh, musec_delay)
	pam_handle_t *	pamh
	unsigned int	musec_delay
	CODE:
	  not_here("pam_fail_delay");

#endif


int
_pam_start(service_name, user, func, pamh)
	const char *	service_name
	const char *	user
	SV *	func
	pam_handle_t *	pamh = NO_INIT
	PREINIT:
	  struct pam_conv conv_st;
	CODE:
	  conv_st.appdata_ptr = 0;
	  set_conv_func(&conv_st, func);
	  RETVAL = pam_start(service_name, user, &conv_st, &pamh);
OUTPUT:
	pamh
	RETVAL

int
pam_end(pamh, pam_status=PAM_SUCCESS)
	pam_handle_t *	pamh
	int	pam_status
	PREINIT:
	  struct pam_conv *conv_st;
	  int res;
	CODE:
	  res = pam_get_item( pamh, PAM_CONV, 
				(PAM_GET_ITEM_ARG3_TYPE)&conv_st);
	  if (res == PAM_SUCCESS) {
	      free_conv_func(conv_st);
	      RETVAL = pam_end(pamh, pam_status);
	  }
	  else
	      RETVAL = res;
	OUTPUT:
	RETVAL

int
pam_authenticate(pamh, flags=0)
	pam_handle_t *	pamh
	int	flags
	CODE:
	  RETVAL = pam_authenticate(pamh,flags);
	OUTPUT:
	RETVAL

int
pam_setcred(pamh, flags)
	pam_handle_t *	pamh
	int	flags
	CODE:
	  RETVAL = pam_setcred(pamh,flags);
	OUTPUT:
	RETVAL

int
pam_acct_mgmt(pamh, flags=0)
	pam_handle_t *	pamh
	int	flags
	CODE:
	  RETVAL = pam_acct_mgmt(pamh,flags);
	OUTPUT:
	RETVAL

int
pam_open_session(pamh, flags=0)
	pam_handle_t *	pamh
	int	flags
	CODE:
	  RETVAL = pam_open_session(pamh,flags);
	OUTPUT:
	RETVAL

int
pam_close_session(pamh, flags=0)
	pam_handle_t *	pamh
	int	flags
	CODE:
	  RETVAL = pam_close_session(pamh, flags);
	OUTPUT:
	RETVAL

int
pam_chauthtok(pamh, flags=0)
	pam_handle_t *	pamh
	int	flags
	CODE:
	  RETVAL = pam_chauthtok(pamh, flags);
	OUTPUT:
	RETVAL
