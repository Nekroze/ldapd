extern (C):

import lber;

alias ldapapiinfo LDAPAPIInfo;
alias ldap_apifeature_info LDAPAPIFeatureInfo;
alias ldapcontrol LDAPControl;
alias ldapmsg LDAPMessage;
alias ldapmod LDAPMod;
alias ldap LDAP;
alias ldap_url_desc LDAPURLDesc;
alias _Anonymous_0 ldap_sync_refresh_t;
alias int function (ldap_sync_t*, ldapmsg*, berval*, _Anonymous_0) ldap_sync_search_entry_f;
alias int function (ldap_sync_t*, ldapmsg*) ldap_sync_search_reference_f;
alias int function (ldap_sync_t*, ldapmsg*, berval*, _Anonymous_0) ldap_sync_intermediate_f;
alias int function (ldap_sync_t*, ldapmsg*, int) ldap_sync_search_result_f;
alias int ldap_conn_add_f;
alias void ldap_conn_del_f;
alias int LDAP_REBIND_PROC;
alias int LDAP_NEXTREF_PROC;
alias int LDAP_URLLIST_PROC;
alias int LDAP_SASL_INTERACT_PROC;
alias ldap_ava LDAPAVA;
alias ldap_ava** LDAPRDN;
alias ldap_ava*** LDAPDN;
alias int LDAPDN_rewrite_func;
alias ldapsortkey LDAPSortKey;
alias ldapvlvinfo LDAPVLVInfo;
alias passpolicyerror_enum LDAPPasswordPolicyError;

enum _Anonymous_0
{
	LDAP_SYNC_CAPI_NONE = -1,
	LDAP_SYNC_CAPI_PHASE_FLAG = 16,
	LDAP_SYNC_CAPI_IDSET_FLAG = 32,
	LDAP_SYNC_CAPI_DONE_FLAG = 64,
	LDAP_SYNC_CAPI_PRESENT = 0,
	LDAP_SYNC_CAPI_ADD = 1,
	LDAP_SYNC_CAPI_MODIFY = 2,
	LDAP_SYNC_CAPI_DELETE = 3,
	LDAP_SYNC_CAPI_PRESENTS = 16,
	LDAP_SYNC_CAPI_DELETES = 19,
	LDAP_SYNC_CAPI_PRESENTS_IDSET = 48,
	LDAP_SYNC_CAPI_DELETES_IDSET = 51,
	LDAP_SYNC_CAPI_DONE = 80
}

enum passpolicyerror_enum
{
	PP_passwordExpired = 0,
	PP_accountLocked = 1,
	PP_changeAfterReset = 2,
	PP_passwordModNotAllowed = 3,
	PP_mustSupplyOldPassword = 4,
	PP_insufficientPasswordQuality = 5,
	PP_passwordTooShort = 6,
	PP_passwordTooYoung = 7,
	PP_passwordInHistory = 8,
	PP_noError = 65535
}

struct ldapapiinfo
{
	int ldapai_info_version;
	int ldapai_api_version;
	int ldapai_protocol_version;
	char** ldapai_extensions;
	char* ldapai_vendor_name;
	int ldapai_vendor_version;
}

struct ldap_apifeature_info
{
	int ldapaif_info_version;
	char* ldapaif_name;
	int ldapaif_version;
}

struct ldapcontrol
{
	char* ldctl_oid;
	berval ldctl_value;
	char ldctl_iscritical;
}

struct ldapmod
{
	int mod_op;
	char* mod_type;
	union mod_vals_u
	{
		char** modv_strvals;
		berval** modv_bvals;
	}
	mod_vals_u mod_vals;
}

struct ldap_url_desc
{
	ldap_url_desc* lud_next;
	char* lud_scheme;
	char* lud_host;
	int lud_port;
	char* lud_dn;
	char** lud_attrs;
	int lud_scope;
	char* lud_filter;
	char** lud_exts;
	int lud_crit_exts;
}

struct ldap_sync_t
{
	char* ls_base;
	int ls_scope;
	char* ls_filter;
	char** ls_attrs;
	int ls_timelimit;
	int ls_sizelimit;
	int ls_timeout;
	ldap_sync_search_entry_f ls_search_entry;
	ldap_sync_search_reference_f ls_search_reference;
	ldap_sync_intermediate_f ls_intermediate;
	ldap_sync_search_result_f ls_search_result;
	void* ls_private;
	LDAP* ls_ld;
	int ls_msgid;
	int ls_reloadHint;
	berval ls_cookie;
	ldap_sync_refresh_t ls_refreshPhase;
}

struct ldap_conncb
{
	int function (LDAP*, Sockbuf*, LDAPURLDesc*, sockaddr*, ldap_conncb*) lc_add;
	void function (LDAP*, Sockbuf*, ldap_conncb*) lc_del;
	void* lc_arg;
}

struct ldap_ava
{
	berval la_attr;
	berval la_value;
	uint la_flags;
	void* la_private;
}

struct ldapsortkey
{
	char* attributeType;
	char* orderingRule;
	int reverseOrder;
}

struct ldapvlvinfo
{
	ber_int_t ldvlv_version;
	ber_int_t ldvlv_before_count;
	ber_int_t ldvlv_after_count;
	ber_int_t ldvlv_offset;
	ber_int_t ldvlv_count;
	berval* ldvlv_attrvalue;
	berval* ldvlv_context;
	void* ldvlv_extradata;
}

struct LDAPDerefSpec
{
	char* derefAttr;
	char** attributes;
}

struct LDAPDerefVal
{
	char* type;
	BerVarray vals;
	LDAPDerefVal* next;
}

struct LDAPDerefRes
{
	char* derefAttr;
	berval derefVal;
	LDAPDerefVal* attrVals;
	LDAPDerefRes* next;
}

struct timeval;


struct sockaddr;


struct ldapmsg;


struct ldap;


int ldap_get_option (LDAP* ld, int option, void* outvalue);
int ldap_set_option (LDAP* ld, int option, const(void)* invalue);
int ldap_set_rebind_proc (LDAP* ld, int function (LDAP*, const(char)*, ber_tag_t, ber_int_t, void*) rebind_proc, void* params);
int ldap_set_nextref_proc (LDAP* ld, int function (LDAP*, char***, int*, void*) nextref_proc, void* params);
int ldap_set_urllist_proc (LDAP* ld, int function (LDAP*, LDAPURLDesc**, LDAPURLDesc**, void*) urllist_proc, void* params);
int ldap_control_create (const(char)* requestOID, int iscritical, berval* value, int dupval, LDAPControl** ctrlp);
LDAPControl* ldap_control_find (const(char)* oid, LDAPControl** ctrls, LDAPControl*** nextctrlp);
void ldap_control_free (LDAPControl* ctrl);
void ldap_controls_free (LDAPControl** ctrls);
LDAPControl** ldap_controls_dup (LDAPControl** controls);
LDAPControl* ldap_control_dup (const(LDAPControl)* c);
int ldap_domain2dn (const(char)* domain, char** dn);
int ldap_dn2domain (const(char)* dn, char** domain);
int ldap_domain2hostlist (const(char)* domain, char** hostlist);
int ldap_extended_operation (LDAP* ld, const(char)* reqoid, berval* reqdata, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_extended_operation_s (LDAP* ld, const(char)* reqoid, berval* reqdata, LDAPControl** serverctrls, LDAPControl** clientctrls, char** retoidp, berval** retdatap);
int ldap_parse_extended_result (LDAP* ld, LDAPMessage* res, char** retoidp, berval** retdatap, int freeit);
int ldap_parse_intermediate (LDAP* ld, LDAPMessage* res, char** retoidp, berval** retdatap, LDAPControl*** serverctrls, int freeit);
int ldap_abandon_ext (LDAP* ld, int msgid, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_add_ext (LDAP* ld, const(char)* dn, LDAPMod** attrs, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_add_ext_s (LDAP* ld, const(char)* dn, LDAPMod** attrs, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_sasl_bind (LDAP* ld, const(char)* dn, const(char)* mechanism, berval* cred, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_sasl_interactive_bind (LDAP* ld, const(char)* dn, const(char)* saslMechanism, LDAPControl** serverControls, LDAPControl** clientControls, uint flags, int function (LDAP*, uint, void*, void*) proc, void* defaults, LDAPMessage* result, const(char*)* rmech, int* msgid);
int ldap_sasl_interactive_bind_s (LDAP* ld, const(char)* dn, const(char)* saslMechanism, LDAPControl** serverControls, LDAPControl** clientControls, uint flags, int function (LDAP*, uint, void*, void*) proc, void* defaults);
int ldap_sasl_bind_s (LDAP* ld, const(char)* dn, const(char)* mechanism, berval* cred, LDAPControl** serverctrls, LDAPControl** clientctrls, berval** servercredp);
int ldap_parse_sasl_bind_result (LDAP* ld, LDAPMessage* res, berval** servercredp, int freeit);
int ldap_compare_ext (LDAP* ld, const(char)* dn, const(char)* attr, berval* bvalue, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_compare_ext_s (LDAP* ld, const(char)* dn, const(char)* attr, berval* bvalue, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_delete_ext (LDAP* ld, const(char)* dn, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_delete_ext_s (LDAP* ld, const(char)* dn, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_parse_result (LDAP* ld, LDAPMessage* res, int* errcodep, char** matcheddnp, char** errmsgp, char*** referralsp, LDAPControl*** serverctrls, int freeit);
char* ldap_err2string (int err);
int ldap_gssapi_bind (LDAP* ld, const(char)* dn, const(char)* creds);
int ldap_gssapi_bind_s (LDAP* ld, const(char)* dn, const(char)* creds);
int ldap_modify_ext (LDAP* ld, const(char)* dn, LDAPMod** mods, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_modify_ext_s (LDAP* ld, const(char)* dn, LDAPMod** mods, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_rename (LDAP* ld, const(char)* dn, const(char)* newrdn, const(char)* newSuperior, int deleteoldrdn, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_rename_s (LDAP* ld, const(char)* dn, const(char)* newrdn, const(char)* newSuperior, int deleteoldrdn, LDAPControl** sctrls, LDAPControl** cctrls);
int ldap_create (LDAP** ldp);
int ldap_initialize (LDAP** ldp, const(char)* url);
LDAP* ldap_dup (LDAP* old);
int ldap_tls_inplace (LDAP* ld);
int ldap_start_tls (LDAP* ld, LDAPControl** serverctrls, LDAPControl** clientctrls, int* msgidp);
int ldap_install_tls (LDAP* ld);
int ldap_start_tls_s (LDAP* ld, LDAPControl** serverctrls, LDAPControl** clientctrls);
LDAPMessage* ldap_first_message (LDAP* ld, LDAPMessage* chain);
LDAPMessage* ldap_next_message (LDAP* ld, LDAPMessage* msg);
int ldap_count_messages (LDAP* ld, LDAPMessage* chain);
LDAPMessage* ldap_first_reference (LDAP* ld, LDAPMessage* chain);
LDAPMessage* ldap_next_reference (LDAP* ld, LDAPMessage* ref_);
int ldap_count_references (LDAP* ld, LDAPMessage* chain);
int ldap_parse_reference (LDAP* ld, LDAPMessage* ref_, char*** referralsp, LDAPControl*** serverctrls, int freeit);
LDAPMessage* ldap_first_entry (LDAP* ld, LDAPMessage* chain);
LDAPMessage* ldap_next_entry (LDAP* ld, LDAPMessage* entry);
int ldap_count_entries (LDAP* ld, LDAPMessage* chain);
int ldap_get_entry_controls (LDAP* ld, LDAPMessage* entry, LDAPControl*** serverctrls);
LDAPMessage* ldap_delete_result_entry (LDAPMessage** list, LDAPMessage* e);
void ldap_add_result_entry (LDAPMessage** list, LDAPMessage* e);
char* ldap_get_dn (LDAP* ld, LDAPMessage* entry);
void ldap_rdnfree (LDAPRDN rdn);
void ldap_dnfree (LDAPDN dn);
int ldap_bv2dn (berval* bv, LDAPDN* dn, uint flags);
int ldap_str2dn (const(char)* str, LDAPDN* dn, uint flags);
int ldap_dn2bv (LDAPDN dn, berval* bv, uint flags);
int ldap_dn2str (LDAPDN dn, char** str, uint flags);
int ldap_bv2rdn (berval* bv, LDAPRDN* rdn, char** next, uint flags);
int ldap_str2rdn (const(char)* str, LDAPRDN* rdn, char** next, uint flags);
int ldap_rdn2bv (LDAPRDN rdn, berval* bv, uint flags);
int ldap_rdn2str (LDAPRDN rdn, char** str, uint flags);
int ldap_dn_normalize (const(char)* in_, uint iflags, char** out_, uint oflags);
char* ldap_dn2ufn (const(char)* dn);
char** ldap_explode_dn (const(char)* dn, int notypes);
char** ldap_explode_rdn (const(char)* rdn, int notypes);
int ldap_X509dn2bv (void* x509_name, berval* dn, int function (LDAPDN, uint, void*) func, uint flags);
char* ldap_dn2dcedn (const(char)* dn);
char* ldap_dcedn2dn (const(char)* dce);
char* ldap_dn2ad_canonical (const(char)* dn);
int ldap_get_dn_ber (LDAP* ld, LDAPMessage* e, BerElement** berout, berval* dn);
int ldap_get_attribute_ber (LDAP* ld, LDAPMessage* e, BerElement* ber, berval* attr, berval** vals);
char* ldap_first_attribute (LDAP* ld, LDAPMessage* entry, BerElement** ber);
char* ldap_next_attribute (LDAP* ld, LDAPMessage* entry, BerElement* ber);
berval** ldap_get_values_len (LDAP* ld, LDAPMessage* entry, const(char)* target);
int ldap_count_values_len (berval** vals);
void ldap_value_free_len (berval** vals);
int ldap_result (LDAP* ld, int msgid, int all, timeval* timeout, LDAPMessage** result);
int ldap_msgtype (LDAPMessage* lm);
int ldap_msgid (LDAPMessage* lm);
int ldap_msgfree (LDAPMessage* lm);
int ldap_msgdelete (LDAP* ld, int msgid);
int ldap_bv2escaped_filter_value (berval* in_, berval* out_);
int ldap_search_ext (LDAP* ld, const(char)* base, int scope_, const(char)* filter, char** attrs, int attrsonly, LDAPControl** serverctrls, LDAPControl** clientctrls, timeval* timeout, int sizelimit, int* msgidp);
int ldap_search_ext_s (LDAP* ld, const(char)* base, int scope_, const(char)* filter, char** attrs, int attrsonly, LDAPControl** serverctrls, LDAPControl** clientctrls, timeval* timeout, int sizelimit, LDAPMessage** res);
int ldap_unbind_ext (LDAP* ld, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_unbind_ext_s (LDAP* ld, LDAPControl** serverctrls, LDAPControl** clientctrls);
int ldap_destroy (LDAP* ld);
int ldap_put_vrFilter (BerElement* ber, const(char)* vrf);
void* ldap_memalloc (ber_len_t s);
void* ldap_memrealloc (void* p, ber_len_t s);
void* ldap_memcalloc (ber_len_t n, ber_len_t s);
void ldap_memfree (void* p);
void ldap_memvfree (void** v);
char* ldap_strdup (const(char)*);
void ldap_mods_free (LDAPMod** mods, int freemods);
int ldap_is_ldap_url (const(char)* url);
int ldap_is_ldaps_url (const(char)* url);
int ldap_is_ldapi_url (const(char)* url);
int ldap_url_parse (const(char)* url, LDAPURLDesc** ludpp);
char* ldap_url_desc2str (LDAPURLDesc* ludp);
void ldap_free_urldesc (LDAPURLDesc* ludp);
int ldap_cancel (LDAP* ld, int cancelid, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_cancel_s (LDAP* ld, int cancelid, LDAPControl** sctrl, LDAPControl** cctrl);
int ldap_turn (LDAP* ld, int mutual, const(char)* identifier, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_turn_s (LDAP* ld, int mutual, const(char)* identifier, LDAPControl** sctrl, LDAPControl** cctrl);
int ldap_create_page_control_value (LDAP* ld, ber_int_t pagesize, berval* cookie, berval* value);
int ldap_create_page_control (LDAP* ld, ber_int_t pagesize, berval* cookie, int iscritical, LDAPControl** ctrlp);
int ldap_parse_pageresponse_control (LDAP* ld, LDAPControl* ctrl, ber_int_t* count, berval* cookie);
int ldap_create_sort_keylist (LDAPSortKey*** sortKeyList, char* keyString);
void ldap_free_sort_keylist (LDAPSortKey** sortkeylist);
int ldap_create_sort_control_value (LDAP* ld, LDAPSortKey** keyList, berval* value);
int ldap_create_sort_control (LDAP* ld, LDAPSortKey** keyList, int iscritical, LDAPControl** ctrlp);
int ldap_parse_sortresponse_control (LDAP* ld, LDAPControl* ctrl, ber_int_t* result, char** attribute);
int ldap_create_vlv_control_value (LDAP* ld, LDAPVLVInfo* ldvlistp, berval* value);
int ldap_create_vlv_control (LDAP* ld, LDAPVLVInfo* ldvlistp, LDAPControl** ctrlp);
int ldap_parse_vlvresponse_control (LDAP* ld, LDAPControl* ctrls, ber_int_t* target_posp, ber_int_t* list_countp, berval** contextp, int* errcodep);
int ldap_parse_whoami (LDAP* ld, LDAPMessage* res, berval** authzid);
int ldap_whoami (LDAP* ld, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_whoami_s (LDAP* ld, berval** authzid, LDAPControl** sctrls, LDAPControl** cctrls);
int ldap_parse_passwd (LDAP* ld, LDAPMessage* res, berval* newpasswd);
int ldap_passwd (LDAP* ld, berval* user, berval* oldpw, berval* newpw, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_passwd_s (LDAP* ld, berval* user, berval* oldpw, berval* newpw, berval* newpasswd, LDAPControl** sctrls, LDAPControl** cctrls);
int ldap_create_passwordpolicy_control (LDAP* ld, LDAPControl** ctrlp);
int ldap_parse_passwordpolicy_control (LDAP* ld, LDAPControl* ctrl, ber_int_t* expirep, ber_int_t* gracep, LDAPPasswordPolicyError* errorp);
const(char)* ldap_passwordpolicy_err2txt (LDAPPasswordPolicyError);
int ldap_parse_refresh (LDAP* ld, LDAPMessage* res, ber_int_t* newttl);
int ldap_refresh (LDAP* ld, berval* dn, ber_int_t ttl, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_refresh_s (LDAP* ld, berval* dn, ber_int_t ttl, ber_int_t* newttl, LDAPControl** sctrls, LDAPControl** cctrls);
ldap_sync_t* ldap_sync_initialize (ldap_sync_t* ls);
void ldap_sync_destroy (ldap_sync_t* ls, int freeit);
int ldap_sync_init (ldap_sync_t* ls, int mode);
int ldap_sync_init_refresh_only (ldap_sync_t* ls);
int ldap_sync_init_refresh_and_persist (ldap_sync_t* ls);
int ldap_sync_poll (ldap_sync_t* ls);
int ldap_create_session_tracking_value (LDAP* ld, char* sessionSourceIp, char* sessionSourceName, char* formatOID, berval* sessionTrackingIdentifier, berval* value);
int ldap_create_session_tracking_control (LDAP* ld, char* sessionSourceIp, char* sessionSourceName, char* formatOID, berval* sessionTrackingIdentifier, LDAPControl** ctrlp);
int ldap_parse_session_tracking_control (LDAP* ld, LDAPControl* ctrl, berval* ip, berval* name, berval* oid, berval* id);
int ldap_create_assertion_control_value (LDAP* ld, char* assertion, berval* value);
int ldap_create_assertion_control (LDAP* ld, char* filter, int iscritical, LDAPControl** ctrlp);
int ldap_create_deref_control_value (LDAP* ld, LDAPDerefSpec* ds, berval* value);
int ldap_create_deref_control (LDAP* ld, LDAPDerefSpec* ds, int iscritical, LDAPControl** ctrlp);
void ldap_derefresponse_free (LDAPDerefRes* dr);
int ldap_parse_derefresponse_control (LDAP* ld, LDAPControl* ctrl, LDAPDerefRes** drp);
int ldap_parse_deref_control (LDAP* ld, LDAPControl** ctrls, LDAPDerefRes** drp);
int ldap_ntlm_bind (LDAP* ld, const(char)* dn, ber_tag_t tag, berval* cred, LDAPControl** sctrls, LDAPControl** cctrls, int* msgidp);
int ldap_parse_ntlm_bind_result (LDAP* ld, LDAPMessage* res, berval* challenge);