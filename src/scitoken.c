#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_time.h"

#include <scitokens/scitokens.h>

#include <unistd.h>

#include "mod_auth.h"

/* ~~~~~~~~~~~~~~~~~~~~~~~~~  CONFIGURATION STRUCTURE ~~~~~~~~~~~~~~~~~~~~~~~~~  */

#define MAX_AUD 20
typedef struct {
	char** issuers;
	char** resources;
	int numberofissuer;
	int enforcing_flag;
	char audience_buf[255];
	char *aud_list[MAX_AUD+1];
} authz_scitoken_config_rec;

/* ~~~~~~~~~~~~~~~~~~~~~~~~~  DEFAULT CONFIGURATION ~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static void *create_authz_scitoken_dir_config(apr_pool_t *p, char *d)
{
    authz_scitoken_config_rec *conf = apr_palloc(p, sizeof(*conf));
    
    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "scitoken: new config allocation"); */
    char** issuers = calloc(1, sizeof(char*));
    char**resources = calloc(1, sizeof(char*));
    *(issuers) = "issuer";
    *(resources) = "resources";
    conf->audience_buf[0] = 0;
    conf->numberofissuer = 1;
    conf->issuers = issuers;
    conf->resources = resources;
    return conf;
}

//The default is to overwrite the old config, NOT merging
static void *merge_auth_scitoken_dir_config(apr_pool_t *p, void *basev, void *new_confv)
{
    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "scitoken: merging...");*/
    authz_scitoken_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    authz_scitoken_config_rec *base = basev;
    authz_scitoken_config_rec *new_conf = new_confv;
    memcpy(newconf, new_conf, sizeof(authz_scitoken_config_rec));
    newconf->numberofissuer = new_conf->numberofissuer ? new_conf->numberofissuer : base->numberofissuer;
    newconf->issuers = new_conf->issuers ? new_conf->issuers : base->issuers;
    newconf->resources = new_conf->resources ? new_conf->resources : base->resources;
    newconf->enforcing_flag = new_conf->enforcing_flag;
    return newconf;
}

/**
 * This function takes the argument "issuers" from the Apache configuration file
 * , parses the directive and sets the (module) configuration accordingly
 * Input: a string of issuers;resource seperated by ","
 *        "issuer1;resource1,issuer2;resource2...."
 */
static const char *set_scitoken_param_iss(cmd_parms *cmd, void *config, const char *issuersstr)
{
    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "scitoken: issuer %s"  , issuersstr); */
    authz_scitoken_config_rec *conf = (authz_scitoken_config_rec *)config;
    char *token = strtok((char *)issuersstr, ",");
    char *res;
    char *domain;
    int counter = 0;
    char** issuers = calloc(1, sizeof(char*));
    char** resources = calloc(1, sizeof(char*));
    while (token != NULL)
    {
        *(issuers+counter) = token;
        token = strtok(NULL, ",");
        counter+=1;
        issuers = realloc(issuers, (counter+1) * sizeof(char*));
        resources = realloc(resources, (counter+1) * sizeof(char*));
    }
    conf->numberofissuer = counter;//+1;
    counter = counter - 1;
    while (counter != -1)
    {
        domain = strtok(*(issuers+counter), ";");
        res = strtok(NULL, ";");
        *(issuers+counter) = domain;
        *(resources+counter) = res;
        counter -= 1;
    }
    conf->issuers = issuers;
    conf->resources = resources;
    return NULL;
}
/**
 * This function takes the argument "exp" from the Apache configuration file
 * , parses the directive and sets the (module) configuration accordingly
 * NOT implemented
 */
static const char *set_scitoken_param_exp(cmd_parms *cmd, void *config, const char *issuersstr)
{
    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "scitoken: exp %s"  , issuersstr); */
    return NULL;
}


static const char *set_scitoken_param_audience(cmd_parms *cmd, void *config, const char *aud)
{
    authz_scitoken_config_rec *conf = config;
    int k = 1;
    char *pc = conf->audience_buf+1;

    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "scitoken audience: %s", aud); */
    strncpy(conf->audience_buf, aud, 255);

    conf->aud_list[0] = conf->audience_buf;
    conf->aud_list[1] = NULL;
    while(*pc && k < MAX_AUD) {
      if(*pc == ',') {
        *pc = 0;
        conf->aud_list[k++] = ++pc;
        conf->aud_list[k] = 0;
      } else {
        pc++;
      }
    }
    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Done splitting audience"); */
    return NULL;
}

static const char *set_scitoken_param_enforcing(cmd_parms *cmd, void *config, const char *flag)
{
    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "scitoken enforcing: %s", flag); */
    authz_scitoken_config_rec *conf = config;

    /* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Setting enforcing: flag: %s", flag); */

    if (flag[0] == 'f' || flag[0] == 'F' || flag[0] == 'n' || flag[0] == 'N'|| flag[0] == '0') {
        conf->enforcing_flag = 0;
    } else {
        conf->enforcing_flag = 1;
    }
    return NULL;
}
/**
 * This function takes the argument "alg" from the Apache configuration file
 * , parses the directive and sets the (module) configuration accordingly
 * NOT implemented
 */
static const char *set_scitoken_param_alg(cmd_parms *cmd, void *config, const char *issuersstr)
{
    return NULL;
}

static const command_rec authz_scitoken_cmds[] =
{
AP_INIT_TAKE1("issuers", set_scitoken_param_iss, NULL, OR_AUTHCFG, "list of issuers"),
AP_INIT_TAKE1("exp", set_scitoken_param_exp, NULL, OR_AUTHCFG, "Enable exp time validation"),
AP_INIT_TAKE1("alg", set_scitoken_param_alg, NULL, OR_AUTHCFG, "Enable algorithm validation"),
AP_INIT_TAKE1("enforcing", set_scitoken_param_enforcing, NULL, OR_AUTHCFG, "Enable/disable enforcer, default on"),
AP_INIT_TAKE1("audience", set_scitoken_param_audience, NULL, OR_AUTHCFG, "set audience"),
        {NULL}
};

/* ~~~~~~~~~~~~~~~~~~~~~~~~  AUTHZ HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

module AP_MODULE_DECLARE_DATA auth_scitoken_module;


/**
 * The main function to verify a Scitoken
 */
authz_status ScitokenVerify(request_rec *r, const char *require_line, const void *parsed_require_line) {
  SciToken scitoken;
  char *err_msg;
  const char *auth_line, *auth_scheme;
  const char *listofauthz= "COPY:write DELETE:write GET:read HEAD:read LOCK:write MKCOL:write MOVE:write OPTIONS:read POST:read PROPFIND:write PROPPATCH:write PUT:write TRACE:read UNLOCK:write";
  // Read scitoken into memory

  /* ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "starting token auth:"); */

  auth_line = apr_table_get(r->headers_in,"Authorization");
  if(auth_line == NULL){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Unauthorized.");
    return AUTHZ_DENIED;
  }
  /* ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Found authorization header"); */

  auth_scheme = ap_getword(r->pool, &auth_line, ' ');
  
  // Read configuration
  authz_scitoken_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &auth_scitoken_module);
  int numberofissuer = conf->numberofissuer;
  char *null_ended_list[numberofissuer+1];
  
  //Get the list of issuers from configuration and create a null ended list of strings
  for(int i = 0; i<numberofissuer; i++){
    null_ended_list[i] = *(conf->issuers+i);
  }
  null_ended_list[numberofissuer] = NULL;
  

  if (strcasecmp(auth_scheme, "Bearer")){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Wrong scheme");
    return AUTHZ_DENIED;
  }
  /* ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Checked scheme.."); */

  while (apr_isspace(*auth_line)) {
    auth_line++;
  }
  if(sizeof(auth_line)>1000*1000){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "SciToken too large");
    return AUTHZ_DENIED;
  }

  if(scitoken_deserialize(auth_line, &scitoken, (char const * const *) null_ended_list, &err_msg)){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to deserialize scitoken");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  
  int i;
  /* int k; */
  char *issuer_ptr = NULL;
  char *sub_ptr = NULL;
  char *aud_ptr = NULL;
  char *scope_ptr = NULL;
  char *wlcg_groups_ptr = NULL;
  if(!scitoken_get_claim_string(scitoken, "sub", &sub_ptr, &err_msg)) {
    apr_table_set(r->subprocess_env, "SCITOKEN_SUB", sub_ptr);
  }
  if(!scitoken_get_claim_string(scitoken, "aud", &aud_ptr, &err_msg)) {
    apr_table_set(r->subprocess_env, "SCITOKEN_AUD", aud_ptr);
  }
  if(!scitoken_get_claim_string(scitoken, "scope", &scope_ptr, &err_msg)) {
    apr_table_set(r->subprocess_env, "SCITOKEN_SCOPE", scope_ptr);
  }
  if(!scitoken_get_claim_string(scitoken, "wlcg.groups", &wlcg_groups_ptr, &err_msg)) {
    apr_table_set(r->subprocess_env, "SCITOKEN_WLCG_GROUPS", wlcg_groups_ptr);
  }
  if(scitoken_get_claim_string(scitoken, "iss", &issuer_ptr, &err_msg)) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to get issuer from token: %s\n",err_msg);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  apr_table_set(r->subprocess_env, "SCITOKEN_ISS", issuer_ptr);
  
  //Preparing for enforcer test
  Enforcer enf;

  char hostname[1024];
  char *host_aud_list[2];
  const char **aud_list;

  
  /* ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Audience buf: %s" , conf->audience_buf); */
  if ( conf->audience_buf[0] ) {
    /* k = 1; */
    aud_list = (const char **)conf->aud_list;
    for (i = 0; i < MAX_AUD; i++) {
        if (aud_list[i] == 0) {
           /* k = i; */
           break;
        }
    }
  } else  {
    aud_list = (const char **)host_aud_list;
    // Get the hostname for the audience. It is using hostname(NOT domain name). Set payload accordingly
    if (gethostname(hostname, 1024) != 0) {
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to get hostname");
      return AUTHZ_DENIED;
    }
    aud_list[0] = hostname;
    aud_list[1] = NULL;
    /* k = 1; */
  }
  /* 
   * ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Using audience:");
   * for(i = 0; i < k ; i++) {
   *     ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%d: %s" , i, aud_list[i]);
   * }
   */
  
  if (conf->enforcing_flag) {
    /* ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "enforcing_flag on.."); */

    if (!(enf = enforcer_create(issuer_ptr, aud_list, &err_msg))) {
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to create enforcer: %s", err_msg);
      return AUTHZ_DENIED;
    }
    
    Acl acl;
    acl.authz = "";
    acl.resource = "";
    //retrieve request type => acl.authz = read/write
    const char *requesttype = r->method;
    char *authzsubstr = strstr(listofauthz,requesttype);
    if(authzsubstr == NULL){
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Request type not supported(acl.authz)");
      return AUTHZ_DENIED;
    }
    //get the requestype:read/write substring
    char *substr = (char *)calloc(1, strchr(authzsubstr,' ') - authzsubstr + 1);
    memcpy(substr,authzsubstr,strchr(authzsubstr,' ') - authzsubstr);
    strtok(substr,":");
    acl.authz = strtok(NULL,":");
    //Resource is found/not found for the audience
    int found = 0;
    for(int i=0; i<conf->numberofissuer; i++){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s",issuer_ptr);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s",*(conf->issuers + i));
    if(*(issuer_ptr) == **(conf->issuers + i))
      {
      acl.resource = *(conf->resources + i);
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s",*(conf->resources + i));
      found = 1;
      break;
      }
    }
    if(!found){
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Resource not found");
      return AUTHZ_DENIED;
    }
    
    if( enforcer_test(enf, scitoken, &acl, &err_msg)) {
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed enforcer test: %s", err_msg);
      enforcer_destroy(enf);
      return AUTHZ_DENIED;
    } else {
      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "enforcer_tested..");
      enforcer_destroy(enf);
    }

  /* } else {
   * ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "enforcing_flag off.."); 
   */
  }

  // +1 for the null-terminator
  char *str = apr_palloc(r->pool, strlen("token:") + strlen(auth_line) + 1);
  strcpy(str, "token:");
  strcat(str, auth_line);
  
  // log the access
  /* ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, str, r->uri); */
  
  return AUTHZ_GRANTED;
  
}
/* ~~~~~~~~~~~~~~~~~~~~~~~~  APACHE HOOKS/HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

//module handler
static const authz_provider Scitoken_Provider =
  {
    &ScitokenVerify,
    NULL,
  };

//hook registration function
static void register_hooks(apr_pool_t *p)
{
  ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "Scitoken",
                AUTHZ_PROVIDER_VERSION,
                &Scitoken_Provider,
                AP_AUTH_INTERNAL_PER_CONF);
}

//module name tags
AP_DECLARE_MODULE(auth_scitoken) =
{
  STANDARD20_MODULE_STUFF,
  create_authz_scitoken_dir_config, /* dir config creater */
  merge_auth_scitoken_dir_config,   /* dir merger(overwrite) */
  create_authz_scitoken_dir_config, /* server config */
  merge_auth_scitoken_dir_config,   /* merge server config */
  authz_scitoken_cmds,              /* command apr_table_t */
  register_hooks                    /* register hooks */
};
