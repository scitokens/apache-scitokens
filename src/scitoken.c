#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_time.h"

#include <scitokens-cpp/src/scitokens.h>

#include <unistd.h>

#include "mod_auth.h"

/* ~~~~~~~~~~~~~~~~~~~~~~~~~  CONFIGURATION STRUCTURE ~~~~~~~~~~~~~~~~~~~~~~~~~  */

typedef struct {
char** issuers;
char** resources;
int numberofissuer;
} authz_scitoken_config_rec;

/* ~~~~~~~~~~~~~~~~~~~~~~~~~  DEFAULT CONFIGURATION ~~~~~~~~~~~~~~~~~~~~~~~~~~  */

static void *create_authz_scitoken_dir_config(apr_pool_t *p, char *d)
{
    authz_scitoken_config_rec *conf = apr_palloc(p, sizeof(*conf));
    
    char** issuers = calloc(1, sizeof(char*));
    char**resources = calloc(1, sizeof(char*));
    *(issuers) = "issuer";
    *(resources) = "resources";
    conf->numberofissuer = 1;
    conf->issuers = issuers;
    conf->resources = resources;
    return conf;
}

//The default is to overwrite the old config, NOT merging
static void *merge_auth_scitoken_dir_config(apr_pool_t *p, void *basev, void *new_confv)
{
    authz_scitoken_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    authz_scitoken_config_rec *base = basev;
    authz_scitoken_config_rec *new_conf = new_confv;
    newconf->numberofissuer = new_conf->numberofissuer ? new_conf->numberofissuer : base->numberofissuer;
    newconf->issuers = new_conf->issuers ? new_conf->issuers : base->issuers;
    newconf->resources = new_conf->resources ? new_conf->resources : base->resources;
}

/**
 * This function takes the argument "issuers" from the Apache configuration file
 * , parses the directive and sets the (module) configuration accordingly
 * Input: a string of issuers;resource seperated by ","
 *        "issuer1;resource1,issuer2;resource2...."
 */
static const char *set_scitoken_param_iss(cmd_parms *cmd, void *config, const char *issuersstr)
{
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
    //ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s",*resources);
    return NULL;
}
/**
 * This function takes the argument "exp" from the Apache configuration file
 * , parses the directive and sets the (module) configuration accordingly
 * NOT implemented
 */
static const char *set_scitoken_param_exp(cmd_parms *cmd, void *config, const char *issuersstr)
{
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
        {NULL}
};

/* ~~~~~~~~~~~~~~~~~~~~~~~~  AUTHZ HANDLERS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

module AP_MODULE_DECLARE_DATA auth_scitoken_module;


/**
 * The main function to verify a Scitoken
 */
int ScitokenVerify(request_rec *r, const char *require_line, const void *parsed_require_line) {
  SciToken scitoken;
  char *err_msg;
  const char *auth_line, *auth_scheme;
  
  // Read in the entire scitoken into memory
  auth_line = apr_table_get(r->headers_in,"Authorization");
  if(auth_line == NULL){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Unauthorized");
    return AUTHZ_DENIED;
  }
  auth_scheme = ap_getword(r->pool, &auth_line, ' ');
  
  // Read in configuration
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

  while (apr_isspace(*auth_line)) {
    auth_line++;
  }
  if(sizeof(auth_line)>1000*1000){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "SciToken too large");
    return AUTHZ_DENIED;
  }

  scitoken_deserialize(auth_line, &scitoken, null_ended_list, &err_msg);
  if(scitoken_deserialize(auth_line, &scitoken, null_ended_list, &err_msg)){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to deserialize scitoken");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  
  char* issuer_ptr = NULL;
  if(scitoken_get_claim_string(scitoken, "iss", &issuer_ptr, &err_msg)) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to get issuer from token: %s\n",err_msg);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  
  
  //Preparing for enforcer test
  Enforcer enf;
  
  char hostname[1024];
  const char* aud_list[2];
  
  // Get the hostname for the audience. It is using hostname but NOT domain name. Set your payload accordingly
  if (gethostname(hostname, 1024) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to get hostname");
    return AUTHZ_DENIED;
  }
  aud_list[0] = hostname;
  aud_list[1] = NULL;

  if (!(enf = enforcer_create(issuer_ptr, aud_list, &err_msg))) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to create enforcer");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s", err_msg);
    return AUTHZ_DENIED;
  }
  
  Acl acl;
  acl.authz = "read";
  acl.resource = "";
  //If a resource is found for the audience
  int found = 0;
  //ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s",*conf->resources);
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

  
  if (enforcer_test(enf, scitoken, &acl, &err_msg)) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed enforcer test");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s", err_msg);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s", hostname);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s", null_ended_list[0]);
    return AUTHZ_DENIED;
  }
  
  // +1 for the null-terminator
  char *str = malloc(strlen("token") + strlen(auth_line) + 1);
  strcpy(str, "token");
  strcat(str, auth_line);
  
  // log the access
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, str, r->uri);
  free(str);
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
  NULL,                             /* server config */
  NULL,                             /* merge server config */
  authz_scitoken_cmds,              /* command apr_table_t */
  register_hooks                    /* register hooks */
};
