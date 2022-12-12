#include <time.h>
#include <string.h>
#include "jwt.h"


#ifdef __cplusplus
extern "C" {
#endif

char *madjwt__sign(char *payload, char *key) {
  time_t iat = time(NULL);
  jwt_t *token = NULL;
  int ret = 0;
  ret = jwt_new(&token);
  ret = jwt_add_grant_int(token, "iat", iat);
  ret = jwt_add_grant(token, "payload", payload);
  ret = jwt_set_alg(token, JWT_ALG_HS256, (const unsigned char *) key, strlen(key));
  return jwt_encode_str(token);
}

char *madjwt__decode(char *tokenStr, char *key) {
  jwt_t *token = NULL;
  int ret = 0;
  ret = jwt_decode(&token, (const char *) tokenStr, (const unsigned char*) key, strlen(key));
  return (char*) jwt_get_grant(token, "payload");
}

#ifdef __cplusplus
}
#endif
