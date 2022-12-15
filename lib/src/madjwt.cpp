#include "gc.h"
#include "madjwt.hpp"
#include <time.h>
#include <string.h>
#include "jwt.h"
#include "record.hpp"


#ifdef __cplusplus
extern "C" {
#endif

jwt_alg_t madjwt__fromMadlibAlg(int64_t algIndex) {
  switch(algIndex) {
    case 0:
      return JWT_ALG_ES256;

    case 1:
      return JWT_ALG_ES384;

    case 2:
      return JWT_ALG_ES512;

    case 3:
      return JWT_ALG_HS256;

    case 4:
      return JWT_ALG_HS384;

    case 5:
      return JWT_ALG_HS512;

    case 6:
      return JWT_ALG_NONE;

    case 7:
      return JWT_ALG_RS256;

    case 8:
      return JWT_ALG_RS384;

    case 9:
      return JWT_ALG_RS512;

    case 10:
      return JWT_ALG_TERM;
  }
}


int64_t madjwt__toMadlibAlg(jwt_alg_t algIndex) {
  switch(algIndex) {
    case JWT_ALG_ES256:
      return 0;

    case JWT_ALG_ES384:
      return 1;

    case JWT_ALG_ES512:
      return 2;

    case JWT_ALG_HS256:
      return 3;

    case JWT_ALG_HS384:
      return 4;

    case JWT_ALG_HS512:
      return 5;

    case JWT_ALG_NONE:
      return 6;

    case JWT_ALG_RS256:
      return 7;

    case JWT_ALG_RS384:
      return 8;

    case JWT_ALG_RS512:
      return 9;

    case JWT_ALG_TERM:
      return 10;
  }
}


char *madjwt__signToken(madlib__record__Record_t *tokenInfo, char *key) {
  jwt_set_alloc(GC_malloc, GC_realloc, GC_free);
  time_t iat = time(NULL);
  jwt_t *token = NULL;
  int ret = 0;

  jwt_alg_t alg = madjwt__fromMadlibAlg(((madjwt__Algorithm_t*) tokenInfo->fields[0]->value)->index);
  char *claims = (char*) tokenInfo->fields[1]->value;
  char *headers = (char*) tokenInfo->fields[2]->value;

  ret = jwt_new(&token);
  ret = jwt_add_grants_json(token, claims);
  ret = jwt_add_headers_json(token, headers);
  ret = jwt_set_alg(token, alg, (const unsigned char *) key, strlen(key));

  char *encoded = jwt_encode_str(token);

  return encoded;
}


madlib__record__Record_t *madjwt__decode(char *tokenStr, char *key) {
  jwt_t *token = NULL;
  int ret = 0;
  ret = jwt_decode(&token, (const char *) tokenStr, (const unsigned char*) key, strlen(key));

  char *claims = jwt_get_grants_json(token, NULL);
  char *headers = jwt_get_headers_json(token, NULL);
  int64_t algIndex = madjwt__toMadlibAlg(jwt_get_alg(token));
  madjwt__Algorithm_t *alg = (madjwt__Algorithm*) GC_MALLOC(sizeof(madjwt__Algorithm));
  alg->index = algIndex;

  madlib__record__Record_t *result = (madlib__record__Record_t*) GC_MALLOC(sizeof(madlib__record__Record_t));
  madlib__record__Field **fields = (madlib__record__Field_t**) GC_MALLOC(sizeof(madlib__record__Field_t*) * 3);
  madlib__record__Field *algField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
  madlib__record__Field *claimsField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
  madlib__record__Field *headersField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));

  algField->name = "algorithm";
  algField->value = (void*)alg;

  claimsField->name = "claims";
  claimsField->value = (void*)claims;

  headersField->name = "headers";
  headersField->value = (void*)headers;

  fields[0] = algField;
  fields[1] = claimsField;
  fields[2] = headersField;

  result->fieldCount = 3;
  result->fields = fields;

  return result;
}


#ifdef __cplusplus
}
#endif
