#ifndef MADJWT_HPP
#define MADJWT_HPP

#include "jwt.h"
#include <string.h>
#include "record.hpp"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct madjwt__Algorithm {
  int64_t index;
} madjwt__Algorithm_t;


#ifdef __cplusplus
}
#endif

#endif // MADJWT_HPP