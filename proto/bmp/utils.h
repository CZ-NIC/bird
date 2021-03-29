/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BMP_UTILS_H_
#define _BIRD_BMP_UTILS_H_

/**
 * TODO:
 * - Provide descriptive explanation for the follwing enums
 */
enum bmp_result {
  BMP_E_NONE = 0,
  BMP_E_INVALID_ARG,
  BMP_E_NULL_REF,
  BMP_E_EXISTS,
  BMP_E_NOT_EXISTS,
  BMP_E_OPEN_SOCKET,
  BMP_E_CONNECT_TO_SRV,
  BMP_E_SEND_DATA,
  BMP_E_BIRDSOCK_NULL_REF,
  BMP_E_REMOTE_CAPS_NULL_REF,
  BMP_E_NEW_TX_EVENT
};

#define BMP_FAILED(v) \
  (v != BMP_E_NONE)

#define IF_BMP_FAILED_RETURN_RC(func) \
  do {                                \
    enum bmp_result rc = func;        \
    if (BMP_FAILED(rc))               \
    {                                 \
      return rc;                      \
    }                                 \
  } while (0)

// The following macro requires to define locally enum bmp_result rc;
#define IF_BMP_FAILED_GOTO_LABEL(func, label)     \
  do {                                            \
    rc = func;                                    \
    if (BMP_FAILED(rc))                           \
    {                                             \
      goto label;                                 \
    }                                             \
  } while (0)

#define IF_BMP_FAILED_PRINT_ERR_MSG(func, msg)   \
  do {                                           \
    enum bmp_result rc = func;                   \
    if (BMP_FAILED(rc))                          \
    {                                            \
      log(L_WARN "[BMP] " msg " (rc = %d)", rc); \
    }                                            \
  } while (0)

#define IF_BMP_FAILED_PRINT_ERR_MSG_AND_GOTO_LABEL(func, msg, label) \
  do {                                                               \
    enum bmp_result rc = func;                                       \
    if (BMP_FAILED(rc))                                              \
    {                                                                \
      log(L_WARN "[BMP] " msg " (rc = %d)", rc);                     \
      goto label;                                                    \
    }                                                                \
  } while (0)

#define IS_NULL(ptr) \
  ((ptr) == NULL)

#define IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(expr, msg, rv...)     \
  do {                                                                      \
    if ((expr))                                                             \
    {                                                                       \
      log(L_WARN "[BMP] " msg);                                             \
      return rv;                                                            \
    }                                                                       \
  } while (0)

#define IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(p, msg, rv...)   \
  do {                                                                   \
    IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(IS_NULL(p), msg, rv);  \
  } while (0)

#define IF_BMP_FAILED_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(func, msg, rv...)     \
  do {                                                                       \
    enum bmp_result rc = func;                                               \
    IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(BMP_FAILED(rc), msg, rv);  \
  } while (0)

#endif /* _BIRD_BMP_UTILS_H_ */