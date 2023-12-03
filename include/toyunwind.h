#ifndef __TOYUNWIND_H_
#define __TOYUNWIND_H_

#include <stdint.h>

struct tunw_context_t;
struct tuwn_cursor_t;

int32_t twun_get_context(struct tunw_context_t *);
int32_t tuwn_init_local(struct tuwn_cursor_t *, tunw_context_t *);


#endif // __TOYUNWIND_H_ 
