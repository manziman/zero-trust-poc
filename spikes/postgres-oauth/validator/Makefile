MODULE_big = custody_jwt_validator
OBJS = validator.o
PG_CPPFLAGS += -Wall -Wextra -Werror
SHLIB_LINK += -ljansson -lcrypto

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
