#
# NSL DFT lib (libdft)
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#

# variable definitions
CXXFLAGS	+= -Wall -c -fomit-frame-pointer -std=c++0x -O3	\
		  -fno-strict-aliasing -fno-stack-protector	\
		  -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		  -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX
CXXFLAGS_SO	+= -Wl,--hash-style=sysv -Wl,-Bsymbolic	-shared \
		   -Wl,--version-script=$(PIN_HOME)/source/include/pintool.ver
LIBS		+= -lpin  -lxed -ldwarf -lelf -ldl #-liberty
H_INCLUDE	+= -I. -I$(PIN_HOME)/source/include		\
		   -I$(PIN_HOME)/source/include/gen		\
		   -I$(PIN_HOME)/extras/xed2-ia32/include	\
		   -I$(PIN_HOME)/extras/components/include
L_INCLUDE	+= -L$(PIN_HOME)/extras/xed2-ia32/lib	\
		-L$(PIN_HOME)/ia32/lib -L$(PIN_HOME)/ia32/lib-ext
TOOLS_DIR	= tools
OBJS		= libdft_api.o libdft_core.o syscall_desc.o tagmap.o
TOOLS_OBJS	= $(TOOLS_DIR)/nullpin.o $(TOOLS_DIR)/libdft.o	\
		  $(TOOLS_DIR)/libdft-dta.o \
		  $(TOOLS_DIR)/taint_xchg.o $(TOOLS_DIR)/taint_exchange.o \
		  $(TOOLS_DIR)/taint_xchg_debug.o \
		  $(TOOLS_DIR)/null_tool.o
TOOLS_SOBJS	= $(TOOLS_OBJS:.o=.so)

# phony targets
.PHONY: all clean tools tools_clean

# default target (build libdft only)
all: $(OBJS)

# libdft_api
libdft_api.o: libdft_api.c libdft_api.h branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft_core
libdft_core.o: libdft_core.c libdft_core.h branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# syscall_desc
syscall_desc.o: syscall_desc.c syscall_desc.h  branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# tagmap
tagmap.o: tagmap.c tagmap.h branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# clean (libdft)
clean:
	rm -rf $(OBJS)

# tools (nullpin, libdft, libdft-dta, taint_exchange, taint_xchg, 
# 	taint_xchg_debug, null_tool)
tools: $(TOOLS_SOBJS)

# nullpin
$(TOOLS_DIR)/nullpin.so: $(TOOLS_DIR)/nullpin.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/nullpin.o: $(TOOLS_DIR)/nullpin.c branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft
$(TOOLS_DIR)/libdft.so: $(TOOLS_DIR)/libdft.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/libdft.o: $(TOOLS_DIR)/libdft.c branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft-dta
$(TOOLS_DIR)/libdft-dta.so: $(TOOLS_DIR)/libdft-dta.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/libdft-dta.o: $(TOOLS_DIR)/libdft-dta.c branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# taint_exchange
$(TOOLS_DIR)/taint_exchange.so: $(TOOLS_DIR)/taint_exchange.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/taint_exchange.o: $(TOOLS_DIR)/taint_exchange.c branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# taint_xchg
$(TOOLS_DIR)/taint_xchg.so: $(TOOLS_DIR)/taint_xchg.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/taint_xchg.o: $(TOOLS_DIR)/taint_xchg.c branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# taint_xchg_debug
$(TOOLS_DIR)/taint_xchg_debug.so: $(TOOLS_DIR)/taint_xchg_debug.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/taint_xchg_debug.o: $(TOOLS_DIR)/taint_xchg.c branch_pred.h
	$(CXX) $(CXXFLAGS) -DDEBUG_ENABLE $(H_INCLUDE) -o $(@) $<

# null_tool
$(TOOLS_DIR)/null_tool.so: $(TOOLS_DIR)/null_tool.o $(OBJS)
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o)	\
		$(OBJS) $(LIBS)
$(TOOLS_DIR)/null_tool.o: $(TOOLS_DIR)/null_tool.c branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# clean (tools)
tools_clean:
	rm -rf $(TOOLS_OBJS) $(TOOLS_SOBJS)
