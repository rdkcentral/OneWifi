##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

include ./makefile.inc

#
# program
#

TARGET = $(INSTALLDIR)/lib/libbus.a
#TARGET = $(INSTALLDIR)

INCLUDEDIRS = \
	-I$(BUS_HOME)/inc \
	-I$(BUS_LIB)/inc \
	-I$(BUS_UTILS) \

CXXFLAGS = $(INCLUDEDIRS) -g -fPIC 
LIBS = -lm -lpthread -ldl
LDFLAGS = $(LIBS) -shared

BUS_SOURCES = $(wildcard $(BUS_HOME)/src/*.c) \
		$(wildcard $(BUS_LIB)/src/*.c) \

ifdef ONEWIFI_RBUS_SUPPORT
BUS_SOURCES += $(BUS_HOME)/platform/rdkb/bus.c
else
#BUS_SOURCES += $(BUS_HOME)/platform/linux/bus.c
endif

BUS_OBJECTS = $(BUS_SOURCES:.c=.o) 

all: $(TARGET)

$(TARGET): $(BUS_OBJECTS)
	$(CXX) -o $@ $(BUS_OBJECTS) $(LDFLAGS)

$(BUS_OBJECTS): %.o: %.c
	$(CC) $(CXXFLAGS) -o $@ -c $<

# Clean target: "make -f Makefile.Linux clean" to remove unwanted objects and executables.
#

clean:
	$(RM) $(BUS_OBJECTS) $(TARGET)

#
# Run target: "make -f Makefile.Linux run" to execute the application
#             You will need to add $(VARIABLE_NAME) for any command line parameters 
#             that you defined earlier in this file.
# 

run:
	./$(TRAGET)
