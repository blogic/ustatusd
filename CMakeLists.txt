cmake_minimum_required(VERSION 2.6)

PROJECT(ustatus C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES ustatus.c)
SET(LIBS ubox ubus json-c blobmsg_json)

ADD_EXECUTABLE(ustatus ${SOURCES})
TARGET_LINK_LIBRARIES(ustatus ${LIBS})
INSTALL(TARGETS ustatus
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

ADD_EXECUTABLE(ustatusd ustatusd.c ubus.c nl80211.c rtnl.c blob.c netlink.c config.c bridge.c resmon.c)
TARGET_LINK_LIBRARIES(ustatusd ${LIBS} nl-tiny uci)
INSTALL(TARGETS ustatusd
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
