CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 14)

find_program(BASH bash HINTS /bin)

file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

include_directories(
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
  ${CMAKE_BINARY_DIR}/contrib/relic/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
  )

set(C_LIB ${CMAKE_BINARY_DIR}/.libs/libchiabls.a)

add_library(chiabls ${CMAKE_CURRENT_SOURCE_DIR}/privatekey.cpp)

add_library(chiablstmp ${HEADERS}
  ${CMAKE_CURRENT_SOURCE_DIR}/privatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chaincode.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/elements.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/extendedprivatekey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/extendedpublickey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/legacy.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/schemes.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/threshold.cpp
)

set(OPREFIX object_)
find_library(GMP_NAME NAMES libgmp.a gmp)
find_library(SODIUM_NAME NAMES libsodium.a sodium)

set(LIBRARIES_TO_COMBINE
      COMMAND mkdir ${OPREFIX}$<TARGET_NAME:chiablstmp> || true && cd ${OPREFIX}$<TARGET_NAME:chiablstmp> &&  ${CMAKE_AR} -x $<TARGET_FILE:chiablstmp>
      COMMAND mkdir ${OPREFIX}$<TARGET_NAME:relic_s> || true && cd ${OPREFIX}$<TARGET_NAME:relic_s> &&  ${CMAKE_AR} -x $<TARGET_FILE:relic_s>
)

#if (GMP_FOUND)
#  list(APPEND LIBRARIES_TO_COMBINE COMMAND mkdir ${OPREFIX}gmp || true && cd ${OPREFIX}gmp &&  ${CMAKE_AR} -x ${GMP_NAME})
#endif()
if (SODIUM_FOUND)
  list(APPEND LIBRARIES_TO_COMBINE COMMAND mkdir ${OPREFIX}sodium || true && cd ${OPREFIX}sodium &&  ${CMAKE_AR} -x ${SODIUM_NAME})
endif()

add_custom_target(combined_custom
        ${LIBRARIES_TO_COMBINE}
        COMMAND ${CMAKE_AR} -rs ${C_LIB} ${OPREFIX}*/*${CMAKE_C_OUTPUT_EXTENSION}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS chiablstmp relic_s
        )

add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/libchiabls.la"
	COMMAND ${BASH} -c "sed \"s^__LIBDIR__^${CMAKE_BINARY_DIR}^\" ${CMAKE_CURRENT_SOURCE_DIR}/libchiabls.la.in >${CMAKE_BINARY_DIR}/libchiabls.la"
	COMMAND ${BASH} -c "mkdir -p ${CMAKE_BINARY_DIR}/.libs"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libchiabls.la.in"
	)	
add_custom_target(chiabls_la DEPENDS "${CMAKE_BINARY_DIR}/libchiabls.la")

add_library(combined STATIC IMPORTED GLOBAL)
add_dependencies(combined combined_custom chiabls_la)

target_link_libraries(chiabls combined)

set_target_properties(combined
        PROPERTIES
        IMPORTED_LOCATION ${C_LIB}
        )

file(GLOB includes "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp")
install(FILES ${includes} DESTINATION include/chiabls)
install(FILES ${C_LIB} DESTINATION lib)

if(ENABLE_TESTS)
  add_executable(runtest test.cpp)
  if (SODIUM_FOUND)
    target_link_libraries(runtest chiablstmp relic_s sodium)
  else()
    target_link_libraries(runtest chiablstmp relic_s)
  endif()
endif()
if(BENCH)
  add_executable(runbench test-bench.cpp)
  if (SODIUM_FOUND)
    target_link_libraries(runbench chiablstmp relic_s sodium)
  else()
    target_link_libraries(runbench chiablstmp relic_s)
  endif()
endif()

