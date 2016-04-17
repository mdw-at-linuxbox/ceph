add_custom_target(cython_rbd
  COMMAND
  LDFLAGS=-L${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
  CYTHON_BUILD_DIR=${CMAKE_BINARY_DIR}/src/pybind/rbd
  CFLAGS=\"-I${CMAKE_SOURCE_DIR}/src/include -std=c++11\"
  python ${CMAKE_SOURCE_DIR}/src/pybind/rbd/setup.py build --build-base ${CYTHON_MODULE_DIR} --verbose
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/pybind/rbd
  BYPRODUCTS "${CYTHON_MODULE_DIR}/lib.${PYTHON_PLATFORM}/rbd.so"
  DEPENDS rbd)

install(FILES "${CYTHON_MODULE_DIR}/lib.${PYTHON_PLATFORM}/rbd.so" DESTINATION "${PYTHON_PREFIXED_LIBDEST}")
