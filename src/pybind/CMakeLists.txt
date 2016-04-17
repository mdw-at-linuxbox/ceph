set(CYTHON_MODULE_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/cython_modules)

# find out where python wants to find stuff
execute_process(COMMAND
python -c "from distutils.sysconfig import get_python_lib; from sys import stdout; stdout.write (get_python_lib(plat_specific=1, prefix='${CMAKE_INSTALL_PREFIX}'))"
OUTPUT_VARIABLE
PYTHON_PREFIXED_LIBDEST)

# Derive platform - python will place things in lib.$PLAT
execute_process(COMMAND
python -c "from distutils.sysconfig import get_python_version; from distutils.util import get_platform; from sys import stdout; stdout.write(get_platform() + '-' + get_python_version())"
OUTPUT_VARIABLE
PYTHON_PLATFORM)

add_subdirectory(rados)
add_subdirectory(rbd)
add_subdirectory(cephfs)

add_custom_target(cython_modules ALL
    DEPENDS cython_rados cython_cephfs cython_rbd)
