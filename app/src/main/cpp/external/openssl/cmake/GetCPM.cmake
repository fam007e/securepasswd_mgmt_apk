# CPM is vendored in-tree: this must never download anything at configure
# time (network-dependent builds break CI and violate F-Droid policy).
include(${CMAKE_CURRENT_LIST_DIR}/CPM.cmake)
