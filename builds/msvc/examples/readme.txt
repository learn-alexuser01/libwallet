Because of the use of certain C++11 features these this project is built using "Visual C++ Compiler Nov 2013 CTP (CTP_Nov2013)".

CTP_Nov2013 component must be downloaded and installed as an add-on to Visual Studio.

The project depends on the libwallet and libbitcoin projects, both statically linked.

All other project dependencies are available via NuGet and there is a packages.config file which references them.

Most of the NuGet libraries are built for compiler v100 and v110 and have not yet been rebuilt with VS2013's default compiler (v120) or Visual C++ Compiler Nov 2013 CTP (CTP_Nov2013).

Because of this compiler mismatch between the internal and external dependencies the external libraries cannot be statically-linked in a release build.

The release build statically links the internal dependencies (libbitcoin and libwallet) and dynamically links the external dependencies (i.e. those from NuGet).

In order to avoid dependency on vcrtd110.dll (v110 compiler non-redistributable debug C runtime library) the debug build is statically linked to its NuGet dependencies.

For release packaging the DLLs (in the same direcory as the EXE) should be distributed into the same folder as the EXE.

The fact that external dependency DLLs are copied into the debug build directory is an idiosyncracy (bug) in those projects' NuGet packaging.

All of this will go away once the external libraries are built with the same compiler as the internal projects.