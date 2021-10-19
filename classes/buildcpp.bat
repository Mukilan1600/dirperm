for %%f in (./cpp-src/*.cpp) do (
      g++ -std=c++17 -c -I"%JAVA_HOME%/include" -I"%JAVA_HOME%/include/win32" ./cpp-src/%%~nf.cpp -o ./cpp-src/%%~nf.o
)

g++ -std=c++17 -shared ./cpp-src/*.o -o ./permission/native.dll