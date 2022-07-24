# Folder-Rights

Place the files folder.cpp,FolderJNI.java,FolderJNI.class,com_reigns_FolderJNI.h to a source directory.
To ease out the debugging process, place the jni.h,jni_md.h files from /jdk_path/include/ and /jdk_path/include/win32/ to msys64/mingw64/bin.
Make the default terminal as windows powershell.
Open terminal from the source directory.

To compile the C++ program,
g++ -shared -o flide.dll folder.cpp
Make sure to change the flide.dll path in the FolderJNI.java file to point to the source directory.

The java file header file is already available,
but if needed, use
javac -h . FolderJNI.java
javac FolderJNI

After all the above steps,
run the command to start the console application.
java FolderJNI.java or java FolderJNI.



