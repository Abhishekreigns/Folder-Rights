package com.reigns;

import java.util.Scanner;

public class FolderJNI {

    static{

        try{
          System.load("C:/Users/Mr.Reignz/source/repos/folder/folder/flide.dll");
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

    private native void showFolderRights(String directory);
    private native void modifyPermissions(String directory);

    public static void main(String[] args) {

        String directory;
        Scanner s =new Scanner(System.in);
        directory = s.next();
        FolderJNI folder =new FolderJNI();
        folder.showFolderRights(directory);
        folder.modifyPermissions(directory);


    }
}


//create a headrefile with updated function (modifyPermissions).
//implement the same in the C++ code.
/Finally check for errors.