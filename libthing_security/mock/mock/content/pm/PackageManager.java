package mock.content.pm;

import mock.util.Log;

/**
 * Mock PackageManager class with mock package structure
 * This ensures GetMethodID can find methods with correct signatures
 * 
 * Important: Concrete implementation to avoid AbstractMethodError
 */
public class PackageManager {
    private static final String TAG = "DEBUG_FUZZ";
    
    // Default constructor
    public PackageManager() {
        Log.d(TAG, "Mock PackageManager constructor called");
        System.out.println("[Mock] PackageManager constructor called");
    }
    
    public String getNameForUid(int uid) {
        Log.d(TAG, "Mock PackageManager.getNameForUid() called with uid: " + uid);
        System.out.println("[Mock] PackageManager.getNameForUid() called with uid: " + uid);
        return "com.thingclips.smart.security";
    }
    
    public int checkPermission(String permName, String pkgName) {
        Log.d(TAG, "Mock PackageManager.checkPermission() called: " + permName + " for " + pkgName);
        System.out.println("[Mock] PackageManager.checkPermission() called: " + permName + " for " + pkgName);
        return 0; // PERMISSION_GRANTED
    }
    
    public boolean hasSystemFeature(String name) {
        Log.d(TAG, "Mock PackageManager.hasSystemFeature() called: " + name);
        System.out.println("[Mock] PackageManager.hasSystemFeature() called: " + name);
        return false;
    }
    
    // Additional common PackageManager methods
    public String[] getPackagesForUid(int uid) {
        Log.d(TAG, "Mock PackageManager.getPackagesForUid() called with uid: " + uid);
        System.out.println("[Mock] PackageManager.getPackagesForUid() called with uid: " + uid);
        return new String[]{"com.mock.app"};
    }
}
