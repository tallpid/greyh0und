package mock.content;

import mock.content.pm.PackageManager;
import mock.content.res.AssetManager;
import mock.util.Log;

/**
 * Mock Android Context class with mock package structure
 * This ensures GetMethodID can find methods with correct signatures like:
 * ()Lmock/content/pm/PackageManager;
 * ()Lmock/content/res/AssetManager;
 * 
 * Important: This is a concrete implementation, not abstract, to avoid 
 * AbstractMethodError when called by native code
 */
public class Context {
    private static final String TAG = "DEBUG_FUZZ";
    
    // Default constructor
    public Context() {
        Log.d(TAG, "Mock Context constructor called");
        System.out.println("[Mock] Context constructor called");
    }
    
    // Concrete implementation - not abstract
    public PackageManager getPackageManager() {
        Log.d(TAG, "Mock Context.getPackageManager() called");
        System.out.println("[Mock] Context.getPackageManager() called");
        return new PackageManager();
    }
    
    // Concrete implementation - not abstract  
    public AssetManager getAssets() {
        Log.d(TAG, "Mock Context.getAssets() called");
        System.out.println("[Mock] Context.getAssets() called");
        return new AssetManager();
    }
    
    public String getPackageName() {
        Log.d(TAG, "Mock Context.getPackageName() called");
        System.out.println("[Mock] Context.getPackageName() called");
        return "com.mock.fuzzing";
    }
    
    public Object getSystemService(String name) {
        Log.d(TAG, "Mock Context.getSystemService() called with: " + name);
        System.out.println("[Mock] Context.getSystemService() called with: " + name);
        return null;
    }
    
    // Additional Context methods that might be called
    public String getString(int resId) {
        Log.d(TAG, "Mock Context.getString() called with resId: " + resId);
        System.out.println("[Mock] Context.getString() called with resId: " + resId);
        return "mock_string";
    }
}
