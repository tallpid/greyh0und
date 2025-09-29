package mock.content.res;

import mock.util.Log;
import java.io.InputStream;
import java.io.ByteArrayInputStream;

/**
 * Mock AssetManager class that provides fuzz input as fake asset files
 * This mock provides a static buffer representing an XML file that can be configured
 * from native code to serve as the asset content for fuzzing
 */
public class AssetManager {
    private static final String TAG = "DEBUG_FUZZ";
    
    // Static fuzz data that can be configured from native code
    private static byte[] fuzzAssetData = getDefaultXmlData();
    private static String fuzzAssetFileName = "t_s.bmp";
    
    // Default constructor
    public AssetManager() {
        Log.d(TAG, "Mock AssetManager constructor called");
        System.out.println("[Mock] AssetManager constructor called");
    }
    
    /**
     * Mock open() method that returns fuzz data as InputStream for any file
     */
    public InputStream open(String fileName) {
        Log.d(TAG, "Mock AssetManager.open() called with: " + fileName);
        System.out.println("[Mock] AssetManager.open() called with: " + fileName + " (returning fuzz data)");
        
        // Return fuzz data as InputStream for any requested file
        return new ByteArrayInputStream(fuzzAssetData);
    }
    
    /**
     * Mock list() method - return fake file list
     */
    public String[] list(String path) {
        Log.d(TAG, "Mock AssetManager.list() called with path: " + path);
        System.out.println("[Mock] AssetManager.list() called with path: " + path);
        return new String[]{ fuzzAssetFileName }; // Return our fake file
    }
    
    /**
     * Mock close() method
     */
    public void close() {
        Log.d(TAG, "Mock AssetManager.close() called");
        System.out.println("[Mock] AssetManager.close() called");
    }
    
    /**
     * Get the current fuzz asset data size
     * This method mimics AAsset_getLength functionality
     */
    public static int getFuzzAssetSize() {
        return fuzzAssetData.length;
    }
    
    /**
     * Get the current fuzz asset data  
     * This method mimics AAsset_read functionality
     */
    public static byte[] getFuzzAssetData() {
        return fuzzAssetData.clone();
    }
    
    /**
     * Native-callable method to get asset length (mimics AAsset_getLength)
     * Called from native code via JNI when AAsset_getLength is patched
     */
    public static int getAssetLength() {
        Log.d(TAG, "Native getAssetLength() called, returning: " + fuzzAssetData.length);
        System.out.println("[Mock] Native getAssetLength() called, returning: " + fuzzAssetData.length);
        return fuzzAssetData.length;
    }
    
    /**
     * Native-callable method to read asset data (mimics AAsset_read) 
     * Called from native code via JNI when AAsset_read is patched
     */
    public static byte[] readAssetData(int length) {
        Log.d(TAG, "Native readAssetData() called with length: " + length);
        System.out.println("[Mock] Native readAssetData() called with length: " + length);
        
        if (length <= 0) {
            return new byte[0];
        }
        
        // Return requested amount of data or full data if less than requested
        int actualLength = Math.min(length, fuzzAssetData.length);
        byte[] result = new byte[actualLength];
        System.arraycopy(fuzzAssetData, 0, result, 0, actualLength);
        return result;
    }
    
    /**
     * Native-callable method to open asset (mimics AAssetManager_open)
     * Returns a fake asset handle (just returns this object's hash)
     */
    public static long openAsset(String filename) {
        Log.d(TAG, "Native openAsset() called with filename: " + filename);
        System.out.println("[Mock] Native openAsset() called with filename: " + filename);
        
        // Return a fake asset handle (non-zero to indicate success)
        // In real implementation this would be a pointer, we return a fake value
        return 0x12345678L; // Fake asset handle
    }
    
    /**
     * Native-callable method to close asset (mimics AAsset_close)
     */
    public static void closeAsset(long assetHandle) {
        Log.d(TAG, "Native closeAsset() called with handle: 0x" + Long.toHexString(assetHandle));
        System.out.println("[Mock] Native closeAsset() called with handle: 0x" + Long.toHexString(assetHandle));
        // Nothing to do for mock implementation
    }
    
    /**
     * Configure fuzz asset data from native code
     * This method can be called from JNI to set the asset content for fuzzing
     */
    public static void setFuzzAssetData(byte[] data) {
        if (data != null) {
            fuzzAssetData = data.clone();
            Log.d(TAG, "Fuzz asset data updated, size: " + fuzzAssetData.length);
            System.out.println("[Mock] Fuzz asset data updated, size: " + fuzzAssetData.length);
        }
    }
    
    /**
     * Configure fuzz asset filename from native code
     */
    public static void setFuzzAssetFileName(String fileName) {
        if (fileName != null) {
            fuzzAssetFileName = fileName;
            Log.d(TAG, "Fuzz asset filename updated: " + fuzzAssetFileName);
            System.out.println("[Mock] Fuzz asset filename updated: " + fuzzAssetFileName);
        }
    }
    
    /**
     * Default XML data for testing
     */
    private static byte[] getDefaultXmlData() {
        String defaultXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                           "<root>\n" +
                           "    <test>Mock asset data for fuzzing</test>\n" +
                           "    <data>FUZZ_DATA_PLACEHOLDER</data>\n" +
                           "</root>\n";
        return defaultXml.getBytes();
    }
    
    /**
     * Reset to default asset data
     */
    public static void resetToDefault() {
        fuzzAssetData = getDefaultXmlData();
        fuzzAssetFileName = "t_s.bmp";
        Log.d(TAG, "Asset data reset to default");
        System.out.println("[Mock] Asset data reset to default");
    }
}
