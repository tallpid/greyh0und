package mock.util;

/**
 * Mock Android Log class for debugging fuzzing operations
 * Prints to both logcat-style output and stdout for compatibility
 */
public class Log {
    
    public static int d(String tag, String msg) {
        System.out.println("D/" + tag + ": " + msg);
        return 0;
    }
    
    public static int i(String tag, String msg) {
        System.out.println("I/" + tag + ": " + msg);
        return 0;
    }
    
    public static int w(String tag, String msg) {
        System.out.println("W/" + tag + ": " + msg);
        return 0;
    }
    
    public static int e(String tag, String msg) {
        System.out.println("E/" + tag + ": " + msg);
        return 0;
    }
    
    public static int v(String tag, String msg) {
        System.out.println("V/" + tag + ": " + msg);
        return 0;
    }
}
