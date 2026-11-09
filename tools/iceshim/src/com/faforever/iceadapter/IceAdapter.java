package com.faforever.iceadapter;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Launch shim for the FAF client (issue #231). The client starts
 * {@code java -cp <nativeDir>/faf-ice-adapter.jar;<javafx jars> com.faforever.iceadapter.IceAdapter <args>};
 * this class has that name and that jar is this shim. It has no network logic:
 *
 * <ul>
 *   <li>runs {@code faf-netbridge.exe} (or {@code faf-netbridge}) from the jar's folder with the same
 *       arguments, passes its output through and exits with its exit code;</li>
 *   <li>runs FAF's original adapter, kept next to it as {@code faf-ice-adapter.orig.jar}, when the bridge
 *       is missing, cannot be started, or exits with an error within {@value #STARTUP_MILLIS} ms.</li>
 * </ul>
 *
 * A bridge that fails after the client has connected to it cannot be replaced this way: the client only
 * connects during its first 50 x 250 ms, so the fallback is for startup failures.
 */
public final class IceAdapter {
    static final long STARTUP_MILLIS = 3000;

    private IceAdapter() {}

    public static void main(String[] args) throws Exception {
        File dir = jarFolder();
        File bridge = findBridge(dir);
        if (bridge != null) {
            Integer code = runBridge(bridge, args);
            if (code != null) {
                System.exit(code);
                return;
            }
        } else {
            System.err.println("faf-ice-adapter shim: no faf-netbridge next to " + dir + ", using the original adapter");
        }
        runOriginal(dir, args);
    }

    private static File jarFolder() throws Exception {
        File jar = new File(IceAdapter.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        return jar.isDirectory() ? jar : jar.getParentFile();
    }

    private static File findBridge(File dir) {
        for (String name : new String[] {"faf-netbridge.exe", "faf-netbridge"}) {
            File f = new File(dir, name);
            if (f.isFile()) {
                return f;
            }
        }
        return null;
    }

    /** Returns the bridge's exit code, or null when the original adapter should run instead. */
    private static Integer runBridge(File bridge, String[] args) throws InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add(bridge.getAbsolutePath());
        for (String a : args) {
            cmd.add(a);
        }
        Process p;
        try {
            p = new ProcessBuilder(cmd).inheritIO().start();
        } catch (Exception e) {
            System.err.println("faf-ice-adapter shim: cannot start " + bridge + ": " + e + ", using the original adapter");
            return null;
        }
        // The client stops the adapter with the RPC quit call; a killed shim takes the bridge with it.
        Runtime.getRuntime().addShutdownHook(new Thread(p::destroy));
        if (p.waitFor(STARTUP_MILLIS, TimeUnit.MILLISECONDS)) {
            int code = p.exitValue();
            if (code != 0) {
                System.err.println("faf-ice-adapter shim: faf-netbridge exited with " + code
                        + " during startup, using the original adapter");
                return null;
            }
            return 0;
        }
        return p.waitFor();
    }

    /**
     * Runs FAF's adapter in this JVM. Its main class has this class's name, so it is loaded by a class loader
     * that sees the original jar and the rest of the class path (the JavaFX jars), but not this shim.
     */
    private static void runOriginal(File dir, String[] args) throws Exception {
        File orig = new File(dir, "faf-ice-adapter.orig.jar");
        if (!orig.isFile()) {
            System.err.println("faf-ice-adapter shim: " + orig + " is missing too");
            System.exit(1);
            return;
        }
        String self = new File(IceAdapter.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .getAbsolutePath();
        List<URL> urls = new ArrayList<>();
        urls.add(orig.toURI().toURL());
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            if (!entry.isEmpty() && !new File(entry).getAbsolutePath().equals(self)) {
                urls.add(new File(entry).toURI().toURL());
            }
        }
        URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]), ClassLoader.getPlatformClassLoader());
        Thread.currentThread().setContextClassLoader(loader);
        Class<?> main = Class.forName("com.faforever.iceadapter.IceAdapter", true, loader);
        Method m = main.getMethod("main", String[].class);
        m.invoke(null, (Object) args);
    }
}
