package org.globus.gsi;

public class VersionUtil {

    /**
     * Checks if GSI-3 mode is enabled.
     *
     * @return true if <I>"org.globus.gsi.version"</I> system property
     *         is set to "3". Otherwise, false.
     */
    public static boolean isGsi3Enabled() {
        String ver = System.getProperty("org.globus.gsi.version");
        return (ver != null && ver.equals("3"));
    }

    /**
     * Checks if GSI-2 mode is enabled.
     *
     * @return true if <I>"org.globus.gsi.version"</I> system property
     *         is set to "2". Otherwise, false.
     */
    public static boolean isGsi2Enabled() {
        String ver = System.getProperty("org.globus.gsi.version");
        return (ver != null && ver.equals("2"));
    }

}
