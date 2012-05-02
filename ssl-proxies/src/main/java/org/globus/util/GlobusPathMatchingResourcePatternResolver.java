package org.globus.util;

import org.apache.commons.codec.net.URLCodec;

import java.io.File;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.net.MalformedURLException;

/**
 * Provides methods to resolve locationPatterns and return GlobusResource
 * objects which match those location patterns.  Supports Ant-Style regular
 * expressions, where:
 * ** matches any number of directories
 * ? matches one character
 * * matches any number of characters
 *
 * Supports file:, classpath:, and relative paths.
 * Provides similar functionality to spring framework's PathMatchingResourcePatternResolver
 *
 * 3/2/2012
 */

public class GlobusPathMatchingResourcePatternResolver {
    //Regex style pattern to match locations
    private Pattern locationPattern = null;
    /**
     * Path from root directory to the directory at the beginning of a classpath.
     * For example if a class was in a package org.globus.utils.MyClass.java,
     * which had an absolute path of /user/userName/project/resources/org/globus/utils/MyClass.java
     * the mainClassPath would be /user/userName/project/resources/
      */
    private String mainClassPath = "";
    //Holds GlobusResource instances of all the paths which matched the locationPattern
    private Vector<GlobusResource> pathsMatchingLocationPattern = new Vector<GlobusResource>();

    public GlobusPathMatchingResourcePatternResolver() {
    }

    /**
     * This method takes a location string and returns a GlobusResource of the
     * corresponding location.  This method does not accept any patterns for the location string.
     * @param location An absolute or relative location in the style classpath:/folder/className.class,
     *                 file:/folder/fileName.ext, or folder/folder/fileName.ext
     * @return  A GlobusResource type object of the corresponding location string.
     */
    public GlobusResource getResource(String location) {
        GlobusResource returnResource;
        URL resourceURL;
        if (location.startsWith("classpath:")) {
            resourceURL = getClass().getClassLoader().getResource(location.replaceFirst("classpath:/", ""));
            returnResource = new GlobusResource(resourceURL.getPath());
        } else if (location.startsWith("file:")) {
            returnResource = new GlobusResource(location.replaceFirst("file:", ""));
        } else
            returnResource = new GlobusResource(location);
        return returnResource;
    }

    /**
     * Finds all the resources that match the Ant-Style locationPattern
     * @param locationPattern  Ant-Style location pattern which may be prefixed with
     *                         classpath:/, file:/, or describe a relative path.
     * @return An array of GlobusResource containing all resources whose locaiton match the locationPattern
     */
    public GlobusResource[] getResources(String locationPattern) {
        String mainPath = "";
        if (locationPattern.startsWith("classpath:")) {
            URL resourceURL = getClass().getClassLoader().getResource(getPathUntilWildcard(locationPattern.replaceFirst("classpath:/", "")));
            this.mainClassPath = resourceURL.getPath();
            this.locationPattern = Pattern.compile(antToRegexConverter(locationPattern.replaceFirst("classpath:/", "")));
            parseDirectoryStructure(new File(this.mainClassPath));
        } else if (locationPattern.startsWith("file:")) {
            if ((locationPattern.replaceFirst("file:", "").compareTo(getPathUntilWildcard(locationPattern.replaceFirst("file:", "")))) == 0) {//Check to see if the pattern is not a pattern
                pathsMatchingLocationPattern.add(new GlobusResource(locationPattern.replaceFirst("file:", "")));
            }
            else {
                try {
                    URL resourceURL = new File(getPathUntilWildcard(locationPattern.replaceFirst("file:", ""))).toURL();
                    mainPath = resourceURL.getPath();
                    this.locationPattern = Pattern.compile(antToRegexConverter(locationPattern.replaceFirst("file:", "")));
                    parseDirectoryStructure(new File(mainPath));
                } catch (MalformedURLException ex) {
                }
            }
        } else {
            mainPath = getPathUntilWildcard(locationPattern);
            this.locationPattern = Pattern.compile(antToRegexConverter(locationPattern));
            parseDirectoryStructure(new File(mainPath));
        }

        return pathsMatchingLocationPattern.toArray(new GlobusResource[0]);
    }

    /**
     * Converts an Ant-style pattern to a regex pattern by replacing (. with \\.), (? with .),
     * (** with .*), and (* with [^/]*).
     * @param antStyleLocationPattern  An Ant-Stlye location pattern.
     * @return A regex style location pattern representation of the antStyleLocationPattern
     */
    private String antToRegexConverter(String antStyleLocationPattern) {
        String regexStyleLocationPattern = antStyleLocationPattern.replaceAll("\\.", "\\\\."); // replace . with \\.
        regexStyleLocationPattern = regexStyleLocationPattern.replaceAll("//", "/");//Solution for known test cases with // issue at org.globus.gsi.proxy.ProxyPathValidatorTest line 536, Needs Review
        regexStyleLocationPattern = regexStyleLocationPattern.replace('?', '.'); // replace ? with .
        regexStyleLocationPattern = regexStyleLocationPattern.replaceAll("\\*", "[^/]*"); //replace all * with [^/]*, this will make ** become [^/]*[^/]*
        regexStyleLocationPattern = regexStyleLocationPattern.replaceAll("\\[\\^/\\]\\*\\[\\^/\\]\\*", ".*"); //now replace the .*.* with just .*
        regexStyleLocationPattern = "^" + this.mainClassPath + regexStyleLocationPattern + "$";  //add the beginning and end symbols, and mainClassPath, if the object is of the type classpath:/
        return regexStyleLocationPattern;
    }

    /**
     * Returns a substring of the locationPattern from the beginning
     * to the first occurrence of * or ?
     * If this is unsuccessful, start at current directory ./
     * @param locationPatternString The Ant-Style location pattern.
     * @return  A substring of the locationPatternString from the beginning to the first occurrence of a wildcard character
     */
    private String getPathUntilWildcard(String locationPatternString) {
        String currentLocationPatternString;

        int locationPatternStringLength = locationPatternString.length();

        //Find the first occurrence of * or ?, if none, set idx to locationPatternLength
        int startIndex, questionMarkIndex;
        if ((startIndex = locationPatternString.indexOf('*')) == -1)
            startIndex = locationPatternStringLength;

        if ((questionMarkIndex = locationPatternString.indexOf('?')) == -1)
            questionMarkIndex = locationPatternStringLength;

        currentLocationPatternString = locationPatternString.substring(0, Math.min(startIndex, questionMarkIndex));
        if (!(new File(currentLocationPatternString).canRead()))
            currentLocationPatternString = "./";
        return currentLocationPatternString;
    }

    /**
     * Go through every directory recursively and perform parseFilesInDirectory method.
     * @param currentDirectory The currentDirectory to explore.
     */
    private void parseDirectoryStructure(File currentDirectory) {
        parseFilesInDirectory(currentDirectory);
        File[] directoryContents = currentDirectory.listFiles();
        for (File currentFile : directoryContents) {
            if (currentFile.isDirectory()) {
                parseDirectoryStructure(currentFile);
            }
        }
    }

    /**
     * Compares every file's Absolute Path against the locationPattern, if they match
     * a GlobusResource is created with the file's Absolute Path and added to pathsMatchingLocationPattern.
     * @param currentDirectory  The directory whose files to parse.
     */
    private void parseFilesInDirectory(File currentDirectory) {
        File[] directoryContents = currentDirectory.listFiles();    //Get a list of the files and directories
        String absolutePath = null;
        Matcher locationPatternMatcher = null;
        if(directoryContents != null){
        for (File currentFile : directoryContents) {
            if (currentFile.isFile()) { //We are only interested in files not directories
                absolutePath = currentFile.getAbsolutePath();
                locationPatternMatcher = locationPattern.matcher(absolutePath);
                if (locationPatternMatcher.find()) {
                    pathsMatchingLocationPattern.add(new GlobusResource(absolutePath));
                }
            }
        }
        }
    }
}
