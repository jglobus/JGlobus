package org.globus.util;

import java.io.File;
import java.net.MalformedURLException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.net.URI;

import org.apache.commons.io.IOExceptionWithCause;

/**
 * This class provides a way of managing file system resources
 * in a manner similar to the spring framework's Resource class.
 *
 * 3/2/2012
 */

public class GlobusResource {

    //A file instance of the specified resourcePath
    private File resourceFile = null;
    //The path to the file
    private String resourcePath = null;

    /**
     * Creates a new instance of GlobusResource referencing the
     * specified resourcePath.
     *
     * @param resourcePath The path to the specified resource in the style
     *                 /directory/directory/fileName.ext
     */
    public GlobusResource(String resourcePath) {
        this.resourcePath = resourcePath;
        this.resourceFile = new File(resourcePath);
    }

    /**
     * @return A string representation of the resource's URI
     */
    public String toURI() {
        return resourceFile.toURI().toASCIIString();
    }

    /**
     * @return A string representation of the resource's URL
     * @throws MalformedURLException
     */
    public String toURL() throws MalformedURLException {
        String fileURLPathString = null;
        fileURLPathString = resourceFile.toURI().toURL().toString();
        return fileURLPathString;
    }

    /**
     * @return The resource's URI(java.Net.URI)
     * @throws IOException
     */
    public URI getURI() throws IOException {
        return resourceFile.toURI();
    }

    /**
     * @return The resource's URL(java.Net.URL)
     * @throws MalformedURLException
     */
    public URL getURL() throws MalformedURLException {
        return resourceFile.toURI().toURL();
    }

    /**
     * @return A new java.io.File object referencing the resource's resourcePath
     * @throws IOException
     */
    public File getFile() throws IOException {
        File duplicateFile = new File(this.resourceFile.getAbsolutePath());
        return duplicateFile;
    }

    /**
     * @return True if the resource exists, and false if the resource does not exist
     */
    public boolean exists() {
        return this.resourceFile.exists();
    }

    /**
     * @return The time the resource was last modified
     * @throws IOException
     */
    public long lastModified() throws IOException {
        return this.resourceFile.lastModified();
    }

    /**
     * @return True if the resource is readable, false if the resource is not readable
     */
    public boolean isReadable() {
        return this.resourceFile.canRead();
    }

    /**
     * @return A new InputStream(java.io.InputStream) of the resource
     * @throws FileNotFoundException
     * @throws IOException
     */
    public InputStream getInputStream() throws FileNotFoundException, IOException {
        InputStream fileInputStream = new FileInputStream(this.getFile());
        return fileInputStream;
    }

    /**
     * @return The name of the resource in the style fileName.ext
     */
    public String getFilename() {
        return this.resourcePath.substring(resourcePath.lastIndexOf("/") + 1, resourcePath.length());
    }

    /**
     * @return A string representing resourcePath and URI of the resource
     */
    @Override
    public String toString() {
        return String.format("resourcePath: %s\nURI: %s\n", this.resourcePath, this.toURI());
    }
}
