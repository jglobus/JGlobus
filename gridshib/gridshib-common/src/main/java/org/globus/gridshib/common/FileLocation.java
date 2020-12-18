/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 * Copyright 2006-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.globus.gridshib.common;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * Manages access to location-based (i.e., file: URLs) resources
 * in a consistent fashion.
 *
 * @see org.globus.opensaml11.md.common.ShibResource
 */
public class FileLocation {

    private URL location = null;

    public FileLocation(String name) throws ResourceNotAvailableException {

        this(name, FileLocation.class);
    }

    public FileLocation(String name, Class requester)
                 throws ResourceNotAvailableException {

        if (name == null) {
            String msg = "Null argument";
            throw new IllegalArgumentException(msg);
        }

        try {
            location = new URL(name);
        } catch (MalformedURLException e) {
            location = requester.getResource(name);
        }

        if (location == null) {
            String msg = "Resource not found at specified location: ";
            msg += name;
            throw new ResourceNotAvailableException(msg);
        }
    }

    /**
     * Returns an input stream to read the file contents
     */
    public InputStream getInputStream() throws IOException {

        return location.openStream();
    }

    /**
     * Returns a <code>File</code> representation of the file
     */
    public File toFile() throws IOException {

        try {
            File file =
                new File(new URI(location.toString().replaceAll("\\s", "%20")));
            return file;
        } catch (URISyntaxException e) {
            String str = "Invalid URI: " + e.getMessage();
            throw new ResourceNotAvailableException(str);
        } catch (IllegalArgumentException e) {
            String str = "Illegal argument: " + e.getMessage();
            throw new ResourceNotAvailableException(str);
        }
    }

    /**
     * Returns a <code>URL</code> pointer to the file
     */
    public URL toURL() throws IOException {

        return location;
    }

    public class ResourceNotAvailableException extends IOException {

        public ResourceNotAvailableException(String message) {

            super(message);
        }
    }
}
