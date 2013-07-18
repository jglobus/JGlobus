/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
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

package org.globus.opensaml11.md.common;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * Manages access to shibboleth file-based resources in a consistent fashion.
 */
public class ShibResource {

	private URL resource;

	public ShibResource(String name) throws ResourceNotAvailableException {

		this(name, ShibResource.class);
	}

	public ShibResource(String name, Class requester) throws ResourceNotAvailableException {

		try {
			resource = new URL(name);
		} catch (MalformedURLException e) {
			resource = requester.getResource(name);
		}
		if (resource == null) {
			throw new ResourceNotAvailableException(
				"ShibResource could not be found at the specified location: " + name);
		}
	}

	/**
	 * Returns an input stream to read the resource contents
	 */
	public InputStream getInputStream() throws IOException {

		return resource.openStream();
	}

	/**
	 * Returns a <code>File</code> representation of the resource
	 */
	public File getFile() throws IOException {

		try {
			File file = new File(new URI(resource.toString().replaceAll("\\s", "%20")));
			return file;
		} catch (URISyntaxException e) {
			throw new ResourceNotAvailableException("File could not be loaded from specified resource: " + e);
		} catch (IllegalArgumentException e) {
			throw new ResourceNotAvailableException("File could not be loaded from specified resource: " + e);
		}
	}

	/**
	 * Returns a <code>URL</code> pointer to the resource
	 */
	public URL getURL() throws IOException {

		return resource;
	}

	public class ResourceNotAvailableException extends IOException {

		public ResourceNotAvailableException(String message) {

			super(message);
		}
	}

}
