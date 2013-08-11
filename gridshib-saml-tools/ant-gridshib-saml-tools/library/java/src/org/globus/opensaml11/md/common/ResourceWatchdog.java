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

import java.io.IOException;
import java.net.URLConnection;

import org.apache.log4j.Logger;

/**
 * Watchdog thread that polls resources at a specified interval and takes actions as prescribed by implementors.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public abstract class ResourceWatchdog extends Thread {

	private static Logger log = Logger.getLogger(ResourceWatchdog.class.getName());

	final static public long DEFAULT_DELAY = 60000;
	private long delay = DEFAULT_DELAY;
	protected ShibResource resource;

	private long lastModified = 0;
	protected boolean interrupted = false;
	protected long retries = 0;
	protected long maxRetries;
	final static public long DEFAULT_MAX_RETRIES = 10;

	protected ResourceWatchdog(ShibResource resource) {

		this.resource = resource;
		setDaemon(true);
		setDelay(DEFAULT_DELAY);
		if (getPriority() > Thread.MIN_PRIORITY) {
			setPriority(getPriority() - 1);
		}
		this.maxRetries = DEFAULT_MAX_RETRIES;
		lastModified = System.currentTimeMillis();
	}

	/**
	 * @param delay
	 *            the delay to observe between each check of the file changes.
	 * @param maxRetries
	 *            the maximum number of times to retry loading after the resource becomes unreachable or 0 for no
	 *            maximum
	 */
	protected ResourceWatchdog(ShibResource resource, long delay, long maxRetries) {

		this(resource, delay);
		this.maxRetries = maxRetries;
	}

	protected ResourceWatchdog(ShibResource resource, long delay) {

		this(resource);
		if (delay > 5000) {
			setDelay(delay);
			return;
		}
		try {
			log.warn("You have set the reload delay on resource (" + resource.getURL().toString() + ") to (" + delay
					+ ") seconds, which will probably cause perfomance problems.  Running with default reload "
					+ "time of (" + DEFAULT_DELAY + ") seconds...");
		} catch (IOException e) {
			log.warn("You have set the reload delay on a resource to (" + delay
					+ ") seconds, which will probably cause perfomance problems.  Running with default reload "
					+ "time of (" + DEFAULT_DELAY + ") seconds...");
		} finally {
			setDelay(DEFAULT_DELAY);
		}
	}

	/**
	 * Set the delay to observe between each check of the file changes.
	 */
	public void setDelay(long delay) {

		this.delay = delay;
	}

	/**
	 * This method is called when the Watchdog detects a change in the resource.
	 * 
	 * @throws WatchdogException
	 *             if it cannot perform the intended operation
	 */
	abstract protected void doOnChange() throws ResourceWatchdogExecutionException;

	protected void checkAndRun() {

		URLConnection connection = null;
		try {
			connection = resource.getURL().openConnection();
			connection.connect();

			log.debug("Checking for updates to resource (" + resource.getURL().toString() + ")");

			long newLastModified = connection.getLastModified();

			if (newLastModified < 1) {
				interrupted = true;
				log.error("Resource (" + resource.getURL().toString() + ") does not provide modification dates.  "
						+ "Resource cannot be reloaded.");
				return;
			}

			if (newLastModified > lastModified) {
				log.debug("Previous Last Modified: " + lastModified + " New Last Modified: " + newLastModified);
				log.info("Found update for resource (" + resource.getURL().toString() + ")");
				lastModified = newLastModified;
				doOnChange();
				retries = 0;

			}

		} catch (Exception e) {
			try {
				if (maxRetries == 0 || retries < maxRetries) {
					log.error("Resource (" + resource.getURL().toString() + ") could not be loaded.  "
							+ "Will retry later.");
					retries++;
					return;

				} else {
					log.error("Unsuccessfully attempted to load resource (" + resource.getURL().toString()
							+ ") too many times.  " + "Resource cannot be reloaded.");
					interrupted = true;
					return;
				}
			} catch (IOException ioe) {
				log.error("Unsuccessfully attempted to load a resource too many times.  "
						+ "Resource cannot be reloaded.");
				interrupted = true;
				return;
			}
		} finally {
			// Silliness to avoid file descriptor leaks
			if (connection != null) {
				try {
					connection.getInputStream().close();
				} catch (IOException e1) {
					// ignore
				}
			}
		}

	}

	public void run() {

		while (!interrupted) {
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				// not applicable
			}
			checkAndRun();
		}
	}

}
