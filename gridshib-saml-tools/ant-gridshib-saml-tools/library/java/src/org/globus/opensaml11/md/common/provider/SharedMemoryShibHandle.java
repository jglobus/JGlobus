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

package org.globus.opensaml11.md.common.provider;

import org.apache.log4j.Logger;
import org.globus.opensaml11.md.common.IdentityProvider;
import org.globus.opensaml11.md.common.InvalidNameIdentifierException;
import org.globus.opensaml11.md.common.LocalPrincipal;
import org.globus.opensaml11.md.common.NameIdentifierMapping;
import org.globus.opensaml11.md.common.NameIdentifierMappingException;
import org.globus.opensaml11.md.common.ServiceProvider;
import org.globus.opensaml11.saml.SAMLConfig;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * {@link NameIdentifierMapping}implementation that uses an in-memory cache to store mappings between principal names
 * and Shibboleth Attribute Query Handles.
 * 
 * @author Walter Hoehn
 */
public class SharedMemoryShibHandle extends AQHNameIdentifierMapping implements NameIdentifierMapping {

	protected HandleCache cache = HandleCache.instance();
	private static Logger log = Logger.getLogger(SharedMemoryShibHandle.class.getName());
	private static SAMLConfig config = SAMLConfig.instance();

	public SharedMemoryShibHandle(Element config) throws NameIdentifierMappingException {

		super(config);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.common.NameIdentifierMapping#getNameIdentifier(edu.internet2.middleware.shibboleth.common.LocalPrincipal,
	 *      edu.internet2.middleware.shibboleth.common.ServiceProvider,
	 *      edu.internet2.middleware.shibboleth.common.IdentityProvider)
	 */
	public SAMLNameIdentifier getNameIdentifier(LocalPrincipal principal, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException {

		if (principal == null) {
			log.error("A principal must be supplied for Attribute Query Handle creation.");
			throw new IllegalArgumentException("A principal must be supplied for Attribute Query Handle creation.");
		}
		try {
			String handle = new String(config.getDefaultIDProvider().getIdentifier());
			log.debug("Assigning handle (" + handle + ") to principal (" + principal.getName() + ").");
			synchronized (cache.handleEntries) {
				cache.handleEntries.put(handle, createHandleEntry(principal));
			}

			SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(getNameIdentifierFormat().toString());
			nameid.setName(handle);
			nameid.setNameQualifier(idProv.getProviderId());
			return nameid;

		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate Attribute Query Handle: " + e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see edu.internet2.middleware.shibboleth.common.NameIdentifierMapping#getPrincipal(org.globus.opensaml11.saml.SAMLNameIdentifier,
	 *      edu.internet2.middleware.shibboleth.common.ServiceProvider,
	 *      edu.internet2.middleware.shibboleth.common.IdentityProvider)
	 */
	public Principal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
			throws NameIdentifierMappingException, InvalidNameIdentifierException {

		verifyQualifier(nameId, idProv);

		synchronized (cache.handleEntries) {
			if (!cache.handleEntries.containsKey(nameId.getName())) {
				log.debug("The Name Mapping Cache does not contain an entry for this Attribute Query Handle.");
				throw new InvalidNameIdentifierException(
						"The Name Mapping Cache does not contain an entry for this Attribute Query Handle.", errorCodes);
			}
		}

		HandleEntry handleEntry;
		synchronized (cache.handleEntries) {
			handleEntry = (HandleEntry) cache.handleEntries.get(nameId.getName());
		}

		if (handleEntry.isExpired()) {
			log.debug("Attribute Query Handle is expired.");
			synchronized (cache.handleEntries) {
				cache.handleEntries.remove(nameId.getName());
			}
			throw new InvalidNameIdentifierException("Attribute Query Handle is expired.", errorCodes);
		} else {
			log.debug("Attribute Query Handle recognized.");
			return handleEntry.principal;
		}
	}

	public void destroy() {

		cache.destroy();
	}

}

class HandleCache {

	protected Map handleEntries = new HashMap();
	private static HandleCache instance;
	protected MemoryRepositoryCleaner cleaner = new MemoryRepositoryCleaner();
	private static Logger log = Logger.getLogger(HandleCache.class.getName());

	protected HandleCache() {

	}

	public static synchronized HandleCache instance() {

		if (instance == null) {
			instance = new HandleCache();
			return instance;
		}
		return instance;
	}

	protected void finalize() throws Throwable {

		super.finalize();
		destroy();
	}

	protected void destroy() {

		synchronized (cleaner) {
			if (cleaner != null) {
				cleaner.shutdown = true;
				cleaner.interrupt();
			}
		}
	}

	private class MemoryRepositoryCleaner extends Thread {

		private boolean shutdown = false;
		private Thread master;

		public MemoryRepositoryCleaner() {

			super(
					"org.globus.opensaml11.md.common.provider.SharedMemoryShibHandle.HandleCache.MemoryRepositoryCleaner");
			this.master = Thread.currentThread();
			setDaemon(true);
			if (getPriority() > Thread.MIN_PRIORITY) {
				setPriority(getPriority() - 1);
			}
			log.debug("Starting memory-based shib handle cache cleanup thread.");
			start();
		}

		public void run() {

			try {
				sleep(60 * 1000); // one minute
			} catch (InterruptedException e) {
				log.debug("Memory-based shib handle cache cleanup interrupted.");
			}
			while (true) {
				try {
					if (!master.isAlive()) {
						shutdown = true;
						log.debug("Memory-based shib handle cache cleaner is orphaned.");
					}
					if (shutdown) {
						log.debug("Stopping Memory-based shib handle cache cleanup thread.");
						return;
					}
					log.debug("Memory cache handle cache cleanup thread searching for stale entries.");
					Set needsDeleting = new HashSet();
					synchronized (handleEntries) {
						Iterator iterator = handleEntries.entrySet().iterator();
						while (iterator.hasNext()) {
							Entry entry = (Entry) iterator.next();
							HandleEntry handleEntry = (HandleEntry) entry.getValue();
							if (handleEntry.isExpired()) {
								needsDeleting.add(entry.getKey());
							}
						}
						// release the lock to be friendly
						Iterator deleteIterator = needsDeleting.iterator();
						while (deleteIterator.hasNext()) {
							synchronized (handleEntries) {
								log.debug("Expiring an Attribute Query Handle from the memory cache.");
								handleEntries.remove(deleteIterator.next());
							}
						}
					}
					sleep(60 * 1000); // one minute
				} catch (InterruptedException e) {
					log.debug("Memory-based shib handle cache cleanup interrupted.");
				}
			}
		}
	}

}