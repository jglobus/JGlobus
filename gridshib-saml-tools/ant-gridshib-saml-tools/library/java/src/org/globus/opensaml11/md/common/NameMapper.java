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

import java.io.StringReader;
import java.lang.reflect.Constructor;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import org.globus.opensaml11.md.common.provider.SharedMemoryShibHandle;
import org.globus.opensaml11.md.xml.Parser;

/**
 * Facility for managing mappings from SAML Name Identifiers to local {@link LocalPrincipal}objects. Mappings are
 * registered by Name Identifier format and can be associated with a <code>String</code> id and recovered based on the
 * same.
 *
 * @author Walter Hoehn
 * @see NameIdentifierMapping
 */
public class NameMapper {

    private static Logger log = Logger.getLogger(NameMapper.class.getName());
    private Map byFormat = new HashMap();
    private Map byId = new HashMap();
    private static Map registeredMappingTypes = Collections.synchronizedMap(new HashMap());
    /** true if mappings have been added */
    protected boolean initialized = false;
    /** Mapping to use if no other mappings have been added */
    protected SharedMemoryShibHandle defaultMapping;

    // Preload aliases for bundled mappings
    static {
        try {
            registeredMappingTypes.put("CryptoHandleGenerator", Class
                    .forName("org.globus.opensaml11.md.common.provider.CryptoShibHandle"));

            registeredMappingTypes.put("SharedMemoryShibHandle", Class
                    .forName("org.globus.opensaml11.md.common.provider.SharedMemoryShibHandle"));

            registeredMappingTypes.put("Principal", Class
                    .forName("org.globus.opensaml11.md.common.provider.PrincipalNameIdentifier"));

        } catch (ClassNotFoundException e) {
            log.error("Unable to pre-register Name mapping implementation types.");
        }
    }

    /**
     * Constructs the name mapper and loads a default name mapping.
     */
    public NameMapper() {

        try {
            // Load the default mapping
            String rawConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<NameMapping xmlns=\"urn:mace:shibboleth:namemapper:1.0\" format=\"urn:mace:shibboleth:1.0:nameIdentifier\""
                    + "     handleTTL=\"1800\"/>";
            Parser.DOMParser parser = new Parser.DOMParser(false);
            parser.parse(new InputSource(new StringReader(rawConfig)));
            defaultMapping = new SharedMemoryShibHandle(parser.getDocument().getDocumentElement());

        } catch (Exception e) {
            log.error("Unable to register default Name Identifier Mapping: " + e);
            initialize();
        }
    }

    protected void initialize() {

        initialized = true;
        defaultMapping = null;
    }

    /**
     * Constructs a {@link NameIdentifierMapping}based on XML configuration data and adds it to this {@link NameMapper},
     * registering it according to its format.
     *
     * @param e
     *            An XML representation of a {@link NameIdentifierMapping}
     * @throws NameIdentifierMappingException
     *             If the mapping could not be constructed according to the supplied configuration
     */
    public void addNameMapping(Element e) throws NameIdentifierMappingException {

        if (!e.getLocalName().equals("NameMapping")) { throw new IllegalArgumentException(); }

        log.info("Found Name Mapping. Loading...");

        String type = ((Element) e).getAttribute("type");
        String implementation = ((Element) e).getAttribute("class");
        if (type != null && (!type.equals("")) && implementation != null && (!implementation.equals(""))) {
            log.error("Name Mapping has both a \"type\" and a \"class\" attribute. Only \"type\" will take effect.");
        }

        if (type != null && (!type.equals(""))) {

            Class registeredImplementation = (Class) registeredMappingTypes.get(type);
            if (registeredImplementation == null) {
                log.error("Name Mapping refers to an unregistered implementation type.");
                throw new NameIdentifierMappingException("Invalid mapping implementation specified.");
            }

            log.debug("Found type (" + type + ") registered with an implementation class of ("
                    + registeredImplementation.getName() + ").");
            addNameMapping(loadNameIdentifierMapping(registeredImplementation, e));

        } else if (implementation != null && (!implementation.equals(""))) {

            try {
                Class implementorClass = Class.forName(implementation);
                addNameMapping(loadNameIdentifierMapping(implementorClass, e));

            } catch (ClassNotFoundException cnfe) {
                log.error("Name Mapping refers to an implementation class that cannot be loaded: " + cnfe);
                throw new NameIdentifierMappingException("Invalid mapping implementation specified.");
            }

        } else {
            log.error("Name Mapping requires either a \"type\" or a \"class\" attribute.");
            throw new NameIdentifierMappingException("No mapping implementation specified.");
        }

    }

    /**
     * Adds a {@link NameIdentifierMapping}to this name mapper, registering it according to its format.
     *
     * @param mapping
     *            the mapping to add
     */
    public void addNameMapping(NameIdentifierMapping mapping) {

        initialize();

        if (byFormat.containsKey(mapping.getNameIdentifierFormat())) {
            log.error("Attempted to register multiple Name Mappings with the same format.  Skipping duplicates...");
            return;
        }
        byFormat.put(mapping.getNameIdentifierFormat(), mapping);

        if (mapping.getId() != null && !mapping.getId().equals("")) {
            byId.put(mapping.getId(), mapping);
        }

    }

    /**
     * Returns the {@link NameIdentifierMapping}registered for a given format.
     *
     * @param format
     *            the registered format
     * @return the mapping or <code>null</code> if no mapping is registered for the given format
     */
    public NameIdentifierMapping getNameIdentifierMapping(URI format) {

        if (!initialized) { return defaultMapping; }

        return (NameIdentifierMapping) byFormat.get(format);
    }

    /**
     * Returns the <code>NameIdentifierMapping</code> registered for a given id
     *
     * @param id
     *            the registered id
     * @return the mapping or <tt>null</tt> if no mapping is registered for the given id
     */
    public NameIdentifierMapping getNameIdentifierMappingById(String id) {

        if (id == null || id.equals("")) {
            if (!initialized) { return defaultMapping; }

            if (byFormat.size() == 1) {
                Iterator values = byFormat.values().iterator();
                Object mapping = values.next();
                return (NameIdentifierMapping) mapping;
            }
        }

        return (NameIdentifierMapping) byId.get(id);
    }

    protected NameIdentifierMapping loadNameIdentifierMapping(Class implementation, Element config)
            throws NameIdentifierMappingException {

        try {
            Class[] params = new Class[]{Element.class};
            Constructor implementorConstructor = implementation.getConstructor(params);
            Object[] args = new Object[]{config};
            log.debug("Initializing Name Identifier Mapping of type (" + implementation.getName() + ").");
            return (NameIdentifierMapping) implementorConstructor.newInstance(args);

        } catch (NoSuchMethodException nsme) {
            log.error("Failed to instantiate a Name Identifier Mapping: NameIdentifierMapping "
                    + "implementation must contain a constructor that accepts an Element object for "
                    + "configuration data.");
            throw new NameIdentifierMappingException("Failed to instantiate a Name Identifier Mapping.");

        } catch (Exception e) {
            log.error("Failed to instantiate a Name Identifier Mapping: " + e + ":" + e.getCause());
            throw new NameIdentifierMappingException("Failed to instantiate a Name Identifier Mapping: " + e);

        }

    }

    /**
     * Maps a SAML Name Identifier to a local principal using the appropriate registered mapping.
     *
     * @param nameId
     *            the SAML Name Identifier that should be converted
     * @param sProv
     *            the provider initiating the request
     * @param idProv
     *            the provider handling the request
     * @return the local principal
     * @throws NameIdentifierMappingException
     *             If the {@link NameMapper}encounters an internal error
     * @throws InvalidNameIdentifierException
     *             If the {@link SAMLNameIdentifier}contains invalid data
     */
    public Principal getPrincipal(SAMLNameIdentifier nameId, ServiceProvider sProv, IdentityProvider idProv)
            throws NameIdentifierMappingException, InvalidNameIdentifierException {

        NameIdentifierMapping mapping = null;
        log.debug("Name Identifier format: (" + nameId.getFormat() + ").");
        try {
            mapping = getNameIdentifierMapping(new URI(nameId.getFormat()));
        } catch (URISyntaxException e) {
            log.error("Invalid Name Identifier format.");
        }
        if (mapping == null) { throw new NameIdentifierMappingException("Name Identifier format not registered."); }
        return mapping.getPrincipal(nameId, sProv, idProv);
    }

    /**
     * Maps a local principal to a SAML Name Identifier using the mapping registered under a given id.
     *
     * @param id
     *            the id under which the effective <code>NameIdentifierMapping</code> is registered
     * @param principal
     *            the principal to map
     * @param sProv
     *            the provider initiating the request
     * @param idProv
     *            the provider handling the request
     * @return the name identifier that maps to the given principal
     * @throws NameIdentifierMappingException
     *             If the <code>NameMapper</code> encounters an internal error
     */
    public SAMLNameIdentifier getNameIdentifier(String id, LocalPrincipal principal, ServiceProvider sProv,
            IdentityProvider idProv) throws NameIdentifierMappingException {

        NameIdentifierMapping mapping = getNameIdentifierMappingById(id);

        if (mapping == null) { throw new NameIdentifierMappingException("Name Identifier id not registered."); }
        return mapping.getNameIdentifier(principal, sProv, idProv);
    }

    /**
     * Cleanup resources that won't be released when this object is garbage-collected
     */
    public void destroy() {

        Iterator mappingIterator = byFormat.values().iterator();
        while (mappingIterator.hasNext()) {
            ((NameIdentifierMapping) mappingIterator.next()).destroy();
        }
    }
}