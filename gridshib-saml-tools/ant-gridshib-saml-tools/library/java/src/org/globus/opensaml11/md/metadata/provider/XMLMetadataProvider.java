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

package org.globus.opensaml11.md.metadata.provider;

import org.globus.opensaml11.md.common.Constants;
import org.globus.opensaml11.md.common.PluggableConfigurationComponent;
import org.globus.opensaml11.md.metadata.AffiliationDescriptor;
import org.globus.opensaml11.md.metadata.AttributeAuthorityDescriptor;
import org.globus.opensaml11.md.metadata.AttributeConsumingService;
import org.globus.opensaml11.md.metadata.AttributeRequesterDescriptor;
import org.globus.opensaml11.md.metadata.AuthnAuthorityDescriptor;
import org.globus.opensaml11.md.metadata.ContactPerson;
import org.globus.opensaml11.md.metadata.Endpoint;
import org.globus.opensaml11.md.metadata.EndpointManager;
import org.globus.opensaml11.md.metadata.EntitiesDescriptor;
import org.globus.opensaml11.md.metadata.EntityDescriptor;
import org.globus.opensaml11.md.metadata.ExtendedEntitiesDescriptor;
import org.globus.opensaml11.md.metadata.ExtendedEntityDescriptor;
import org.globus.opensaml11.md.metadata.IDPSSODescriptor;
import org.globus.opensaml11.md.metadata.IndexedEndpoint;
import org.globus.opensaml11.md.metadata.KeyAuthority;
import org.globus.opensaml11.md.metadata.KeyDescriptor;
import org.globus.opensaml11.md.metadata.Metadata;
import org.globus.opensaml11.md.metadata.MetadataException;
import org.globus.opensaml11.md.metadata.Organization;
import org.globus.opensaml11.md.metadata.PDPDescriptor;
import org.globus.opensaml11.md.metadata.RoleDescriptor;
import org.globus.opensaml11.md.metadata.SPSSODescriptor;
import org.globus.opensaml11.md.metadata.SSODescriptor;
import org.globus.opensaml11.md.metadata.ScopedRoleDescriptor;
import org.apache.log4j.Logger;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.globus.opensaml11.saml.SAMLAttribute;
import org.globus.opensaml11.saml.SAMLBinding;
import org.globus.opensaml11.saml.SAMLBrowserProfile;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.XML;
import org.globus.opensaml11.saml.artifact.Artifact;
import org.globus.opensaml11.saml.artifact.SAMLArtifactType0001;
import org.globus.opensaml11.saml.artifact.SAMLArtifactType0002;
import org.globus.opensaml11.saml.artifact.Util;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TimeZone;

/**
 * @author Scott Cantor
 */
public class XMLMetadataProvider implements Metadata, PluggableConfigurationComponent {

    private static Logger log = Logger.getLogger(XMLMetadataProvider.class.getName());
    private Map /* <String,ArrayList<EntityDescriptor> > */ sites = new HashMap();
    private Map /* <String,ArrayList<EntityDescriptor> > */ sources = new HashMap();
    private XMLEntityDescriptor rootProvider = null;
    private XMLEntitiesDescriptor rootGroup = null;

    public XMLMetadataProvider(Element e) throws SAMLException {
        initialize(e);
    }

    public XMLMetadataProvider() {} // Must call initialize

    public void initialize(Element e) throws SAMLException {
        if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"EntitiesDescriptor"))
            rootGroup=new XMLEntitiesDescriptor(e,this, Long.MAX_VALUE, null);
        else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"EntityDescriptor"))
            rootProvider=new XMLEntityDescriptor(e,this, Long.MAX_VALUE, null);
        else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SHIB_NS,"SiteGroup"))
            rootGroup=new XMLEntitiesDescriptor(e,this, Long.MAX_VALUE, null);
        else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SHIB_NS,"OriginSite"))
            rootProvider=new XMLEntityDescriptor(e,this, Long.MAX_VALUE, null);
        else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SHIB_NS,"DestinationSite"))
            rootProvider=new XMLEntityDescriptor(e,this, Long.MAX_VALUE, null);
        else {
            log.error("Construction requires a valid SAML metadata file");
            throw new MetadataException("Construction requires a valid SAML metadata file");
        }
    }

    public EntityDescriptor lookup(String id, boolean strict) {
        ArrayList list = (ArrayList)sites.get(id);
        if (list != null) {
            long now = System.currentTimeMillis();
            for (int i=0; i<list.size(); i++) {
                if (now < ((XMLEntityDescriptor)list.get(i)).getValidUntil())
                    return (EntityDescriptor)list.get(i);
            }
            if (!strict && list.size() > 0)
                return (EntityDescriptor)list.get(0);
        }
        return null;
    }

    public EntityDescriptor lookup(Artifact artifact, boolean strict) {
        ArrayList list = null;

        if (artifact instanceof SAMLArtifactType0001) {
            byte[] sourceId = ((SAMLArtifactType0001)artifact).getSourceId();
            String sourceString = new String(Hex.encode(sourceId));
            list = (ArrayList)sources.get(sourceString);
        }
        else if (artifact instanceof SAMLArtifactType0002) {
            URI sourceLocation = ((SAMLArtifactType0002)artifact).getSourceLocation();
            String sourceLocationString = sourceLocation.toString();
            list = (ArrayList)sources.get(sourceLocationString);
        }
        else {
            log.error("unsupported artifact type (" + artifact.getTypeCode().toString() + ")");
        }

        if (list != null) {
            long now = System.currentTimeMillis();
            for (int i=0; i<list.size(); i++) {
                if (now < ((XMLEntityDescriptor)list.get(i)).getValidUntil())
                    return (EntityDescriptor)list.get(i);
            }
            if (!strict && list.size() > 0)
                return (EntityDescriptor)list.get(0);
        }
        return null;
    }

    public EntityDescriptor lookup(String id) {
        return lookup(id, true);
    }

    public EntityDescriptor lookup(Artifact artifact) {
        return lookup(artifact, true);
    }

    public EntityDescriptor getRootEntity() {
        return rootProvider;
    }

    public EntitiesDescriptor getRootEntities() {
        return rootGroup;
    }

    class XMLEndpoint implements Endpoint {
        private Element root = null;
        private String binding = null;
        private String location = null;
        private String resploc = null;

        XMLEndpoint(Element e) {
            root = e;
            binding = XML.assign(e.getAttributeNS(null,"Binding"));
            location = XML.assign(e.getAttributeNS(null,"Location"));
            resploc = XML.assign(e.getAttributeNS(null,"ResponseLocation"));
        }

        XMLEndpoint(String binding, String location) {
            this.binding = binding;
            this.location = location;
        }

        public String getBinding() {
            return binding;
        }

        public String getLocation() {
            return location;
        }

        public String getResponseLocation() {
            return resploc;
        }

        public Element getElement() {
            return root;
        }
    }

    class XMLIndexedEndpoint extends XMLEndpoint implements IndexedEndpoint {
        private int index = 0;

        XMLIndexedEndpoint(Element e) {
            super(e);
            index = Integer.parseInt(e.getAttributeNS(null,"index"));
        }

        public int getIndex() {
            return index;
        }
    }

    class XMLEndpointManager implements EndpointManager {
        private ArrayList endpoints = new ArrayList();
        Endpoint soft = null;   // Soft default (not explicit)
        Endpoint hard = null;   // Hard default (explicit)

        public Iterator getEndpoints() {
            return endpoints.iterator();
        }

        public Endpoint getDefaultEndpoint() {
            if (hard != null) return hard;
            if (soft != null) return soft;
            if (!endpoints.isEmpty()) return (Endpoint)endpoints.get(0);
            return null;
        }

        public Endpoint getEndpointByIndex(int index) {
            for (int i=0; i < endpoints.size(); i++) {
                if (endpoints.get(i) instanceof IndexedEndpoint && index==((IndexedEndpoint)endpoints.get(i)).getIndex())
                    return (Endpoint)endpoints.get(i);
            }
            return null;
        }

        public Endpoint getEndpointByBinding(String binding) {
            for (int i=0; i < endpoints.size(); i++) {
                if (binding.equals(((Endpoint)endpoints.get(i)).getBinding()))
                    return (Endpoint)endpoints.get(i);
            }
            return null;
        }

        protected void add(Endpoint e) {
            endpoints.add(e);
            if (hard == null && e.getElement() != null) {
                String v=XML.assign(e.getElement().getAttributeNS(null,"isDefault"));
                if (v != null && (v.equals("1") || v.equals("true")))  // explicit default
                    hard=e;
                else if (v == null && soft == null)            // implicit default
                    soft=e;
            }
            else if (hard == null && soft == null) {
                // No default yet, so this one qualifies as an implicit.
                soft=e;
            }
        }
    }

    class XMLKeyDescriptor implements KeyDescriptor {

        private int use = KeyDescriptor.UNSPECIFIED;
        private KeyInfo keyInfo = null;
        private ArrayList /* <XMLEncryptionMethod> */ methods = new ArrayList();

        XMLKeyDescriptor(Element e) {
            if (XML.safeCompare(e.getAttributeNS(null,"use"),"encryption"))
                use = KeyDescriptor.ENCRYPTION;
            else if (XML.safeCompare(e.getAttributeNS(null,"use"),"signing"))
                use = KeyDescriptor.SIGNING;

            e = XML.getFirstChildElement(e);
            try {
                keyInfo = new KeyInfo(e, null);
            }
            catch (XMLSecurityException e1) {
                log.error("unable to process ds:KeyInfo element: " + e1.getMessage());
            }

            e = XML.getNextSiblingElement(e);
            while (e != null && XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"EncryptionMethod")) {
                methods.add(new XMLEncryptionMethod(e));
            }
        }

        public int getUse() {
            return use;
        }

        public Iterator getEncryptionMethods() {
            return methods.iterator();
        }

        public KeyInfo getKeyInfo() {
            return keyInfo;
        }
    }

    class XMLEncryptionMethod implements EncryptionMethod {

        String alg = null;
        String params = null;
        int size = 0;

        public XMLEncryptionMethod(Element e) {
            alg = XML.assign(e.getAttributeNS(null, "Algorithm"));
            e = XML.getFirstChildElement(e);
            while (e != null) {
                if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.XMLENC_NS,"KeySize")) {
                    if (e.hasChildNodes())
                        size = Integer.parseInt(e.getFirstChild().getNodeValue());
                }
                else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.XMLENC_NS,"OAEParams")) {
                    if (e.hasChildNodes())
                        params = XML.assign(e.getFirstChild().getNodeValue());
                }
                e = XML.getNextSiblingElement(e);
            }
        }

        public String getAlgorithm() {
            return alg;
        }

        public int getKeySize() {
            return size;
        }

        public byte[] getOAEPparams() {
            return params.getBytes();
        }

        public Iterator getEncryptionMethodInformation() {
            return null;
        }

        public void setKeySize(int arg0) {
            throw new UnsupportedOperationException("EncryptionMethod implementation is read-only.");
        }

        public void setOAEPparams(byte[] arg0) {
            throw new UnsupportedOperationException("EncryptionMethod implementation is read-only.");
        }

        public void addEncryptionMethodInformation(Element arg0) {
            throw new UnsupportedOperationException("EncryptionMethod implementation is read-only.");
        }

        public void removeEncryptionMethodInformation(Element arg0) {
            throw new UnsupportedOperationException("EncryptionMethod implementation is read-only.");
        }
    }

    class XMLKeyAuthority implements KeyAuthority {
        private int depth = 1;
        private ArrayList /* <KeyInfo> */ keys = new ArrayList();

        XMLKeyAuthority(Element e) {
            if (e.hasAttributeNS(null,"VerifyDepth"))
                depth = Integer.parseInt(e.getAttributeNS(null,"VerifyDepth"));
            e = XML.getFirstChildElement(e, XML.XMLSIG_NS, "KeyInfo");
            while (e != null) {
                try {
                    keys.add(new KeyInfo(e, null));
                }
                catch (XMLSecurityException e1) {
                    log.error("unable to process ds:KeyInfo element: " + e1.getMessage());
                }
                e = XML.getNextSiblingElement(e, XML.XMLSIG_NS, "KeyInfo");
            }
        }

        public int getVerifyDepth() {
            return depth;
        }

        public Iterator getKeyInfos() {
            return keys.iterator();
        }

    }

    class XMLOrganization implements Organization {
        private HashMap /* <String,String> */ names = new HashMap();
        private HashMap /* <String,String> */ displays = new HashMap();
        private HashMap /* <String,URL> */ urls = new HashMap();

        public XMLOrganization(Element e) throws MetadataException {
            // Old metadata or new?
            if (XML.isElementNamed(e, org.globus.opensaml11.md.common.XML.SHIB_NS,"Alias")) {
                if (e.hasChildNodes()) {
                    names.put("en",XML.assign(e.getFirstChild().getNodeValue()));
                    displays.put("en",XML.assign(e.getFirstChild().getNodeValue()));
                }
            }
            else {
                e=XML.getFirstChildElement(e);
                while (e != null) {
                    if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"OrganizationName")) {
                        if (e.hasChildNodes()) {
                            names.put(e.getAttributeNS(XML.XML_NS,"lang"),XML.assign(e.getFirstChild().getNodeValue()));
                        }
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"OrganizationDisplayName")) {
                        if (e.hasChildNodes()) {
                            displays.put(e.getAttributeNS(XML.XML_NS,"lang"),XML.assign(e.getFirstChild().getNodeValue()));
                        }
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"OrganizationURL")) {
                        if (e.hasChildNodes()) {
                            URL u;
                            try {
                                u = new URL(e.getFirstChild().getNodeValue());
                            }
                            catch (MalformedURLException e1) {
                                throw new MetadataException("OrganizationURL was invalid: " + e1);
                            }
                            urls.put(e.getAttributeNS(XML.XML_NS,"lang"),u);
                        }
                    }
                    e=XML.getNextSiblingElement(e);
                }
            }
        }

        public String getName() {
            return getName("en");
        }

        public String getName(String lang) {
            return (String)names.get(lang);
        }

        public String getDisplayName() {
            return getDisplayName("en");
        }

        public String getDisplayName(String lang) {
            return (String)displays.get(lang);
        }

        public URL getURL() {
            return getURL("en");
        }

        public URL getURL(String lang) {
            return (URL)urls.get(lang);
        }

    }

    class XMLContactPerson implements ContactPerson {
        private Element root = null;
        private int     type;
        private String  company = null;
        private String  givenName = null;
        private String  surName = null;
        private ArrayList /* <String> */ emails = new ArrayList();
        private ArrayList /* <String> */ telephones = new ArrayList();

        public XMLContactPerson(Element e) throws MetadataException {
            root = e;
            String rawType = null;

            // Old metadata or new?
            if (XML.isElementNamed(root, org.globus.opensaml11.md.common.XML.SHIB_NS,"Contact")) {
                rawType = root.getAttributeNS(null,"Type");
                surName = XML.assign(root.getAttributeNS(null,"Name"));
                if (XML.isEmpty(surName)) {
                    throw new MetadataException("Contact is missing Name attribute.");
                }
                if (root.hasAttributeNS(null,"Email"))
                    emails.add(e.getAttributeNS(null,"Email"));
            }
            else {
                rawType = root.getAttributeNS(null,"contactType");
                e=XML.getFirstChildElement(root);
                while (e != null) {
                    if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Company")) {
                        if (e.hasChildNodes())
                            company=XML.assign(e.getFirstChild().getNodeValue());
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"GivenName")) {
                        if (e.hasChildNodes())
                            givenName=XML.assign(e.getFirstChild().getNodeValue());
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"SurName")) {
                        if (e.hasChildNodes())
                            surName=XML.assign(e.getFirstChild().getNodeValue());
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"EmailAddress")) {
                        if (e.hasChildNodes())
                            emails.add(XML.assign(e.getFirstChild().getNodeValue()));
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"TelephoneNumber")) {
                        if (e.hasChildNodes())
                            telephones.add(XML.assign(e.getFirstChild().getNodeValue()));
                    }
                    e=XML.getNextSiblingElement(e);
                }
            }

            if (rawType.equalsIgnoreCase("TECHNICAL")) {
                type = ContactPerson.TECHNICAL;
            } else if (rawType.equalsIgnoreCase("SUPPORT")) {
                type = ContactPerson.SUPPORT;
            } else if (rawType.equalsIgnoreCase("ADMINISTRATIVE")) {
                type = ContactPerson.ADMINISTRATIVE;
            } else if (rawType.equalsIgnoreCase("BILLING")) {
                type = ContactPerson.BILLING;
            } else if (rawType.equalsIgnoreCase("OTHER")) {
                type = ContactPerson.OTHER;
            } else {
                throw new MetadataException("Contact has unknown contact type.");
            }
        }

        public int getType() {
            return type;
        }

        public String getGivenName() {
            return givenName;
        }

        public String getSurName() {
            return surName;
        }

        public String getCompany() {
            return company;
        }

        public Iterator getEmailAddresses() {
            return emails.iterator();
        }

        public Iterator getTelephoneNumbers() {
            return telephones.iterator();
        }

        public Element getElement() {
            return root;
        }
    }

    class Role implements RoleDescriptor {
        private Element root = null;
        private XMLEntityDescriptor provider = null;
        private URL errorURL = null;
        // tfreeman: renamed private var 'org', it conflicts with new package name
        private Organization organization = null;
        private ArrayList /* <ContactPerson> */ contacts = new ArrayList();
        private long validUntil = Long.MAX_VALUE;
        protected ArrayList /* <String> */ protocolEnum = new ArrayList();
        protected ArrayList /* <KeyDescriptor> */ keys = new ArrayList();

        public Role(XMLEntityDescriptor provider, long validUntil, Element e) throws MetadataException {
            root = e;
            this.validUntil = validUntil;
            this.provider = provider;

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (e != null && org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {

                if (e.hasAttributeNS(null,"validUntil")) {
                    SimpleDateFormat formatter = null;
                    String dateTime = XML.assign(e.getAttributeNS(null,"validUntil"));
                    int dot = dateTime.indexOf('.');
                    if (dot > 0)
                        formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    else
                        formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
                    try {
                        this.validUntil=Math.min(validUntil,formatter.parse(dateTime).getTime());
                    }
                    catch (ParseException e1) {
                        log.warn("Role descriptor contains invalid expiration time");
                    }
                }

                if (e.hasAttributeNS(null,"errorURL")) {
                    try {
                        errorURL=new URL(e.getAttributeNS(null,"errorURL"));
                    }
                    catch (MalformedURLException e1) {
                        log.error("Role descriptor contains malformed errorURL");
                    }
                }

                // Chop the protocol list into pieces...assume any whitespace can appear in between.
                protocolEnum.addAll(Arrays.asList(e.getAttributeNS(null,"protocolSupportEnumeration").split("\\s")));

                e = XML.getFirstChildElement(root,org.globus.opensaml11.md.common.XML.SAML2META_NS,"KeyDescriptor");
                while (e != null) {
                    keys.add(new XMLKeyDescriptor(e));
                    e = XML.getNextSiblingElement(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"KeyDescriptor");
                }

                e = XML.getFirstChildElement(root,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Organization");
                if (e != null)
                    organization=new XMLOrganization(e);

                e = XML.getFirstChildElement(root,org.globus.opensaml11.md.common.XML.SAML2META_NS,"ContactPerson");
                while (e != null) {
                    contacts.add(new XMLContactPerson(e));
                    e = XML.getNextSiblingElement(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"ContactPerson");
                }
            }
        }

        public EntityDescriptor getEntityDescriptor() {
            return provider;
        }

        public Iterator getProtocolSupportEnumeration() {
            return protocolEnum.iterator();
        }

        public boolean hasSupport(String version) {
            return protocolEnum.contains(version);
        }

        public boolean isValid() {
            return System.currentTimeMillis() < validUntil;
        }

        public URL getErrorURL() {
            return (errorURL != null) ? errorURL : provider.getErrorURL();
        }

        public Iterator getKeyDescriptors() {
            return keys.iterator();
        }

        public Organization getOrganization() {
            return (organization != null) ? organization : provider.getOrganization();
        }

        public Iterator getContactPersons() {
            return (contacts.isEmpty()) ? provider.getContactPersons() : contacts.iterator();
        }

        public Element getElement() {
            return root;
        }
    }

    class SSORole extends Role implements SSODescriptor {
        private XMLEndpointManager artifact = new XMLEndpointManager();
        private XMLEndpointManager logout = new XMLEndpointManager();
        private XMLEndpointManager nameid = new XMLEndpointManager();
        private ArrayList /* <String> */ formats = new ArrayList();

        public SSORole(XMLEntityDescriptor provider, long validUntil, Element e) throws MetadataException {
            super(provider, validUntil, e);

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {
                int i;
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"ArtifactResolutionService");
                for (i=0; i<nlist.getLength(); i++)
                    artifact.add(new XMLIndexedEndpoint((Element)nlist.item(i)));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"SingleLogoutService");
                for (i=0; i<nlist.getLength(); i++)
                    logout.add(new XMLEndpoint((Element)nlist.item(i)));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"ManageNameIDService");
                for (i=0; i<nlist.getLength(); i++)
                    nameid.add(new XMLEndpoint((Element)nlist.item(i)));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"NameIDFormat");
                for (i = 0; i < nlist.getLength(); i++) {
                    if (nlist.item(i).hasChildNodes()) {
                        Node tnode = nlist.item(i).getFirstChild();
                        if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
                            formats.add(tnode.getNodeValue());
                        }
                    }
                }
            }
            else {
                // For old style, we just do SAML 1.1 compatibility with Shib handles.
                protocolEnum.add(XML.SAML11_PROTOCOL_ENUM);
                formats.add(Constants.SHIB_NAMEID_FORMAT_URI);
            }
        }

        public EndpointManager getArtifactResolutionServiceManager() {
            return artifact;
        }

        public EndpointManager getSingleLogoutServiceManager() {
            return logout;
        }

        public EndpointManager getManageNameIDServiceManager() {
            return nameid;
        }

        public Iterator getNameIDFormats() {
            return formats.iterator();
        }
    }

    class IDPRole extends SSORole implements IDPSSODescriptor, ScopedRoleDescriptor {
        private ArrayList /* <Scope> */ scopes = new ArrayList();
        private XMLEndpointManager sso = new XMLEndpointManager();
        private XMLEndpointManager mapping = new XMLEndpointManager();
        private XMLEndpointManager idreq = new XMLEndpointManager();
        private ArrayList /* <String> */ attrprofs = new ArrayList();
        private ArrayList /* <SAMLAttribute> */ attrs = new ArrayList();
        private boolean wantAuthnRequestsSigned = false;
        private String sourceId = null;

        public IDPRole(XMLEntityDescriptor provider, long validUntil, Element e) throws SAMLException {
            super(provider, validUntil, e);
            NodeList domains=null;

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {
                String flag=XML.assign(e.getAttributeNS(null,"WantAuthnRequestsSigned"));
                wantAuthnRequestsSigned=(XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"));

                // Check for extensions.
                Element ext=XML.getFirstChildElement(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Extensions");
                if (ext != null) {
                    Element ext1=XML.getFirstChildElement(ext,XML.SAML_ARTIFACT_SOURCEID,"SourceID");
                    if (ext1 != null && ext1.hasChildNodes())
                        sourceId=ext1.getFirstChild().getNodeValue();
                    // Save off any domain elements for later.
                    domains = ext.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIBMETA_NS,"Scope");
                }

                int i;
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"SingleSignOnService");
                for (i=0; i<nlist.getLength(); i++)
                    sso.add(new XMLEndpoint((Element)(nlist.item(i))));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"NameIDMappingService");
                for (i=0; i<nlist.getLength(); i++)
                    mapping.add(new XMLEndpoint((Element)(nlist.item(i))));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"AssertionIDRequestService");
                for (i=0; i<nlist.getLength(); i++)
                    idreq.add(new XMLEndpoint((Element)(nlist.item(i))));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"AttributeProfile");
                for (i=0; i<nlist.getLength(); i++) {
                    if (nlist.item(i).hasChildNodes())
                        attrprofs.add(nlist.item(i).getFirstChild().getNodeValue());
                }

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2ASSERT_NS,"Attribute");
                for (i=0; i<nlist.getLength(); i++) {
                    // For now, we need to convert these to plain SAML 1.1 attributes.
                    Element src=(Element)(nlist.item(i));
                    Element copy=e.getOwnerDocument().createElementNS(XML.SAML_NS,"Attribute");
                    copy.setAttributeNS(null,"AttributeName",src.getAttributeNS(null,"Name"));
                    copy.setAttributeNS(null,"AttributeNamespace",src.getAttributeNS(null,"NameFormat"));
                    src=XML.getFirstChildElement(src,org.globus.opensaml11.md.common.XML.SAML2ASSERT_NS,"AttributeValue");
                    while (src != null) {
                        src=XML.getNextSiblingElement(src,org.globus.opensaml11.md.common.XML.SAML2ASSERT_NS,"AttributeValue");
                        Element val=e.getOwnerDocument().createElementNS(XML.SAML_NS,"AttributeValue");
                        NamedNodeMap attrs = src.getAttributes();
                        for (int j=0; j<attrs.getLength(); j++)
                            val.setAttributeNodeNS((Attr)(e.getOwnerDocument().importNode(attrs.item(j),true)));
                        while (src.hasChildNodes())
                            val.appendChild(src.getFirstChild());
                        copy.appendChild(val);
                    }
                    attrs.add(SAMLAttribute.getInstance(copy));
                }
            }
            else {
                protocolEnum.add(org.globus.opensaml11.md.common.XML.SHIB_NS);
                attrprofs.add(Constants.SHIB_ATTRIBUTE_NAMESPACE_URI);
                int i;
                domains = e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIB_NS,"Domain");
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIB_NS,"HandleService");
                for (i=0; i<nlist.getLength(); i++) {
                    // Manufacture an endpoint for the "Shib" binding.
                    sso.add(
                        new XMLEndpoint(Constants.SHIB_AUTHNREQUEST_PROFILE_URI,((Element)nlist.item(i)).getAttributeNS(null,"Location"))
                        );

                    // We're going to "mock up" a KeyDescriptor that contains the specified Name as a ds:KeyName.
                    Element kd=e.getOwnerDocument().createElementNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"KeyDescriptor");
                    Element ki=e.getOwnerDocument().createElementNS(XML.XMLSIG_NS,"KeyInfo");
                    Element kn=e.getOwnerDocument().createElementNS(XML.XMLSIG_NS,"KeyName");
                    kn.appendChild(
                        e.getOwnerDocument().createTextNode(((Element)nlist.item(i)).getAttributeNS(null,"Name"))
                        );
                    ki.appendChild(kn);
                    kd.appendChild(ki);
                    kd.setAttributeNS(null,"use","signing");
                    keys.add(new XMLKeyDescriptor(kd));
                }
            }

            if (domains != null) {
                for (int i=0; i < domains.getLength(); i++) {
                    String dom=(domains.item(i).hasChildNodes()) ? domains.item(i).getFirstChild().getNodeValue() : null;
                    if (dom != null) {
                        String regexp=XML.assign(((Element)domains.item(i)).getAttributeNS(null,"regexp"));
                        scopes.add(
                            new Scope(dom,(XML.safeCompare(regexp,"true") || XML.safeCompare(regexp,"1")))
                            );
                    }
                }
            }
        }

        public Iterator getScopes() {
            return scopes.iterator();
        }

        public boolean getWantAuthnRequestsSigned() {
            return wantAuthnRequestsSigned;
        }

        public EndpointManager getSingleSignOnServiceManager() {
            return sso;
        }

        public EndpointManager getNameIDMappingServiceManager() {
            return mapping;
        }

        public EndpointManager getAssertionIDRequestServiceManager() {
            return idreq;
        }

        public Iterator getAttributeProfiles() {
            return attrprofs.iterator();
        }

        public Iterator getAttributes() {
            return attrs.iterator();
        }
    }

    class AARole extends Role implements AttributeAuthorityDescriptor, ScopedRoleDescriptor {
        private ArrayList /* <Scope> */ scopes = new ArrayList();
        private XMLEndpointManager query = new XMLEndpointManager();
        private XMLEndpointManager idreq = new XMLEndpointManager();
        private ArrayList /* <String> */ attrprofs = new ArrayList();
        private ArrayList /* <String> */ formats = new ArrayList();
        private ArrayList /* <SAMLAttribute> */ attrs = new ArrayList();

        public AARole(XMLEntityDescriptor provider, long validUntil, Element e) throws SAMLException {
            super(provider, validUntil, e);
            NodeList domains=null;

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {

                // Check for extensions.
                Element ext=XML.getFirstChildElement(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Extensions");
                if (ext != null) {
                    // Save off any domain elements for later.
                    domains = ext.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIBMETA_NS,"Scope");
                }

                int i;
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"AttributeService");
                for (i=0; i<nlist.getLength(); i++)
                    query.add(new XMLEndpoint((Element)(nlist.item(i))));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"AssertionIDRequestService");
                for (i=0; i<nlist.getLength(); i++)
                    idreq.add(new XMLEndpoint((Element)(nlist.item(i))));

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"AttributeProfile");
                for (i=0; i<nlist.getLength(); i++) {
                    if (nlist.item(i).hasChildNodes())
                        attrprofs.add(nlist.item(i).getFirstChild().getNodeValue());
                }

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2ASSERT_NS,"Attribute");
                for (i=0; i<nlist.getLength(); i++) {
                    // For now, we need to convert these to plain SAML 1.1 attributes.
                    Element src=(Element)(nlist.item(i));
                    Element copy=e.getOwnerDocument().createElementNS(XML.SAML_NS,"Attribute");
                    copy.setAttributeNS(null,"AttributeName",src.getAttributeNS(null,"Name"));
                    copy.setAttributeNS(null,"AttributeNamespace",src.getAttributeNS(null,"NameFormat"));
                    src=XML.getFirstChildElement(src,org.globus.opensaml11.md.common.XML.SAML2ASSERT_NS,"AttributeValue");
                    while (src != null) {
                        Element val=e.getOwnerDocument().createElementNS(XML.SAML_NS,"AttributeValue");
                        NamedNodeMap attrs = src.getAttributes();
                        for (int j=0; j<attrs.getLength(); j++)
                            val.setAttributeNodeNS((Attr)(e.getOwnerDocument().importNode(attrs.item(j),true)));
                        while (src.hasChildNodes())
                            val.appendChild(src.getFirstChild());
                        copy.appendChild(val);

                        //tfreeman: moved this down here, cf. Sassa's mail to gridshib-beta
                        src=XML.getNextSiblingElement(src,org.globus.opensaml11.md.common.XML.SAML2ASSERT_NS,"AttributeValue");
                    }
                    attrs.add(SAMLAttribute.getInstance(copy));
                }
            }
            else {
                // For old style, we just do SAML 1.1 compatibility with Shib handles.
                protocolEnum.add(XML.SAML11_PROTOCOL_ENUM);
                formats.add(Constants.SHIB_NAMEID_FORMAT_URI);
                attrprofs.add(Constants.SHIB_ATTRIBUTE_NAMESPACE_URI);
                domains = e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIB_NS,"Domain");
                int i;
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIB_NS,"AttributeAuthority");
                for (i=0; i<nlist.getLength(); i++) {
                    // Manufacture an endpoint for the SOAP binding.
                    query.add(
                        new XMLEndpoint(
                            SAMLBinding.SOAP,
                            ((Element)nlist.item(i)).getAttributeNS(null,"Location")
                            )
                        );

                    // We're going to "mock up" a KeyDescriptor that contains the specified Name as a ds:KeyName.
                    Element kd=e.getOwnerDocument().createElementNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"KeyDescriptor");
                    Element ki=e.getOwnerDocument().createElementNS(XML.XMLSIG_NS,"KeyInfo");
                    Element kn=e.getOwnerDocument().createElementNS(XML.XMLSIG_NS,"KeyName");
                    kn.appendChild(
                        e.getOwnerDocument().createTextNode(((Element)nlist.item(i)).getAttributeNS(null,"Name"))
                        );
                    ki.appendChild(kn);
                    kd.appendChild(ki);
                    kd.setAttributeNS(null,"use","signing");
                    keys.add(new XMLKeyDescriptor(kd));
                }
            }

            if (domains != null) {
                for (int i=0; i < domains.getLength(); i++) {
                    String dom=(domains.item(i).hasChildNodes()) ? domains.item(i).getFirstChild().getNodeValue() : null;
                    if (dom != null) {
                        String regexp=XML.assign(((Element)domains.item(i)).getAttributeNS(null,"regexp"));
                        scopes.add(
                            new Scope(dom,(XML.safeCompare(regexp,"true") || XML.safeCompare(regexp,"1")))
                            );
                    }
                }
            }
        }

        public Iterator getScopes() {
            return scopes.iterator();
        }

        public EndpointManager getAttributeServiceManager() {
            return query;
        }

        public EndpointManager getAssertionIDRequestServiceManager() {
            return idreq;
        }

        public Iterator getAttributeProfiles() {
            return attrprofs.iterator();
        }

        public Iterator getAttributes() {
            return attrs.iterator();
        }

        public Iterator getNameIDFormats() {
            return formats.iterator();
        }
    }

    class SPRole extends SSORole implements SPSSODescriptor {
        private boolean authnRequestsSigned = false;
        private boolean wantAssertionsSigned = false;
        private XMLEndpointManager asc = new XMLEndpointManager();

        public SPRole(XMLEntityDescriptor provider, long validUntil, Element e) throws MetadataException {
            super(provider, validUntil, e);

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {
                String flag=XML.assign(e.getAttributeNS(null,"AuthnRequestsSigned"));
                authnRequestsSigned=(XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"));
                flag=XML.assign(e.getAttributeNS(null,"WantAssertionsSigned"));
                wantAssertionsSigned=(XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"));

                int i;
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"AssertionConsumerService");
                for (i=0; i<nlist.getLength(); i++)
                    asc.add(new XMLIndexedEndpoint((Element)(nlist.item(i))));

                /*
                nlist=e.getElementsByTagNameNS(edu.internet2.middleware.shibboleth.common.XML.SAML2ASSERT_NS,"Attribute");
                for (i=0; i<nlist.getLength(); i++) {
                    // For now, we need to convert these to plain SAML 1.1 attributes.
                    Element src=(Element)(nlist.item(i));
                    Element copy=e.getOwnerDocument().createElementNS(XML.SAML_NS,"Attribute");
                    copy.setAttributeNS(null,"AttributeName",src.getAttributeNS(null,"Name"));
                    copy.setAttributeNS(null,"AttributeNamespace",src.getAttributeNS(null,"NameFormat"));
                    src=XML.getFirstChildElement(src,edu.internet2.middleware.shibboleth.common.XML.SAML2ASSERT_NS,"AttributeValue");
                    while (src != null) {
                        src=XML.getNextSiblingElement(src,edu.internet2.middleware.shibboleth.common.XML.SAML2ASSERT_NS,"AttributeValue");
                        Element val=e.getOwnerDocument().createElementNS(XML.SAML_NS,"AttributeValue");
                        NamedNodeMap attrs = src.getAttributes();
                        for (int j=0; j<attrs.getLength(); j++)
                            val.setAttributeNodeNS((Attr)(e.getOwnerDocument().importNode(attrs.item(j),true)));
                        while (src.hasChildNodes())
                            val.appendChild(src.getFirstChild());
                        copy.appendChild(val);
                    }
                    attrs.add(SAMLAttribute.getInstance(copy));
                }
                */
            }
            else {
                int i;
                NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIB_NS,"AssertionConsumerServiceURL");
                for (i=0; i<nlist.getLength(); i++) {
                    // Manufacture an endpoint for the POST profile.
                    asc.add(
                        new XMLEndpoint(SAMLBrowserProfile.PROFILE_POST_URI,((Element)nlist.item(i)).getAttributeNS(null,"Location"))
                        );
                }

                nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SHIB_NS,"AttributeRequester");
                for (i=0; i<nlist.getLength(); i++) {
                    // We're going to "mock up" a KeyDescriptor that contains the specified Name as a ds:KeyName.
                    Element kd=e.getOwnerDocument().createElementNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"KeyDescriptor");
                    Element ki=e.getOwnerDocument().createElementNS(XML.XMLSIG_NS,"KeyInfo");
                    Element kn=e.getOwnerDocument().createElementNS(XML.XMLSIG_NS,"KeyName");
                    kn.appendChild(
                        e.getOwnerDocument().createTextNode(((Element)nlist.item(i)).getAttributeNS(null,"Name"))
                        );
                    ki.appendChild(kn);
                    kd.appendChild(ki);
                    kd.setAttributeNS(null,"use","signing");
                    keys.add(new XMLKeyDescriptor(kd));
                }
            }
        }

        public boolean getAuthnRequestsSigned() {
            return authnRequestsSigned;
        }

        public boolean getWantAssertionsSigned() {
            return wantAssertionsSigned;
        }

        public EndpointManager getAssertionConsumerServiceManager() {
            return asc;
        }

        public Iterator getAttributeConsumingServices() {
            // TODO Auto-generated method stub
            return null;
        }

        public AttributeConsumingService getDefaultAttributeConsumingService() {
            // TODO Auto-generated method stub
            return null;
        }

        public AttributeConsumingService getAttributeConsumingServiceByID(String id) {
            // TODO Auto-generated method stub
            return null;
        }
    }

    class AttributeRequesterRole extends Role implements AttributeRequesterDescriptor {
        private boolean wantAssertionsSigned = false;
        private ArrayList /* <String> */ formats = new ArrayList();

        public AttributeRequesterRole(XMLEntityDescriptor provider, long validUntil, Element e) throws MetadataException {
            super(provider, validUntil, e);

            String flag=XML.assign(e.getAttributeNS(null,"WantAssertionsSigned"));
            wantAssertionsSigned=(XML.safeCompare(flag,"1") || XML.safeCompare(flag,"true"));

            NodeList nlist=e.getElementsByTagNameNS(org.globus.opensaml11.md.common.XML.SAML2META_NS,"NameIDFormat");
            for (int i = 0; i < nlist.getLength(); i++) {
                if (nlist.item(i).hasChildNodes()) {
                    Node tnode = nlist.item(i).getFirstChild();
                    if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
                        formats.add(tnode.getNodeValue());
                    }
                }
            }
        }

        public boolean getWantAssertionsSigned() {
            return wantAssertionsSigned;
        }

        public Iterator getNameIDFormats() {
            return formats.iterator();
        }

        public Iterator getAttributeConsumingServices() {
            // TODO Auto-generated method stub
            return null;
        }

        public AttributeConsumingService getDefaultAttributeConsumingService() {
            // TODO Auto-generated method stub
            return null;
        }

        public AttributeConsumingService getAttributeConsumingServiceByID(String id) {
            // TODO Auto-generated method stub
            return null;
        }
    }

    class XMLEntityDescriptor implements ExtendedEntityDescriptor {
        private Element root = null;
        private EntitiesDescriptor parent = null;
        private String id = null;
        private URL errorURL = null;
        // tfreeman: renamed private var 'org', it conflicts with new package name
        private Organization organization = null;
        private ArrayList /* <ContactPerson> */ contacts = new ArrayList();
        private ArrayList /* <RoleDescriptor> */ roles = new ArrayList();
        private AffiliationDescriptor affiliation = null;
        private HashMap /* <String,String> */ locs = new HashMap();
        private long validUntil = Long.MAX_VALUE;
        private ArrayList /* <KeyAuthority> */ keyauths = new ArrayList();

        public XMLEntityDescriptor(Element e, XMLMetadataProvider wrapper, long validUntil, EntitiesDescriptor parent) throws SAMLException {
            root = e;
            this.parent = parent;
            this.validUntil = validUntil;

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {
                id=e.getAttributeNS(null,"entityID");

                if (e.hasAttributeNS(null,"validUntil")) {
                    SimpleDateFormat formatter = null;
                    String dateTime = XML.assign(e.getAttributeNS(null,"validUntil"));
                    int dot = dateTime.indexOf('.');
                    if (dot > 0)
                        formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    else
                        formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
                    try {
                        this.validUntil=Math.min(validUntil,formatter.parse(dateTime).getTime());
                    }
                    catch (ParseException e1) {
                        log.warn("Entity descriptor contains invalid expiration time");
                    }
                }

                Element child=XML.getFirstChildElement(e);
                while (child != null) {
                    // Process the various kinds of children that we care about...
                    if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Extensions")) {
                        Element ext = XML.getFirstChildElement(child,org.globus.opensaml11.md.common.XML.SHIBMETA_NS,"KeyAuthority");
                        while (ext != null) {
                            keyauths.add(new XMLKeyAuthority(ext));
                            ext = XML.getNextSiblingElement(ext,org.globus.opensaml11.md.common.XML.SHIBMETA_NS,"KeyAuthority");
                        }
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"ContactPerson")) {
                        contacts.add(new XMLContactPerson(child));
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Organization")) {
                        organization=new XMLOrganization(child);
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"AdditionalMetadataLocation")) {
                        Node loc=child.getFirstChild();
                        if (loc != null)
                            locs.put(child.getAttributeNS(null,"namespace"),loc.getNodeValue());
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"IDPSSODescriptor")) {
                        roles.add(new IDPRole(this,validUntil,child));
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"AttributeAuthorityDescriptor")) {
                        roles.add(new AARole(this,validUntil,child));
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"SPSSODescriptor")) {
                        roles.add(new SPRole(this,validUntil,child));
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SAML2META_NS,"RoleDescriptor")) {
                        QName xsitype = XML.getQNameAttribute(child,XML.XSI_NS,"type");
                        if (org.globus.opensaml11.md.common.XML.SAML2METAEXT_NS.equals(xsitype.getNamespaceURI()) &&
                                "AttributeRequesterDescriptorType".equals(xsitype.getLocalPart()))
                            roles.add(new AttributeRequesterRole(this,validUntil,child));
                    }
                    child = XML.getNextSiblingElement(child);
                }
            }
            else {
                id=e.getAttributeNS(null,"Name");
                if (e.hasAttributeNS(null,"ErrorURL")) {
                    try {
                        errorURL=new URL(e.getAttributeNS(null,"ErrorURL"));
                    }
                    catch (MalformedURLException e1) {
                        log.error("Site descriptor contains invalid ErrorURL");
                    }
                }

                boolean idp=false,aa=false,sp=false;    // only want to build a role once
                Element child=XML.getFirstChildElement(e);
                while (child != null) {
                    // Process the various kinds of OriginSite children that we care about...
                    if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SHIB_NS,"Contact")) {
                        contacts.add(new XMLContactPerson(child));
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SHIB_NS,"HandleService") && !idp) {
                        // Create the IDP role if needed.
                        roles.add(new IDPRole(this, validUntil, e));
                        idp=true;
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SHIB_NS,"AttributeAuthority") && !aa) {
                        // Create the AA role if needed.
                        roles.add(new AARole(this, validUntil, e));
                        aa=true;
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SHIB_NS,"AssertionConsumerServiceURL") && !sp) {
                        // Create the SP role if needed.
                        roles.add(new SPRole(this, validUntil, e));
                        sp=true;
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SHIB_NS,"AttributeRequester") && !sp) {
                        // Create the SP role if needed.
                        roles.add(new SPRole(this, validUntil, e));
                        sp=true;
                    }
                    else if (XML.isElementNamed(child,org.globus.opensaml11.md.common.XML.SHIB_NS,"Alias") && (organization == null)) {
                        // Create the Organization.
                        organization = new XMLOrganization(child);
                    }
                    child = XML.getNextSiblingElement(child);
                }
            }

            // Each map entry is a list of the descriptors with this ID.
            ArrayList list;
            if (wrapper.sites.containsKey(id)) {
                list = (ArrayList)wrapper.sites.get(id);
            }
            else {
                list = new ArrayList();
                wrapper.sites.put(id,list);
            }
            list.add(this);

            // Look for an IdP role, and register the artifact source ID and endpoints.
            IDPRole idp=null;
            for (int i=0; i<roles.size(); i++) {
                if (roles.get(i) instanceof IDPRole) {
                    idp = (IDPRole)roles.get(i);
                    if (idp.sourceId != null) {
                        if (wrapper.sources.containsKey(idp.sourceId)) {
                            list = (ArrayList)wrapper.sources.get(idp.sourceId);
                        }
                        else {
                            list = new ArrayList();
                            wrapper.sources.put(idp.sourceId,list);
                        }
                        list.add(this);
                    }
                    else {
                        String sourceId;
                        try {
                            sourceId = new String(Hex.encode(Util.generateSourceId(id)));
                        }
                        catch (NoSuchAlgorithmException e1) {
                            log.error("caught exception while encoding sourceId: " + e1.getMessage());
                            continue;
                        }
                        if (wrapper.sources.containsKey(sourceId)) {
                            list = (ArrayList)wrapper.sources.get(sourceId);
                        }
                        else {
                            list = new ArrayList();
                            wrapper.sources.put(sourceId,list);
                        }
                        list.add(this);
                    }
                    Iterator locs=idp.getArtifactResolutionServiceManager().getEndpoints();
                    while (locs.hasNext()) {
                        String loc=((Endpoint)locs.next()).getLocation();
                        if (wrapper.sources.containsKey(loc)) {
                            list = (ArrayList)wrapper.sources.get(loc);
                        }
                        else {
                            list = new ArrayList();
                            wrapper.sources.put(loc,list);
                        }
                        list.add(this);
                    }
                }
            }
        }

        public String getId() {
            return id;
        }

        public boolean isValid() {
            return System.currentTimeMillis() < validUntil;
        }

        public Iterator getRoleDescriptors() {
            return roles.iterator();
        }

        public RoleDescriptor getRoleByType(Class type, String protocol) {
            for (int i=0; i<roles.size(); i++) {
                RoleDescriptor role = (RoleDescriptor)roles.get(i);
                if (type.isInstance(role) && role.hasSupport(protocol))
                    return role;
            }
            return null;
        }

        public IDPSSODescriptor getIDPSSODescriptor(String protocol) {
            return (IDPSSODescriptor)getRoleByType(IDPSSODescriptor.class, protocol);
        }

        public SPSSODescriptor getSPSSODescriptor(String protocol) {
            return (SPSSODescriptor)getRoleByType(SPSSODescriptor.class, protocol);
        }

        public AuthnAuthorityDescriptor getAuthnAuthorityDescriptor(String protocol) {
            return (AuthnAuthorityDescriptor)getRoleByType(AuthnAuthorityDescriptor.class, protocol);
        }

        public AttributeAuthorityDescriptor getAttributeAuthorityDescriptor(String protocol) {
            return (AttributeAuthorityDescriptor)getRoleByType(AttributeAuthorityDescriptor.class, protocol);
        }

        public AttributeRequesterDescriptor getAttributeRequesterDescriptor(String protocol) {
            return (AttributeRequesterDescriptor)getRoleByType(AttributeRequesterDescriptor.class, protocol);
        }

        public PDPDescriptor getPDPDescriptor(String protocol) {
            return (PDPDescriptor)getRoleByType(PDPDescriptor.class, protocol);
        }

        public AffiliationDescriptor getAffiliationDescriptor() {
            return affiliation;
        }

        public Organization getOrganization() {
            return organization;
        }

        public Iterator getContactPersons() {
            return contacts.iterator();
        }

        public Map getAdditionalMetadataLocations() {
            return Collections.unmodifiableMap(locs);
        }

        public EntitiesDescriptor getEntitiesDescriptor() {
            return parent;
        }

        public Element getElement() {
            return root;
        }

        public long getValidUntil() {
            return validUntil;
        }

        public URL getErrorURL() {
            return errorURL;
        }

        public Iterator getKeyAuthorities() {
            return keyauths.iterator();
        }
    }

    class XMLEntitiesDescriptor implements ExtendedEntitiesDescriptor {
        private Element root = null;
        private EntitiesDescriptor parent = null;
        private String name = null;
        private ArrayList /* <EntitiesDescriptor> */ groups = new ArrayList();
        private ArrayList /* <EntityDescriptor> */ providers = new ArrayList();
        private long validUntil = Long.MAX_VALUE;
        private ArrayList /* <KeyAuthority> */ keyauths = new ArrayList();

        public XMLEntitiesDescriptor(Element e, XMLMetadataProvider wrapper, long validUntil, EntitiesDescriptor parent) throws SAMLException {
            root = e;
            this.parent = parent;
            this.validUntil = validUntil;
            name = XML.assign(e.getAttributeNS(null, "Name"));

            // Check the root element namespace. If SAML2, assume it's the std schema.
            if (org.globus.opensaml11.md.common.XML.SAML2META_NS.equals(e.getNamespaceURI())) {

                if (e.hasAttributeNS(null,"validUntil")) {
                    SimpleDateFormat formatter = null;
                    String dateTime = XML.assign(e.getAttributeNS(null,"validUntil"));
                    int dot = dateTime.indexOf('.');
                    if (dot > 0)
                        formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                    else
                        formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
                    try {
                        this.validUntil=Math.min(validUntil,formatter.parse(dateTime).getTime());
                    }
                    catch (ParseException e1) {
                        log.warn("Entities descriptor contains invalid expiration time");
                    }
                }

                e = XML.getFirstChildElement(e);
                while (e != null) {
                    if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"Extensions")) {
                        Element ext = XML.getFirstChildElement(e,org.globus.opensaml11.md.common.XML.SHIBMETA_NS,"KeyAuthority");
                        while (ext != null) {
                            keyauths.add(new XMLKeyAuthority(ext));
                            ext = XML.getNextSiblingElement(ext,org.globus.opensaml11.md.common.XML.SHIBMETA_NS,"KeyAuthority");
                        }
                    }
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"EntitiesDescriptor"))
                        groups.add(new XMLEntitiesDescriptor(e, wrapper, this.validUntil, this));
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SAML2META_NS,"EntityDescriptor"))
                        providers.add(new XMLEntityDescriptor(e, wrapper, this.validUntil, this));
                    e = XML.getNextSiblingElement(e);
                }
            }
            else {
                e = XML.getFirstChildElement(e);
                while (e != null) {
                    if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SHIB_NS,"SiteGroup"))
                        groups.add(new XMLEntitiesDescriptor(e, wrapper, this.validUntil, this));
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SHIB_NS,"OriginSite"))
                        providers.add(new XMLEntityDescriptor(e, wrapper, this.validUntil, this));
                    else if (XML.isElementNamed(e,org.globus.opensaml11.md.common.XML.SHIB_NS,"DestinationSite"))
                        providers.add(new XMLEntityDescriptor(e, wrapper, this.validUntil, this));
                    e = XML.getNextSiblingElement(e);
                }
            }
        }

        public String getName() {
            return name;
        }

        public boolean isValid() {
            return System.currentTimeMillis() < validUntil;
        }

        public EntitiesDescriptor getEntitiesDescriptor() {
            return parent;
        }

        public Iterator getEntitiesDescriptors() {
            return groups.iterator();
        }

        public Iterator getEntityDescriptors() {
            return providers.iterator();
        }

        public Element getElement() {
            return root;
        }

        public Iterator getKeyAuthorities() {
            return keyauths.iterator();
        }
    }
}
