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

import org.globus.opensaml11.md.common.IdentityProvider;
import org.globus.opensaml11.md.common.InvalidNameIdentifierException;
import org.globus.opensaml11.md.common.LocalPrincipal;
import org.globus.opensaml11.md.common.NameIdentifierMapping;
import org.globus.opensaml11.md.common.NameIdentifierMappingException;
import org.globus.opensaml11.md.common.ServiceProvider;
import org.apache.log4j.Logger;
import org.globus.opensaml11.saml.SAMLException;
import org.globus.opensaml11.saml.SAMLNameIdentifier;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.security.Principal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * <code>NameIdentifierMapping</code> implementation that translates principal names to E-Auth compliant
 * X509SubjectNames.
 * 
 * @author Walter Hoehn
 */
public class X509SubjectNameNameIdentifierMapping extends BaseNameIdentifierMapping implements NameIdentifierMapping {

	private static Logger log = Logger.getLogger(X509SubjectNameNameIdentifierMapping.class.getName());
	private String regexTemplate = ".*uid=([^,/]+).*";
	private Pattern regex;
	private String qualifier;
	private String internalNameContext;
	private QName[] errorCodes = new QName[0];

	public X509SubjectNameNameIdentifierMapping(Element config) throws NameIdentifierMappingException {

		super(config);

		String rawRegex = ((Element) config).getAttribute("regex");
		if (rawRegex != null && !rawRegex.equals("")) {
			try {
				regex = Pattern.compile(rawRegex);
			} catch (PatternSyntaxException e) {
				log.error("Supplied (regex) attribute is not a valid regular expressions.  Using default value.");
				regex = Pattern.compile(regexTemplate);
			}
		} else {
			regex = Pattern.compile(regexTemplate);
		}

		qualifier = ((Element) config).getAttribute("qualifier");
		if (qualifier == null || qualifier.equals("")) {
			log.error("The X509SubjectName NameMapping requires a (qualifier) attribute.");
			throw new NameIdentifierMappingException(
					"Invalid configuration.  Unable to initialize X509SubjectName Mapping.");
		}

		internalNameContext = ((Element) config).getAttribute("internalNameContext");
		if (internalNameContext == null || internalNameContext.equals("")) {
			log.error("The X509SubjectName NameMapping requires a (internalNameContext) attribute.");
			throw new NameIdentifierMappingException(
					"Invalid configuration.  Unable to initialize X509SubjectName Mapping.");
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

		if (!nameId.getNameQualifier().equals(qualifier)) {
			log.error("The name qualifier (" + nameId.getNameQualifier()
					+ ") for the referenced subject is not valid for this identity provider.");
			throw new NameIdentifierMappingException("The name qualifier (" + nameId.getNameQualifier()
					+ ") for the referenced subject is not valid for this identity provider.");
		}

		Matcher matcher = regex.matcher(nameId.getName());
		matcher.find();
		String principal = matcher.group(1);
		if (principal == null) { throw new InvalidNameIdentifierException("Unable to map X509SubjectName ("
				+ nameId.getName() + ") to a local principal.", errorCodes); }
		return new LocalPrincipal(principal);
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

		try {
			SAMLNameIdentifier nameid = SAMLNameIdentifier.getInstance(getNameIdentifierFormat().toString());
			nameid.setName(internalNameContext.replaceAll("%PRINCIPAL%", principal.getName()));
			nameid.setNameQualifier(qualifier);
			return nameid;
		} catch (SAMLException e) {
			throw new NameIdentifierMappingException("Unable to generate X509 SubjectName: " + e);
		}

	}

}