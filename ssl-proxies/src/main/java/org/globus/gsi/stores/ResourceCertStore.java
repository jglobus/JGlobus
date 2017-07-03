/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.gsi.stores;

import org.apache.commons.logging.LogFactory;

import org.apache.commons.logging.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Vector;


/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Dec 29, 2009 Time:
 * 12:57:23 PM To change this template use File | Settings | File Templates.
 */
public class ResourceCertStore extends CertStoreSpi {

	private static Log logger = LogFactory.getLog(ResourceCertStore.class.getCanonicalName());
	private ResourceCACertStore caDelegate = new ResourceCACertStore();
	private ResourceCRLStore crlDelegate = new ResourceCRLStore();

	/**
	 * The sole constructor.
	 *
	 * @param params
	 *            the initialization parameters (may be <code>null</code>)
	 * @throws java.security.InvalidAlgorithmParameterException
	 *             if the initialization parameters are inappropriate for this
	 *             <code>CertStoreSpi</code>
	 * @throws ResourceStoreException
	 *             If error loading certs and crls.
	 */
	public ResourceCertStore(CertStoreParameters params)
			throws InvalidAlgorithmParameterException, ResourceStoreException {
		super(params);
		if (params == null) {
			throw new InvalidAlgorithmParameterException();
		}

		if (params instanceof ResourceCertStoreParameters) {
			ResourceCertStoreParameters storeParams = (ResourceCertStoreParameters) params;
			crlDelegate.loadWrappers(storeParams.getCrlLocationPattern());
			caDelegate.loadWrappers(storeParams.getCertLocationPattern());
		} else {
			throw new InvalidAlgorithmParameterException();
		}
	}

	/**
	 * Returns a <code>Collection</code> of <code>Certificate</code>s that match
	 * the specified selector. If no <code>Certificate</code>s match the
	 * selector, an empty <code>Collection</code> will be returned.
	 * <p>
	 * For some <code>CertStore</code> types, the resulting
	 * <code>Collection</code> may not contain <b>all</b> of the
	 * <code>Certificate</code>s that match the selector. For instance, an LDAP
	 * <code>CertStore</code> may not search all entries in the directory.
	 * Instead, it may just search entries that are likely to contain the
	 * <code>Certificate</code>s it is looking for.
	 * <p>
	 * Some <code>CertStore</code> implementations (especially LDAP
	 * <code>CertStore</code>s) may throw a <code>CertStoreException</code>
	 * unless a non-null <code>CertSelector</code> is provided that includes
	 * specific criteria that can be used to find the certificates. Issuer
	 * and/or subject names are especially useful criteria.
	 *
	 * @param selector
	 *            A <code>CertSelector</code> used to select which
	 *            <code>Certificate</code>s should be returned. Specify
	 *            <code>null</code> to return all <code>Certificate</code>s (if
	 *            supported).
	 * @return A <code>Collection</code> of <code>Certificate</code>s that match
	 *         the specified selector (never <code>null</code>)
	 * @throws java.security.cert.CertStoreException
	 *             if an exception occurs
	 */
	public Collection<? extends Certificate> engineGetCertificates(
			CertSelector selector) throws CertStoreException {
		logger.debug("selecting Certificates");
		if (selector != null && !(selector instanceof X509CertSelector)) {
			throw new IllegalArgumentException();
		}

		if (caDelegate.getCollection() == null) {
			return null;
		}
		// Given that we always only use subject, how can we improve performance
		// here. Custom
		Vector<X509Certificate> certSet = new Vector<X509Certificate>();
		if (selector == null) {
			for (TrustAnchor trustAnchor : caDelegate.getCollection()) {
				certSet.add(trustAnchor.getTrustedCert());
			}

		} else {
			for (TrustAnchor trustAnchor : caDelegate.getCollection()) {
				X509Certificate cert = trustAnchor.getTrustedCert();
				if (selector.match(cert)) {
					certSet.add(cert);
				}
			}
		}

		return certSet;
	}

	/**
	 * Returns a <code>Collection</code> of <code>CRL</code>s that match the
	 * specified selector. If no <code>CRL</code>s match the selector, an empty
	 * <code>Collection</code> will be returned.
	 * <p>
	 * For some <code>CertStore</code> types, the resulting
	 * <code>Collection</code> may not contain <b>all</b> of the
	 * <code>CRL</code>s that match the selector. For instance, an LDAP
	 * <code>CertStore</code> may not search all entries in the directory.
	 * Instead, it may just search entries that are likely to contain the
	 * <code>CRL</code>s it is looking for.
	 * <p>
	 * Some <code>CertStore</code> implementations (especially LDAP
	 * <code>CertStore</code>s) may throw a <code>CertStoreException</code>
	 * unless a non-null <code>CRLSelector</code> is provided that includes
	 * specific criteria that can be used to find the CRLs. Issuer names and/or
	 * the certificate to be checked are especially useful.
	 *
	 * @param selector
	 *            A <code>CRLSelector</code> used to select which
	 *            <code>CRL</code>s should be returned. Specify
	 *            <code>null</code> to return all <code>CRL</code>s (if
	 *            supported).
	 * @return A <code>Collection</code> of <code>CRL</code>s that match the
	 *         specified selector (never <code>null</code>)
	 * @throws java.security.cert.CertStoreException
	 *             if an exception occurs
	 */
	public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
			throws CertStoreException {

		if (selector != null && !(selector instanceof X509CRLSelector)) {
			throw new IllegalArgumentException();
		}

		if (crlDelegate.getCollection() == null) {
			return new Vector<X509CRL>();
		}

		// Given that we always only use subject, how can we improve performance
		// here. Custom

		if (selector == null) {
			return crlDelegate.getCollection();
		} else {
			Vector<X509CRL> certSet = new Vector<X509CRL>();
			for (X509CRL crl : crlDelegate.getCollection()) {
				if (selector.match(crl)) {
					certSet.add(crl);
				}
			}
			return certSet;
		}
	}
}
