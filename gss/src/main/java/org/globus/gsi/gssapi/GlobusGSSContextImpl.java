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
package org.globus.gsi.gssapi;

import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.ProxyCertificateUtil;


import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.ChannelBinding;

import org.gridforum.jgss.ExtendedGSSContext;
import org.gridforum.jgss.ExtendedGSSCredential;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Date;
import java.util.Calendar;
import java.util.Map;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

import org.globus.gsi.ProviderLoader;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.KeyStoreParametersFactory;

import org.globus.gsi.stores.ResourceCertStoreParameters;
import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.ResourceSigningPolicyStoreParameters;

import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.KeyStore;

import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509Credential;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.bc.BouncyCastleUtil;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.proxy.ProxyPolicyHandler;
import org.globus.util.I18n;
import org.globus.common.CoGProperties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.globus.gsi.jsse.SSLConfigurator;

import org.bouncycastle.jce.provider.X509CertificateObject;
import java.security.NoSuchAlgorithmException;

/*
import COM.claymoresystems.ptls.SSLConn;
import COM.claymoresystems.ptls.SSLRecord;
import COM.claymoresystems.ptls.SSLDebug;
import COM.claymoresystems.ptls.SSLCipherSuite;
import COM.claymoresystems.ptls.SSLCipherState;
import COM.claymoresystems.ptls.SSLHandshake;
import COM.claymoresystems.sslg.SSLPolicyInt;
import COM.claymoresystems.sslg.CertVerifyPolicyInt;
import COM.claymoresystems.cert.X509Cert;
import COM.claymoresystems.util.Util;
*/

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Implementation of SSL/GSI mechanism for Java GSS-API. The implementation
 * is based on JSSE (for SSL API) and the 
 * <a href="http://www.bouncycastle.org/">BouncyCastle library</a> 
 * (for certificate processing API).
 * <BR>
 * The implementation is not designed to be thread-safe.
 */
public class GlobusGSSContextImpl implements ExtendedGSSContext {
    
    private static Log logger = 
        LogFactory.getLog(GlobusGSSContextImpl.class.getName());

    private static I18n i18n =
            I18n.getI18n("org.globus.gsi.gssapi.errors",
                         GlobusGSSContextImpl.class.getClassLoader());

    static {
        new ProviderLoader();
    }

/*DEL
    private static Log sslLog = 
        LogFactory.getLog(SSLDebug.class.getName());
*/


    /**
     * KeyPair generation with cache of keypairs if configured

     */

    private KeyPairCache keyPairCache = KeyPairCache.getKeyPairCache();

    
    /** Used to distinguish between a token created by 
     * <code>wrap</code> with {@link GSSConstants#GSI_BIG
     * GSSConstants.GSI_BIG}
     * QoP and a regular token created by <code>wrap</code>. */
    public static final int GSI_WRAP = 26; /** SSL3_RT_GSSAPI_OPENSSL */

    private static final int GSI_SEQUENCE_SIZE = 8;
    
    private static final int GSI_MESSAGE_DIGEST_PADDING = 12;

    private static final String [] ENABLED_PROTOCOLS = {"TLSv1", "SSLv3"};
    // TODO: Delete this once GRAM server is fixed and we no longer
    //       would be talking to old GRAM servers.
    private static final String [] GRAM_PROTOCOLS = {"SSLv3"};

/*DEL
    private static final short [] NO_ENCRYPTION = {SSLPolicyInt.TLS_RSA_WITH_NULL_MD5};
*/
    private static final String [] NO_ENCRYPTION =
                    {"SSL_RSA_WITH_NULL_SHA", "SSL_RSA_WITH_NULL_MD5"};

    // TODO: Delete these once GRAM server is fixed and we no longer
    //       would be talking to old GRAM servers.
    private static final String [] GRAM_ENCRYPTION_CIPHER_SUITES =
		{"SSL_RSA_WITH_3DES_EDE_CBC_SHA"};
    private static final String [] GRAM_NO_ENCRYPTION_CIPHER_SUITES =
		{"SSL_RSA_WITH_NULL_SHA"};
    
    private static final byte[] DELEGATION_TOKEN = new byte[] {GSIConstants.DELEGATION_CHAR};
    
    private static final int 
        UNDEFINED = 0,
        INITIATE = 1,
        ACCEPT = 2;

    /** Handshake state */
    protected int state = HANDSHAKE; 

    /* handshake states */
    private static final int
        HANDSHAKE = 0,
        CLIENT_START_DEL = 2,
        CLIENT_END_DEL = 3,
        SERVER_START_DEL = 4,
        SERVER_END_DEL = 5;

    /** Delegation state */
    protected int delegationState = DELEGATION_START;

    /* delegation states */
    private static final int
        DELEGATION_START = 0,
        DELEGATION_SIGN_CERT = 1,
        DELEGATION_COMPLETE_CRED = 2;

    /** Credential delegated using delegation API */
    protected ExtendedGSSCredential delegatedCred;

    /** Delegation finished indicator */
    protected boolean delegationFinished = false;

    // gss context state variables
    protected boolean credentialDelegation = false;
    protected boolean anonymity = false;
    protected boolean encryption = true;
    protected boolean established = false;

    /** The name of the context initiator */
    protected GSSName sourceName = null;

    /** The name of the context acceptor */
    protected GSSName targetName = null;

    /** Context role */
    protected int role = UNDEFINED;

    /** Credential delegated during context establishment */
    protected ExtendedGSSCredential delegCred;

    // these can be set via setOption
/*DEL
    protected Integer delegationType = GSIConstants.DELEGATION_TYPE_LIMITED;
*/
    protected GSIConstants.DelegationType delegationType =
                                      GSIConstants.DelegationType.LIMITED;
    protected Integer gssMode = GSIConstants.MODE_GSI;
    protected Boolean checkContextExpiration = Boolean.FALSE;
    protected Boolean rejectLimitedProxy = Boolean.FALSE;
    protected Boolean requireClientAuth = Boolean.TRUE;
    protected Boolean acceptNoClientCerts = Boolean.FALSE;
    protected Boolean requireAuthzWithDelegation = Boolean.TRUE;
    protected Boolean forceSSLv3AndConstrainCipherSuitesForGram =
                                      Boolean.FALSE;

    // *** implementation-specific variables ***
    
    /** Credential of this context. Might be anonymous */
    protected GlobusGSSCredentialImpl ctxCred;
    
    /** Expected target name. Used for authorization in initiator */
    protected GSSName expectedTargetName = null;

    /** Context expiration date. */
    protected Date goodUntil = null;

    protected SSLConfigurator sslConfigurator = null;
    protected SSLContext sslContext = null;
    protected SSLEngine sslEngine = null;
    
/*DEL
    protected SSLConn conn;
*/
    protected boolean conn = false;
/*DEL
    protected PureTLSContext context;
    protected SSLPolicyInt policy;
    protected TokenInputStream in;
    protected ByteArrayOutputStream out;
*/
    private byte[] savedInBytes = null;
    private ByteBuffer outByteBuff = null;
    protected BouncyCastleCertProcessingFactory certFactory;

    /** Used during delegation */
    protected KeyPair keyPair;

    /* Needed to verifing certs */
/*DEL
    protected TrustedCertificates tc;
*/
    
    protected Map proxyPolicyHandlers;

    /** Limited peer credentials */
    protected Boolean peerLimited = null;
    
    private static KeyStore ms_trustStore = null;
    private static CertStore ms_crlStore = null;
    private static ResourceSigningPolicyStore ms_sigPolStore = null;
    

    /**
     * @param target expected target name. Can be null.
     * @param cred credential. Cannot be null. Might be anonymous.
     */
    public GlobusGSSContextImpl(GSSName target,
                                GlobusGSSCredentialImpl cred)
        throws GSSException {

        if (cred == null) {
            throw new GSSException(GSSException.NO_CRED);
        }

        this.expectedTargetName = target;
        this.ctxCred = cred;
        
/*DEL
        this.context = new PureTLSContext();
*/
	try {

            this.sslConfigurator = new SSLConfigurator();

	    // set trust parameters in SSLConfigurator

    	    String caCertsLocation = "file:" + CoGProperties.getDefault().getCaCertLocations();

            KeyStore trustStore = GlobusGSSContextImpl.getTrustStore(caCertsLocation);
            sslConfigurator.setTrustAnchorStore(trustStore);

            CertStore crlStore = GlobusGSSContextImpl.getCRLStore(caCertsLocation); 
            sslConfigurator.setCrlStore(crlStore);

            ResourceSigningPolicyStore sigPolStore = GlobusGSSContextImpl.getSigPolStore(caCertsLocation);
            sslConfigurator.setPolicyStore(sigPolStore);

            // Need to set this so we are able to communicate properly with
            // GT4.0.8 servers that use only SSLv3 (no TLSv1). Thanks to
            // Jon Siwek for pointing this and the following link out:
            // http://java.sun.com/j2se/1.4.2/relnotes.html#security
            if (System.getProperty("com.sun.net.ssl.rsaPreMasterSecretFix") == null)
               System.setProperty("com.sun.net.ssl.rsaPreMasterSecretFix", "true");

            // WARNING WARNING:
            // The new jglobus2-based srm-client is not compatible with old bestman2
            // servers UNLESS we change this setting.
            //
            // The protection we are turning off helps against the BEAST attack.
            // When enabled, it will insert empty TLS application records into the
            // stream.  However, the old server will deadlock on the extra records.
            //
            // To our knowledge, the BEAST attack is not applicable to this client as
            // we don't have any concurrent insecure connections.  Regardless, we ought
            // to remove this as soon as we can drop support for the old servers.
            //
            // -BB.  Sept 24, 2012.
            //
            System.setProperty("jsse.enableCBCProtection", "false");

	} catch  (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
	}

/*DEL
        CertVerifyPolicyInt certPolicy = PureTLSUtil.getDefaultCertVerifyPolicy();
        
        this.policy = new SSLPolicyInt();
        this.policy.negotiateTLS(false);
        this.policy.waitOnClose(false);
        this.policy.setCertVerifyPolicy(certPolicy);
        this.context.setPolicy(policy);

	// TODO
        setSSLDebugging();
*/
    }

/*DEL
    private void setSSLDebugging() {
        if (sslLog.isTraceEnabled()) {
            SSLDebug.setDebug( 0xffff );
        } else if (sslLog.isDebugEnabled()) {
            SSLDebug.setDebug( SSLDebug.DEBUG_CERT );
        }
    }
*/

    private static KeyStore getTrustStore(String caCertsLocation) throws  GeneralSecurityException, IOException
    {
        if(GlobusGSSContextImpl.ms_trustStore != null)
            return GlobusGSSContextImpl.ms_trustStore;
        
        String caCertsPattern = caCertsLocation + "/*.0";
        KeyStore keyStore = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE, GlobusProvider.PROVIDER_NAME);
        keyStore.load(KeyStoreParametersFactory.createTrustStoreParameters(caCertsPattern));
        
        GlobusGSSContextImpl.ms_trustStore = keyStore;
        
        return keyStore;
    }
    
    private static CertStore getCRLStore(String caCertsLocation) throws GeneralSecurityException, NoSuchAlgorithmException
    {
        if(GlobusGSSContextImpl.ms_crlStore != null)
            return GlobusGSSContextImpl.ms_crlStore;
        
        String crlPattern = caCertsLocation + "/*.r*";
        CertStore crlStore = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, new ResourceCertStoreParameters(null,crlPattern));
        
        GlobusGSSContextImpl.ms_crlStore = crlStore ;
        
        return crlStore;
    }
    
    private static ResourceSigningPolicyStore getSigPolStore(String caCertsLocation) throws GeneralSecurityException
    {
        if(GlobusGSSContextImpl.ms_sigPolStore != null)
            return GlobusGSSContextImpl.ms_sigPolStore;
        
        String sigPolPattern = caCertsLocation + "/*.signing_policy";
        ResourceSigningPolicyStore sigPolStore = new ResourceSigningPolicyStore(new ResourceSigningPolicyStoreParameters(sigPolPattern));
        
        GlobusGSSContextImpl.ms_sigPolStore = sigPolStore;
        
        return sigPolStore;
    }
    /*
     * If the result indicates that we have outstanding tasks to do,
     * go ahead and run them in this thread.
     */
    private void runDelegatedTasks(SSLEngine engine) throws Exception {

            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                logger.debug("\trunning delegated task...");
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus =
                    engine.getHandshakeStatus();
            if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
            logger.debug("\tnew HandshakeStatus: " + hsStatus);
    }

    private X509Certificate bcConvert(X509Certificate cert)
            throws GSSException {
        if (!(cert instanceof X509CertificateObject)) {
            try {
                return CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(cert.getEncoded()));
            } catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }
        } else {
                return cert;
        }
    }


    /**
     * This function drives the accepting side of the context establishment
     * process. It is expected to be called in tandem with the
     * {@link #initSecContext(byte[], int, int) initSecContext} function.
     * <BR>
     * The behavior of context establishment process can be modified by 
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE}
     * and {@link GSSConstants#REJECT_LIMITED_PROXY 
     * GSSConstants.REJECT_LIMITED_PROXY} context options. If the
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE} 
     * option is set to 
     * {@link GSIConstants#MODE_SSL GSIConstants.MODE_SSL}
     * the context establishment process will be compatible with regular SSL
     * (no credential delegation support). If the option is set to
     * {@link GSIConstants#MODE_GSI GSIConstants.MODE_GSI}
     * credential delegation during context establishment process will be accepted.
     * If the {@link GSSConstants#REJECT_LIMITED_PROXY
     * GSSConstants.REJECT_LIMITED_PROXY} option is enabled, a peer
     * presenting limited proxy credential will be automatically 
     * rejected and the context establishment process will be aborted.
     * 
     * @return a byte[] containing the token to be sent to the peer.
     *         null indicates that no token is generated (needs more data)
     */
    public byte[] acceptSecContext(byte[] inBuff, int off, int len) 
        throws GSSException {
        logger.debug("enter acceptSecContext");

        if (!this.conn) {
            this.role = ACCEPT;
            
	    logger.debug("enter initializing in acceptSecContext");

            if (this.ctxCred.getName().isAnonymous()) {
                throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL,
                                             GlobusGSSException.UNKNOWN,
                                             "acceptCtx00");
            }

            if (this.ctxCred.getUsage() != GSSCredential.ACCEPT_ONLY &&
                this.ctxCred.getUsage() != GSSCredential.INITIATE_AND_ACCEPT) {
                throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL,
                                             GlobusGSSException.UNKNOWN,
                                             "badCredUsage");
            }

            setCredential();

	    try {
                init(this.role);
	    } catch (SSLException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

	    this.conn = true;
	    logger.debug("done initializing in acceptSecContext");
        }

/*DEL
        this.out.reset();
        this.in.putToken(inBuff, off, len);
*/
	this.outByteBuff.clear();
	ByteBuffer inByteBuff;
        if (savedInBytes != null) {
            if (len > 0) {
                byte[] allInBytes = new byte[savedInBytes.length + len];
                logger.debug("ALLOCATED for allInBytes " + savedInBytes.length + " + " + len + " bytes\n");
                System.arraycopy(savedInBytes, 0, allInBytes, 0, savedInBytes.length);
                System.arraycopy(inBuff, off, allInBytes, savedInBytes.length, len);
                inByteBuff = ByteBuffer.wrap(allInBytes, 0, allInBytes.length);
            } else {
                inByteBuff = ByteBuffer.wrap(savedInBytes, 0, savedInBytes.length);
            }
            savedInBytes = null;
        } else {
            inByteBuff = ByteBuffer.wrap(inBuff, off, len);
        }

        switch (state) {
            
        case HANDSHAKE:
            
            try {
		logger.debug("STATUS BEFORE: " +
			this.sslEngine.getHandshakeStatus().toString());
                SSLEngineResult.HandshakeStatus handshake_status =
                        sslEngine.getHandshakeStatus();

                if (handshake_status ==
                        SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        // return null;
                    throw new Exception("GSSAPI in HANDSHAKE state but " +
                         "SSLEngine in NOT_HANDSHAKING state!");
                } else {
                        outByteBuff = this.sslProcessHandshake(inByteBuff, outByteBuff);
                }

		logger.debug("STATUS AFTER: " + this.sslEngine.getHandshakeStatus().toString());

            outByteBuff.flip();

/*DEL
                if (this.conn.getHandshake().finishedP()) {
*/
		if (this.sslEngine.getHandshakeStatus() ==
                        SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        // the wrap/unwrap above has resulted in handshaking
                        // being complete on our end.

                    logger.debug("acceptSecContext handshake finished");
                    handshakeFinished();
                    
                    // acceptor
                    for (X509Certificate cert : this.ctxCred.getCertificateChain()) {
                        setGoodUntil(cert.getNotAfter());
                    }
                    this.targetName = this.ctxCred.getName();

                    // initiator - peer
/*DEL
                    Vector chain = this.conn.getCertificateChain();
*/
		    Certificate[] chain;
		    try {
			chain = this.sslEngine.getSession().getPeerCertificates();
		    } catch (SSLPeerUnverifiedException e) {
                        chain = null;
                    }
                    if (chain == null || chain.length == 0) {
                        this.sourceName = new GlobusGSSName();
                        this.anonymity = true;
                    } else {
/*DEL
                        X509Cert crt = (X509Cert)chain.elementAt(chain.size()-1);
                        setGoodUntil(crt.getValidityNotAfter());
                        
                        String identity = verifyChain(chain);
*/
                        for (X509Certificate cert : (X509Certificate[])chain) {
                            setGoodUntil(cert.getNotAfter());
                        }

                        String identity = BouncyCastleUtil.getIdentity(bcConvert(BouncyCastleUtil.getIdentityCertificate((X509Certificate [])chain)));
                        this.sourceName = new GlobusGSSName(CertificateUtil.toGlobusID(identity, false));
			this.peerLimited = Boolean.valueOf(ProxyCertificateUtil.isLimitedProxy(BouncyCastleUtil.getCertificateType((X509Certificate)chain[0])));

			logger.debug("Peer Identity is: " + identity
				 + " Target name is: " + this.targetName +
				" Limited Proxy: " + this.peerLimited.toString());

                        this.anonymity = false;
                    }

                    if (this.gssMode == GSIConstants.MODE_GSI) {
                        this.state = SERVER_START_DEL;
                    } else {
                        setDone();
                    }
                }
            } catch (IOException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            } catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

            break;

        case SERVER_START_DEL:
            
            try {
                if (inByteBuff.remaining() <= 0) {
                    return null;
                }

/*DEL
                int delChar = this.conn.getInStream().read();
*/
		outByteBuff = sslDataUnwrap(inByteBuff, outByteBuff);
                outByteBuff.flip();
		byte [] delChar = new byte[outByteBuff.remaining()];
		outByteBuff.get(delChar, 0, delChar.length);
/*DEL
                if (delChar != GSIConstants.DELEGATION_CHAR) {
*/
		if (!Arrays.equals(delChar, DELEGATION_TOKEN)) {
                    setDone();
                    break;
                }
                
/*DEL
                Vector chain = this.conn.getCertificateChain();
*/
		Certificate[] chain;
		try {
		    chain = this.sslEngine.getSession().getPeerCertificates();
		} catch (SSLPeerUnverifiedException e) {
                    chain = null;
                }
                if (chain == null || chain.length == 0) {
                    throw new GlobusGSSException(GSSException.FAILURE, 
                                                 GlobusGSSException.DELEGATION_ERROR,
                                                 "noClientCert");
                }

                X509Certificate tmpCert = (X509Certificate) chain[0];
/*DEL
                    PureTLSUtil.convertCert((X509Cert)chain.lastElement());
*/
                byte [] req = generateCertRequest(tmpCert);
/*DEL
                this.conn.getOutStream().write(req, 0, req.length);
*/
		inByteBuff = ByteBuffer.wrap(req, 0, req.length);
                outByteBuff.clear();
                outByteBuff = sslDataWrap(inByteBuff, outByteBuff);
                outByteBuff.flip();

            } catch (GeneralSecurityException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }
            
            this.state = SERVER_END_DEL;
            break;

        case SERVER_END_DEL:

            try {
                if (inByteBuff.remaining() <= 0) {
                    return null;
                }

/*DEL
                X509Certificate certificate = CertUtil.loadCertificate(this.conn.getInStream());
*/
		outByteBuff = sslDataUnwrap(inByteBuff, outByteBuff);
                outByteBuff.flip();
                if (!outByteBuff.hasRemaining())
                    break;
                byte [] buf = new byte[outByteBuff.remaining()];
                outByteBuff.get(buf, 0, buf.length);
		ByteArrayInputStream inStream = new ByteArrayInputStream(buf, 0, buf.length);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)cf.generateCertificate(inStream);
		inStream.close();

                if (logger.isTraceEnabled()) {
                    logger.trace("Received delegated cert: " + 
                               certificate.toString());
                }

                verifyDelegatedCert(certificate);
                
/*DEL
                Vector chain = this.conn.getCertificateChain();
*/
		Certificate[] chain = this.sslEngine.getSession().getPeerCertificates();
                int chainLen = chain.length;
                X509Certificate [] newChain = new X509Certificate[chainLen + 1];
                newChain[0] = bcConvert((X509Certificate)certificate);
                for (int i=0;i<chainLen;i++) {
/*DEL
                    newChain[i+1] = PureTLSUtil.convertCert((X509Cert)chain.elementAt(chainLen - 1 - i));
*/
		    newChain[i+1] = bcConvert((X509Certificate)chain[i]);
                }

                X509Credential proxy = 
                    new X509Credential(this.keyPair.getPrivate(), newChain);

                this.delegCred = 
                    new GlobusGSSCredentialImpl(proxy,
                                                GSSCredential.INITIATE_AND_ACCEPT);
                
            } catch (GeneralSecurityException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            } catch (IOException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }
            setDone();
            break;

        default:
            throw new GSSException(GSSException.FAILURE);
        }

        if (inByteBuff.hasRemaining()) {
            // Likely BUFFER_UNDERFLOW; save the
            // inByteBuff bytes here like in the unwrap() case
	    logger.debug("Not all data processed; Original: " + len
                        + " Remaining: " + inByteBuff.remaining() +
                        " Handshaking status: " + sslEngine.getHandshakeStatus());
               logger.debug("SAVING unprocessed " + inByteBuff.remaining() + "BYTES\n");
               savedInBytes = new byte[inByteBuff.remaining()];
               inByteBuff.get(savedInBytes, 0, savedInBytes.length);
	}

        logger.debug("exit acceptSecContext");
/*DEL
        return (this.out.size() > 0) ? this.out.toByteArray() : null;
*/
	if (this.outByteBuff.hasRemaining()) {
                // TODO can we avoid this copy if the ByteBuffer is array based
                // and we return that array, each time allocating a new array
                // for outByteBuff?
                byte [] out = new byte[this.outByteBuff.remaining()];
                this.outByteBuff.get(out, 0, out.length);
                return out;
	} else
                return null;
    }

    // Meant for non-handshake processing
    private ByteBuffer sslDataWrap(ByteBuffer inBBuff, ByteBuffer outBBuff)
                      throws GSSException {
	try {

              if (sslEngine.getHandshakeStatus() !=
			SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                  throw new Exception("SSLEngine handshaking needed! " +
                        "HandshakeStatus: " +
                        sslEngine.getHandshakeStatus().toString());
              }
		int iter = 0;
	      do {
		logger.debug("PROCESSING DATA (WRAP) " + ++iter +
					 ": " + inBBuff.remaining());
		SSLEngineResult result = sslEngine.wrap(inBBuff, outBBuff);
		if (result.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NEED_TASK) {
			runDelegatedTasks(sslEngine);
			continue;
		}
		if (result.getStatus() ==
			SSLEngineResult.Status.BUFFER_OVERFLOW) {
		        // just increase it to the size needed.
		        int pktSize = sslEngine.getSession().getPacketBufferSize();
		        ByteBuffer b = ByteBuffer.allocate(pktSize + outBBuff.position());
		        outBBuff.flip();
		        b.put(outBBuff);
		        outBBuff = b;
			continue;
		} else if (result.getStatus() ==
                            SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                	throw new GlobusGSSException(GSSException.FAILURE,
		 		new Exception("Unexpected BUFFER_UNDERFLOW;" +
                        " Handshaking status: " + sslEngine.getHandshakeStatus()));
                }
		if (result.getStatus() !=
			SSLEngineResult.Status.OK) {
               	throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.TOKEN_FAIL,
                                         result.getStatus().toString());
		}
              } while (inBBuff.hasRemaining());

		return outBBuff;
	} catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
	}
    }

    // Not all in inBBuff might be consumed by this method!!!
    private ByteBuffer sslDataUnwrap(ByteBuffer inBBuff, ByteBuffer outBBuff)
                      throws GSSException {
	try {
		int iter = 0;
              if (sslEngine.getHandshakeStatus() !=
			SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                  throw new Exception("SSLEngine handshaking needed! " +
                        "HandshakeStatus: " +
                        sslEngine.getHandshakeStatus().toString());
              }
	      do {
		logger.debug("PROCESSING DATA (UNWRAP) " + ++iter +
			 ": " + inBBuff.remaining());
		SSLEngineResult result = sslEngine.unwrap(
			inBBuff, outBBuff);
		if (result.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NEED_TASK) {
			runDelegatedTasks(sslEngine);
			continue;
		}
		if (result.getStatus() ==
			SSLEngineResult.Status.BUFFER_OVERFLOW) {
		        // increase it to the size needed.
		        int appSize = sslEngine.getSession().getApplicationBufferSize();
		        ByteBuffer b = ByteBuffer.allocate(appSize + outBBuff.position());
		        outBBuff.flip();
		        b.put(outBBuff);
		        outBBuff = b;
			continue;
		}
		else if (result.getStatus() ==
				SSLEngineResult.Status.BUFFER_UNDERFLOW) {
			// More data needed from peer
			break;
		}
		if (result.getStatus() !=
			SSLEngineResult.Status.OK) {
                	throw new GlobusGSSException(GSSException.FAILURE,
                                             GlobusGSSException.TOKEN_FAIL,
                                         result.getStatus().toString());
		}
              } while (inBBuff.hasRemaining());
		return outBBuff;
	} catch (IllegalArgumentException e) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_TOKEN, e);
        } catch (SSLException e) {
            if (e.toString().endsWith("bad record MAC"))
                throw new GlobusGSSException(GSSException.BAD_MIC, e);
            else if (e.toString().endsWith("ciphertext sanity check failed"))
                throw new GlobusGSSException(GSSException.DEFECTIVE_TOKEN, e);
            else
                throw new GlobusGSSException(GSSException.FAILURE, e);
	} catch (Exception e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
	}
    }

    private ByteBuffer sslProcessHandshake(ByteBuffer inBBuff, ByteBuffer outBBuff)
                      throws GSSException {
	// Loopon until we need more from peer or we are done with handshaking.
	try {
done:      do {
              while (sslEngine.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NEED_WRAP) {
		SSLEngineResult result = sslEngine.wrap(inBBuff, outBBuff);
		if (result.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NEED_TASK) {
			runDelegatedTasks(sslEngine);
			continue;
		}
		if (result.getStatus() ==
			SSLEngineResult.Status.BUFFER_OVERFLOW) {
		        // increase it to the size needed.
		        int pktSize = sslEngine.getSession().getPacketBufferSize();
		        ByteBuffer b = ByteBuffer.allocate(pktSize + outBBuff.position());
		        outBBuff.flip();
		        b.put(outBBuff);
		        outBBuff = b;
			continue;
		} else if (result.getStatus() ==
                            SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                	throw new GlobusGSSException(GSSException.FAILURE,
		 		new Exception("Unexpected BUFFER_UNDERFLOW;" +
                        " Handshaking status: " + sslEngine.getHandshakeStatus()));
                }
		if (result.getStatus() !=
			SSLEngineResult.Status.OK) {
                	throw new GlobusGSSException(GSSException.FAILURE,
                                             GlobusGSSException.TOKEN_FAIL,
                                         result.getStatus().toString());
		}
              }

		int iter = 0;
              while (sslEngine.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
		logger.debug("PROCESSING " + ++iter + ": " +
					inBBuff.remaining());
		SSLEngineResult result = sslEngine.unwrap(
			inBBuff, outBBuff);
		if (result.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NEED_TASK) {
			runDelegatedTasks(sslEngine);
			continue;
		}
		if (result.getStatus() ==
			SSLEngineResult.Status.BUFFER_OVERFLOW) {
		        // increase it to the size needed.
		        int appSize = sslEngine.getSession().getApplicationBufferSize();
		        ByteBuffer b = ByteBuffer.allocate(appSize + outBBuff.position());
		        outBBuff.flip();
		        b.put(outBBuff);
		        outBBuff = b;
			continue;
		}
		else if (result.getStatus() ==
				SSLEngineResult.Status.BUFFER_UNDERFLOW) {
			// More data needed from peer
			// break out of outer loop
			break done;
		}
		if (result.getStatus() !=
			SSLEngineResult.Status.OK) {
                	throw new GlobusGSSException(GSSException.FAILURE,
                                             GlobusGSSException.TOKEN_FAIL,
                                         result.getStatus().toString());
		}
              }
           } while (sslEngine.getHandshakeStatus() !=
			SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);

	   return outBBuff;
	} catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
	}
    }

    /**
     * This function drives the initiating side of the context establishment
     * process. It is expected to be called in tandem with the
     * {@link #acceptSecContext(byte[], int, int) acceptSecContext} function.
     * <BR>
     * The behavior of context establishment process can be modified by 
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE},
     * {@link GSSConstants#DELEGATION_TYPE GSSConstants.DELEGATION_TYPE}, and
     * {@link GSSConstants#REJECT_LIMITED_PROXY GSSConstants.REJECT_LIMITED_PROXY}
     * context options. If the {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE} 
     * option is set to {@link GSIConstants#MODE_SSL GSIConstants.MODE_SSL}
     * the context establishment process will be compatible with regular SSL
     * (no credential delegation support). If the option is set to
     * {@link GSIConstants#MODE_GSI GSIConstants.GSS_MODE_GSI}
     * credential delegation during context establishment process will performed.
     * The delegation type to be performed can be set using the 
     * {@link GSSConstants#DELEGATION_TYPE GSSConstants.DELEGATION_TYPE}
     * context option. If the {@link GSSConstants#REJECT_LIMITED_PROXY 
     * GSSConstants.REJECT_LIMITED_PROXY} option is enabled, 
     * a peer presenting limited proxy credential will be automatically 
     * rejected and the context establishment process will be aborted.
     *
     * @return a byte[] containing the token to be sent to the peer.
     *         null indicates that no token is generated (needs more data). 
     */
    public byte[] initSecContext(byte[] inBuff, int off, int len) 
        throws GSSException {
        logger.debug("enter initSecContext");

        if (!this.conn) {
            this.role = INITIATE;

		logger.debug("enter initializing in initSecContext");

            if (this.anonymity || this.ctxCred.getName().isAnonymous()) {
                this.anonymity = true;
            } else {
                this.anonymity = false;

                setCredential();
                
                if (this.ctxCred.getUsage() != GSSCredential.INITIATE_ONLY &&
                    this.ctxCred.getUsage() != GSSCredential.INITIATE_AND_ACCEPT) {
                    throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL,
                                                 GlobusGSSException.UNKNOWN,
                                                 "badCredUsage");
                }
            }
            
            if (getCredDelegState()) {
                if (this.gssMode == GSIConstants.MODE_SSL) {
                    throw new GlobusGSSException(GSSException.FAILURE,
                                                 GlobusGSSException.BAD_ARGUMENT,
                                                 "initCtx00");
                }
                if (this.anonymity) {
                    throw new GlobusGSSException(GSSException.FAILURE,
                                                 GlobusGSSException.BAD_ARGUMENT,
                                                 "initCtx01");
                }
            }

	    try {
            	init(this.role);
            } catch (SSLException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

	    this.conn = true;
	    logger.debug("done initializing in initSecContext");
        }

        // Unless explicitly disabled, check if delegation is
        // requested and expected target is null
        logger.debug("Require authz with delegation: " 
                     + this.requireAuthzWithDelegation);
        if (!Boolean.FALSE.equals(this.requireAuthzWithDelegation)) {

            if (this.expectedTargetName == null && 
                getCredDelegState()) {
                throw new GlobusGSSException(GSSException.FAILURE,
                                             GlobusGSSException.BAD_ARGUMENT,
                                         "initCtx02");
            }
        }

/*DEL
        this.out.reset();
        this.in.putToken(inBuff, off, len);
*/

        this.outByteBuff.clear();
	ByteBuffer inByteBuff;
        if (savedInBytes != null) {
            if (len > 0) {
                byte[] allInBytes = new byte[savedInBytes.length + len];
                logger.debug("ALLOCATED for allInBytes " + savedInBytes.length + " + " + len + " bytes\n");
                System.arraycopy(savedInBytes, 0, allInBytes, 0, savedInBytes.length);
                System.arraycopy(inBuff, off, allInBytes, savedInBytes.length, len);
                inByteBuff = ByteBuffer.wrap(allInBytes, 0, allInBytes.length);
            } else {
                inByteBuff = ByteBuffer.wrap(savedInBytes, 0, savedInBytes.length);
            }
            savedInBytes = null;
        } else {
            inByteBuff = ByteBuffer.wrap(inBuff, off, len);
        }

        switch (state) {
            
        case HANDSHAKE:
            try {

		logger.debug("STATUS BEFORE: " +
			this.sslEngine.getHandshakeStatus().toString());
		SSLEngineResult.HandshakeStatus handshake_status =
			sslEngine.getHandshakeStatus();

        	if (handshake_status ==
			SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
			// return null;
                    throw new Exception("GSSAPI in HANDSHAKE state but " +
                         "SSLEngine in NOT_HANDSHAKING state!");
		} else {
			outByteBuff = this.sslProcessHandshake(inByteBuff, outByteBuff);
		}

		logger.debug("STATUS AFTER: " +
			this.sslEngine.getHandshakeStatus().toString());

	    outByteBuff.flip();
/*DEL
                this.conn.getHandshake().processHandshake();
                if (this.conn.getHandshake().finishedP()) {
*/
                if (this.sslEngine.getHandshakeStatus() ==
			SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
			// the wrap/unwrap above has resulted in handshaking
			// being complete on our end.
                    logger.debug("initSecContext handshake finished");
                    handshakeFinished();

/*DEL
                    Vector chain = this.conn.getCertificateChain();
                    X509Cert crt = (X509Cert)chain.elementAt(chain.size()-1);
                    setGoodUntil(crt.getValidityNotAfter());
*/
                    Certificate[] chain = this.sslEngine.getSession().getPeerCertificates();
		    if (!(chain instanceof X509Certificate[])) {
			throw new Exception("Certificate chain not of type X509Certificate");
		    }

                    for (X509Certificate cert : (X509Certificate[])chain) {
                        setGoodUntil(cert.getNotAfter());
                    }

                    // acceptor - peer

/*DEL
                    String identity = verifyChain(chain);
*/
			// chain verification would have already been done by
			// JSSE

                    String identity = BouncyCastleUtil.getIdentity(bcConvert(BouncyCastleUtil.getIdentityCertificate((X509Certificate [])chain)));
                    this.targetName = new GlobusGSSName(CertificateUtil.toGlobusID(identity, false));

                    this.peerLimited = Boolean.valueOf(ProxyCertificateUtil.isLimitedProxy(BouncyCastleUtil.getCertificateType((X509Certificate)chain[0])));

		    logger.debug("Peer Identity is: " + identity +
			 " Target name is: " + this.targetName +
			 " Limited Proxy: " + this.peerLimited.toString());

                    // initiator 
                    if (this.anonymity) {
                        this.sourceName = new GlobusGSSName();
                    } else {
                        for (X509Certificate cert : this.ctxCred.getCertificateChain()) {
                            setGoodUntil(cert.getNotAfter());
                        }
                        this.sourceName = this.ctxCred.getName();
                    }
                    
                    // mutual authentication test
                    if (this.expectedTargetName != null &&
                        !this.expectedTargetName.equals(this.targetName)) {
                        throw new GlobusGSSException(GSSException.UNAUTHORIZED,
                                                     GlobusGSSException.BAD_NAME,
                                                     "authFailed00",
                                                     new Object[] {this.expectedTargetName,
                                                                   this.targetName});
                    }

                    if (this.gssMode == GSIConstants.MODE_GSI) {
                        this.state = CLIENT_START_DEL;
                        // if there is data to return then
                        // break. otherwise we fall through!!!
                        if (this.outByteBuff.remaining() > 0) {
                            break;
                        }
                    } else {
                        setDone();
                        break;
                    }

                } else {
                    break;
                }
            } catch (IOException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            } catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

        case CLIENT_START_DEL:
            
            logger.debug("CLIENT_START_DEL");
            // sanity check - might be invalid state
            if (this.state != CLIENT_START_DEL || this.outByteBuff.remaining() > 0) {
                throw new GSSException(GSSException.FAILURE);
            }
	    if (inByteBuff.hasRemaining()) {
               		throw new GlobusGSSException(GSSException.FAILURE,
		 		new Exception("Not all data processed; Original: " + len
                        + " Remaining: " + inByteBuff.remaining() +
                        " Handshaking status: " + sslEngine.getHandshakeStatus()));
	    }
            this.outByteBuff.clear();

            try {
		String deleg;

                if (getCredDelegState()) {
                    deleg = Character.toString(GSIConstants.DELEGATION_CHAR);
                    this.state = CLIENT_END_DEL;
                } else {
		    deleg = Character.toString('0');
                    setDone();
		}

		byte[] a = deleg.getBytes("US-ASCII");
		inByteBuff = ByteBuffer.wrap(a, 0, a.length);
                outByteBuff = sslDataWrap(inByteBuff, outByteBuff);
		outByteBuff.flip();

            } catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

            break;

        case CLIENT_END_DEL:

            logger.debug("CLIENT_END_DEL");
	    if (!inByteBuff.hasRemaining()) {
                throw new GSSException(GSSException.DEFECTIVE_TOKEN);
	    }

            try {
/*DEL
                if (this.in.available() <= 0) {
                    return null;
                }
*/
                outByteBuff = sslDataUnwrap(inByteBuff, outByteBuff);
		outByteBuff.flip();
                if (!outByteBuff.hasRemaining())
                    break;

		byte [] certReq = new byte[outByteBuff.remaining()];
		outByteBuff.get(certReq, 0, certReq.length);

                X509Certificate [] chain = this.ctxCred.getCertificateChain();

                X509Certificate cert = 
                    this.certFactory.createCertificate(new ByteArrayInputStream(certReq),
                                                       chain[0],
                                                       this.ctxCred.getPrivateKey(),
                                                       -1,
/*DEL
                                                       getDelegationType(chain[0]));
*/
                                                       BouncyCastleCertProcessingFactory.decideProxyType(chain[0], this.delegationType));

                byte [] enc = cert.getEncoded();
/*DEL
                this.conn.getOutStream().write(enc, 0, enc.length);
*/
		inByteBuff = ByteBuffer.wrap(enc, 0, enc.length);
		outByteBuff.clear();
                outByteBuff = sslDataWrap(inByteBuff, outByteBuff);
		outByteBuff.flip();

                setDone();
            } catch (GeneralSecurityException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            } catch (IOException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

            break;

        default:
            throw new GSSException(GSSException.FAILURE);
        }

        if (inByteBuff.hasRemaining()) {
            // Likely BUFFER_UNDERFLOW; save the
            // inByteBuff bytes here like in the unwrap() case
	    logger.debug("Not all data processed; Original: " + len
                        + " Remaining: " + inByteBuff.remaining() +
                        " Handshaking status: " + sslEngine.getHandshakeStatus());
               logger.debug("SAVING unprocessed " + inByteBuff.remaining() + "BYTES\n");
               savedInBytes = new byte[inByteBuff.remaining()];
               inByteBuff.get(savedInBytes, 0, savedInBytes.length);
	}

        logger.debug("exit initSecContext");
	//XXX: Why is here a check for CLIENT_START_DEL?
        // if (this.outByteBuff.hasRemaining() || this.state == CLIENT_START_DEL) {
        if (this.outByteBuff.hasRemaining()) {
                // TODO can we avoid this copy if the ByteBuffer is array based
                // and we return that array, each time allocating a new array
                // for outByteBuff?
		byte [] out = new byte[this.outByteBuff.remaining()];
		this.outByteBuff.get(out, 0, out.length);
		return out;
	} else
		return null;
    }

    private void setDone() {
	logger.debug("DONE with Handshaking and any initial cred delegation");
        this.established = true;
    }

    private void setGoodUntil(Date date) {
        if (this.goodUntil == null) {
            this.goodUntil = date;
        } else if (date.before(this.goodUntil)) {
            this.goodUntil = date;
        }
    }

    private void init(int how) 
        throws GSSException, SSLException {

/*DEL
        short [] cs;
        if (this.encryption) {
            // always make sure to add NULL cipher at the end
            short [] ciphers = this.policy.getCipherSuites();
            short [] newCiphers = new short[ciphers.length + 1];
            System.arraycopy(ciphers, 0, newCiphers, 0, ciphers.length);
            newCiphers[ciphers.length] = SSLPolicyInt.TLS_RSA_WITH_NULL_MD5;
            cs = newCiphers;
        } else {
            // encryption not requested - accept only one cipher
            // XXX: in the future might want to iterate through 
            // all cipher and enable only the null encryption ones
            cs = NO_ENCRYPTION;
        }
        this.policy.setCipherSuites(cs);
        this.policy.requireClientAuth(this.requireClientAuth.booleanValue());
        this.policy.setAcceptNoClientCert(this.acceptNoClientCerts.booleanValue());

        setTrustedCertificates();
        
        this.in = new TokenInputStream();
        this.out = new ByteArrayOutputStream();

        try {
            this.conn = new SSLConn(null, 
                                    this.in,
                                    this.out, 
                                    this.context, 
                                    how); 
        } catch (IOException e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }       

        this.conn.init();
*/
	try {
		this.sslConfigurator.setRejectLimitProxy(rejectLimitedProxy);
                if (proxyPolicyHandlers != null)
                    sslConfigurator.setHandlers(proxyPolicyHandlers);

        	this.sslContext = this.sslConfigurator.getSSLContext();
        	this.sslEngine = this.sslContext.createSSLEngine();
	} catch (Exception e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }

	if (this.forceSSLv3AndConstrainCipherSuitesForGram.booleanValue())
           this.sslEngine.setEnabledProtocols(GRAM_PROTOCOLS);
        else
           this.sslEngine.setEnabledProtocols(ENABLED_PROTOCOLS);
	logger.debug("SUPPORTED PROTOCOLS: " +
                    Arrays.toString(this.sslEngine.getSupportedProtocols()) +
                    "; ENABLED PROTOCOLS: " +
                    Arrays.toString(this.sslEngine.getEnabledProtocols()));

        ArrayList<String> cs = new ArrayList();
        if (this.encryption) {
            if (this.forceSSLv3AndConstrainCipherSuitesForGram.booleanValue())
                for (String cipherSuite : GRAM_ENCRYPTION_CIPHER_SUITES)
                    cs.add(cipherSuite);
            else // Simply retain the default-enabled Cipher Suites
               cs.addAll(Arrays.asList(this.sslEngine.getEnabledCipherSuites()));
        } else {
            if (this.forceSSLv3AndConstrainCipherSuitesForGram.booleanValue())
                for (String cipherSuite : GRAM_NO_ENCRYPTION_CIPHER_SUITES)
                    cs.add(cipherSuite);
            else {
               for (String cipherSuite : NO_ENCRYPTION)
                   cs.add(cipherSuite);
               cs.addAll(Arrays.asList(this.sslEngine.getEnabledCipherSuites()));
            }
        }
        String[] testSuite = new String[0];
        this.sslEngine.setEnabledCipherSuites(cs.toArray(testSuite));
        logger.debug("CIPHER SUITE IS: " + Arrays.toString(
                      this.sslEngine.getEnabledCipherSuites()));

	// TODO: Document the following behavior
	// NOTE: requireClientAuth Vs. acceptNoClientCerts
	// which one takes precedence? for now err on the side of security
	 if (this.requireClientAuth.booleanValue() == Boolean.TRUE) {
             this.sslEngine.setNeedClientAuth(this.requireClientAuth.booleanValue());
	 } else
             this.sslEngine.setWantClientAuth(!this.acceptNoClientCerts.booleanValue());

        this.sslEngine.setUseClientMode(how == INITIATE);

        this.certFactory = BouncyCastleCertProcessingFactory.getDefault();
        this.state = HANDSHAKE;
	int appSize = sslEngine.getSession().getApplicationBufferSize();
	this.outByteBuff = ByteBuffer.allocate(appSize);
	this.sslEngine.beginHandshake();
    }

    /* this is called when handshake is done */
    private void handshakeFinished()
        throws IOException {
/*DEL
        // this call just forces some internal library
        // variables to be initailized
        this.conn.finishHandshake();
*/
        String cs =
            this.sslEngine.getSession().getCipherSuite();
        this.encryption = !cs.contains("WITH_NULL");
        logger.debug("encryption alg: " + cs); 
    }
    
/*DEL
    // allows bypass of PureTLS checks - since they were
    // already performed during SSL hashshake
    static class GSSProxyPathValidator extends ProxyPathValidator {
        public void validate(X509Certificate [] certPath,
                             TrustedCertificates trustedCerts,
                             CertificateRevocationLists crlsList)
            throws ProxyPathValidatorException {
            super.validate(certPath, trustedCerts, crlsList);
        }
    }

    private String verifyChain(Vector peerCerts)
        throws GSSException {
        
        X509Certificate[] peerChain = null;
        try {
            peerChain = PureTLSUtil.certificateChainToArray(peerCerts);
        } catch (GeneralSecurityException e) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL,
                                         e);
        }

        GSSProxyPathValidator validator = new GSSProxyPathValidator();

        if (this.proxyPolicyHandlers != null) {
            Iterator iter = this.proxyPolicyHandlers.keySet().iterator();
            String oid;
            ProxyPolicyHandler handler;
            while(iter.hasNext()) {
                oid = (String)iter.next();
                handler = 
                    (ProxyPolicyHandler)this.proxyPolicyHandlers.get(oid);
                validator.setProxyPolicyHandler(oid, handler);
            }
        }

        CertificateRevocationLists certRevList =
            CertificateRevocationLists.getDefaultCertificateRevocationLists();

        validator.setRejectLimitedProxyCheck(
                  this.rejectLimitedProxy.booleanValue());

        try {
            validator.validate(peerChain, this.tc, certRevList);
        } catch (ProxyPathValidatorException e) {
            // COMMENT FIXME we don't have an error code
            if (e.getErrorCode() == 
                ProxyPathValidatorException.LIMITED_PROXY_ERROR) {
                throw new GlobusGSSException(GSSException.UNAUTHORIZED, 
                                             e);
            } else {
                throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL,
                                             e);
            }
        }
        
        // C code also sets a flag RECEIVED_LIMITED_PROXY
        // when recevied certs is a limited proxy
        this.peerLimited = (validator.isLimited()) ? 
            Boolean.TRUE : Boolean.FALSE;
        
        return validator.getIdentity();
    }
*/
    
    private void setCredential() 
        throws GSSException {
        try {
/*DEL
            this.context.setCredential(this.ctxCred.getX509Credential());
*/
        KeyStore keyStore = KeyStore.getInstance("JKS");
	    keyStore.load(null, null);
	    X509Credential cred = this.ctxCred.getX509Credential();

	    keyStore.setKeyEntry("default", cred.getPrivateKey(),
			"password".toCharArray(), cred.getCertificateChain());
	    this.sslConfigurator.setCredentialStore(keyStore);
	    this.sslConfigurator.setCredentialStorePassword("password");

        } catch (GeneralSecurityException e) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL, e);
        } catch (Exception e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }
    }

/*DEL
    private void setTrustedCertificates()
        throws GSSException {
        if (this.tc == null) {
            this.tc = PureTLSTrustedCertificates.getDefaultPureTLSTrustedCertificates();
        }
        if (this.tc == null) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_CREDENTIAL,
                                         GlobusGSSException.UNKNOWN,
                                         "noCaCerts");
        }
        try {
            // COMMENT: move use of PureTLS from TrustCertificates
            this.context.setRootList(PureTLSUtil.certificateChainToVector(this.tc.getCertificates()));
        } catch (GeneralSecurityException e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }
    }
*/

    /**
     * Wraps a message for integrity and protection.
     * A regular SSL-wrapped token is returned.
     */
    public byte[] wrap(byte []inBuf, int off, int len, MessageProp prop) 
        throws GSSException {

        checkContext();

        logger.debug("enter wrap");

        byte [] token = null;
        boolean doGSIWrap = false;

        if (prop != null) {
            if (prop.getQOP() != 0 && prop.getQOP() != GSSConstants.GSI_BIG) {
                throw new GSSException(GSSException.BAD_QOP);
            }
            doGSIWrap = (!prop.getPrivacy() && prop.getQOP() == GSSConstants.GSI_BIG);
        }
        
        if (doGSIWrap) {
            throw new GSSException(GSSException.UNAVAILABLE);
/*DEL
            
            byte [] mic = getMIC(inBuf, off, len, null);

            byte [] wtoken = new byte[5 + len + mic.length];
            wtoken[0] = GSI_WRAP;
            wtoken[1] = 3;
            wtoken[2] = 0;
            wtoken[3] = (byte)(mic.length >>> 8);
            wtoken[4] = (byte)(mic.length >>> 0);
            System.arraycopy(mic, 0, wtoken, 5, mic.length);
            System.arraycopy(inBuf, off, wtoken, 5+mic.length, len);

            token = wtoken;
*/
        } else {
            token = wrap(inBuf, off, len);

            if (prop != null) {
                prop.setPrivacy(this.encryption);
                prop.setQOP(0);
            }
        }
        
        logger.debug("exit wrap");
        return token;
    }
    
    private byte[] wrap(byte[] inBuf, int off, int len) 
        throws GSSException {
        try {
/*DEL
            this.conn.getOutStream().write(inBuf, off, len);
*/
	    ByteBuffer inByteBuff = ByteBuffer.wrap(inBuf, off, len);
	    this.outByteBuff.clear();
	    outByteBuff = this.sslDataWrap(inByteBuff, outByteBuff);
	    outByteBuff.flip();

	    if (inByteBuff.hasRemaining()) {
		throw new Exception("Not all data processed; Original: " + len
                        + " Remaining: " + inByteBuff.remaining() +
                        " Handshaking status: " + sslEngine.getHandshakeStatus());
	    }
        } catch (Exception e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }

        if (this.outByteBuff.hasRemaining()) {
                // TODO can we avoid this copy if the ByteBuffer is array based
                // and we return that array, each time allocating a new array
                // for outByteBuff?
		byte [] out = new byte[this.outByteBuff.remaining()];
		this.outByteBuff.get(out, 0, out.length);
		return out;
	} else
		return null;
/*DEL
        return this.out.toByteArray();
*/
    }
    
    /**
     * Unwraps a token generated by <code>wrap</code> method on the other side of the context.
     */
    public byte[] unwrap(byte []inBuf, int off, int len, MessageProp prop) 
        throws GSSException {

        checkContext();

        logger.debug("enter unwrap");

        byte [] token = null;

        /*
         * see if the token is a straight SSL packet or
         * one of ours made by wrap using get_mic
         */
        if (inBuf[off] == GSI_WRAP &&
            inBuf[off+1] == 3 && 
            inBuf[off+2] == 0) {
            throw new GSSException(GSSException.UNAVAILABLE);
/*DEL
            
            int micLen = SSLUtil.toShort(inBuf[off+3], inBuf[off+4]);
            int msgLen = len - 5 - micLen;

            if (micLen > len-5 || msgLen < 0) {
                throw new GSSException(GSSException.DEFECTIVE_TOKEN);
            } 
            
            verifyMIC(inBuf, off+5, micLen,
                      inBuf, off+5+micLen, msgLen, 
                      null);

            if (prop != null) {
                prop.setPrivacy(false);
                prop.setQOP(GSSConstants.GSI_BIG);
            }

            // extract the data
            token = new byte[msgLen];
            System.arraycopy(inBuf, off+5+micLen, token, 0, msgLen);
*/
            
        } else {
            token = unwrap(inBuf, off, len);
            
            if (prop != null) {
                prop.setPrivacy(this.encryption);
                prop.setQOP(0);
            }
        }
        
        logger.debug("exit unwrap");
        return token;
    }
    
    private byte[] unwrap(byte[] inBuf, int off, int len) 
        throws GSSException {

/*DEL
        ByteArrayInputStream in =
            new ByteArrayInputStream(inBuf, off, len);
        ByteArrayOutputStream out =
            new ByteArrayOutputStream();

        // TODO: this might need to be rewritten
        // to catch lower level exceptions
        // e.g. mac too long, etc.
        try {
            while(in.available() > 0) {
                SSLRecord r = new SSLRecord(null);
                r.decode(this.conn, in);
                switch (r.getType().getValue()) {
                case SSLRecord.SSL_CT_APPLICATION_DATA:
                    out.write(r.getData().getValue());
                    break;
                case SSLRecord.SSL_CT_ALERT:
                    this.conn.getRecordReader().processAlert(r.getData().getValue());
                    break;
                default:
                    throw new Exception(i18n.getMessage("tokenFail03"));
                }
            }
        } catch (IOException e) {
            throw new GlobusGSSException(GSSException.BAD_MIC, e);
        } catch (Exception e) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_TOKEN, e);
        }
        
        return out.toByteArray();
*/
	ByteBuffer inByteBuff;
        if (savedInBytes != null) {
            if (len > 0) {
                byte[] allInBytes = new byte[savedInBytes.length + len];
                logger.debug("ALLOCATED for allInBytes " + savedInBytes.length + " + " + len + " bytes\n");
                System.arraycopy(savedInBytes, 0, allInBytes, 0, savedInBytes.length);
                System.arraycopy(inBuf, off, allInBytes, savedInBytes.length, len);
                inByteBuff = ByteBuffer.wrap(allInBytes, 0, allInBytes.length);
            } else {
                inByteBuff = ByteBuffer.wrap(savedInBytes, 0, savedInBytes.length);
            }
            savedInBytes = null;
        } else {
            inByteBuff = ByteBuffer.wrap(inBuf, off, len);
        }
	this.outByteBuff.clear();
	outByteBuff = this.sslDataUnwrap(inByteBuff, outByteBuff);
	outByteBuff.flip();

	if (inByteBuff.hasRemaining()) {
	    logger.debug("Not all data processed; Original: " + len
                        + " Remaining: " + inByteBuff.remaining() +
                        " Handshaking status: " + sslEngine.getHandshakeStatus());
               logger.debug("SAVING unprocessed " + inByteBuff.remaining() + "BYTES\n");
               savedInBytes = new byte[inByteBuff.remaining()];
               inByteBuff.get(savedInBytes, 0, savedInBytes.length);
	}

        if (this.outByteBuff.hasRemaining()) {
                // TODO can we avoid this copy if the ByteBuffer is array based
                // and we return that array, each time allocating a new array
                // for outByteBuff?
		byte [] out = new byte[this.outByteBuff.remaining()];
		this.outByteBuff.get(out, 0, out.length);
		return out;
	} else
		return null;

    }

    public void dispose() 
        throws GSSException {
        // doesn't do anything right now
        logger.debug("dipose");
    }

    public boolean isEstablished() {
        return this.established;
    }

    public void requestCredDeleg(boolean state) throws GSSException {
        this.credentialDelegation = state;
    }

    public boolean getCredDelegState() {
        return this.credentialDelegation;
    }
    
    public boolean isInitiator() 
        throws GSSException {
        if (this.role == UNDEFINED) {
            throw new GSSException(GSSException.FAILURE);
        }
        return (this.role == INITIATE);
    }

    public boolean isProtReady() {
        return isEstablished();
    }

    public void requestLifetime(int lifetime) 
        throws GSSException {
        if (lifetime == GSSContext.INDEFINITE_LIFETIME) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.UNKNOWN,
                                         "badLifetime00");
        }

        if (lifetime != GSSContext.DEFAULT_LIFETIME) {
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.SECOND, lifetime);
            setGoodUntil(calendar.getTime());
        }
    }

    public int getLifetime() {
        if (this.goodUntil != null) {
            return (int)((this.goodUntil.getTime() - System.currentTimeMillis())/1000);
        } else {
            return -1;
        }
    }

    public Oid getMech() throws GSSException {
        return GSSConstants.MECH_OID;
    }

    public GSSCredential getDelegCred() throws GSSException {
        return this.delegCred;
    }

    public void requestConf(boolean state) 
        throws GSSException {
        // enabled encryption
        this.encryption = state;
    }

    public boolean getConfState() {
        return this.encryption;
    }

    /**
     * Returns a cryptographic MIC (message integrity check)
     * of a specified message.
     */
    public byte[] getMIC(byte [] inBuf, 
                         int off,
                         int len,
                         MessageProp prop) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
/*TODO

        checkContext();

        logger.debug("enter getMic");

        if (prop != null && (prop.getQOP() != 0 || prop.getPrivacy())) {
            throw new GSSException(GSSException.BAD_QOP);
        }

        SSLCipherState st = this.conn.getWriteCipherState();
        SSLCipherSuite cs = st.getCipherSuite();
        long sequence = this.conn.getWriteSequence();

        byte [] mic = new byte[GSI_MESSAGE_DIGEST_PADDING + cs.getDigestOutputLength()];
        
        System.arraycopy(Util.toBytes(sequence), 0, mic, 0, GSI_SEQUENCE_SIZE);
        System.arraycopy(Util.toBytes(len, 4), 0, mic, GSI_SEQUENCE_SIZE, 4);

        this.conn.incrementWriteSequence();

        int pad_ct = (cs.getDigestOutputLength()==16) ? 48 : 40;
        
        try {
            MessageDigest md = 
                MessageDigest.getInstance(cs.getDigestAlg());
        
            md.update(st.getMacKey());
            for(int i=0;i<pad_ct;i++) {
                md.update(SSLHandshake.pad_1);
            }
            md.update(mic, 0, GSI_MESSAGE_DIGEST_PADDING);
            md.update(inBuf, off, len);

            byte[] digest = md.digest();

            System.arraycopy(digest, 0, mic, GSI_MESSAGE_DIGEST_PADDING, digest.length);
        } catch (NoSuchAlgorithmException e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }
        
        if (prop != null) {
            prop.setPrivacy(false);
            prop.setQOP(0);
        }
        
        logger.debug("exit getMic");
        return mic;
*/
    }
    
    /**
     * Verifies a cryptographic MIC (message integrity check)
     * of a specified message.
     */
    public void verifyMIC(byte[] inTok, int tokOff, int tokLen, // mic
                          byte[] inMsg, int msgOff, int msgLen, // real msg
                          MessageProp prop) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
/*TODO

        checkContext();

        logger.debug("enter verifyMic");

        SSLCipherState st = this.conn.getReadCipherState();
        SSLCipherSuite cs = st.getCipherSuite();

        logger.debug("digest algorithm: " + cs.getDigestAlg());

        if (tokLen != (GSI_MESSAGE_DIGEST_PADDING + cs.getDigestOutputLength())) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_TOKEN,
                                         GlobusGSSException.TOKEN_FAIL,
                                         "tokenFail00",
                                         new Object[] {new Integer(tokLen), 
                                                       new Integer(GSI_MESSAGE_DIGEST_PADDING + 
                                                                   cs.getDigestOutputLength())});
        }
        
        int bufLen = SSLUtil.toInt(inTok, tokOff+GSI_SEQUENCE_SIZE);
        if (bufLen != msgLen) {
            throw new GlobusGSSException(GSSException.DEFECTIVE_TOKEN, 
                                         GlobusGSSException.TOKEN_FAIL,
                                         "tokenFail01",
                                         new Object[] {new Integer(msgLen), new Integer(bufLen)});
        }
        
        int pad_ct = (cs.getDigestOutputLength()==16) ? 48 : 40;

        byte [] digest = null;
        
        try {
            MessageDigest md = 
                MessageDigest.getInstance(cs.getDigestAlg());
            
            md.update(st.getMacKey());
            for(int i=0;i<pad_ct;i++) {
                md.update(SSLHandshake.pad_1);
            }
            md.update(inTok, tokOff, GSI_MESSAGE_DIGEST_PADDING);
            md.update(inMsg, msgOff, msgLen);

            digest = md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }
        
        byte [] token = new byte[tokLen-GSI_MESSAGE_DIGEST_PADDING];
        System.arraycopy(inTok, tokOff+GSI_MESSAGE_DIGEST_PADDING, token, 0, token.length);

        if (!Arrays.equals(digest, token)) {
            throw new GlobusGSSException(GSSException.BAD_MIC, 
                                         GlobusGSSException.BAD_MIC,
                                         "tokenFail02");
        }
        
        long tokSeq = SSLUtil.toLong(inTok, tokOff);
        long readSeq = this.conn.getReadSequence();
        long seqTest = tokSeq - readSeq;

        logger.debug("Token seq#   : " + tokSeq);
        logger.debug("Current seq# : " + readSeq);
        
        if (seqTest > 0) {
            // gap token
            throw new GSSException(GSSException.GAP_TOKEN);
        } else if (seqTest < 0) {
            // old token
            throw new GSSException(GSSException.OLD_TOKEN);
        } else {
            this.conn.incrementReadSequence();
        }

        if (prop != null) {
            prop.setPrivacy(false);
            prop.setQOP(0);
        }
        
        logger.debug("exit verifyMic");
*/
    }


    /**
     * It works just like {@link #initSecContext(byte[], int, int) initSecContext} method.
     * It reads one SSL token from input stream, calls 
     * {@link #initSecContext(byte[], int, int) initSecContext} method and
     * writes the output token to the output stream (if any)
     * SSL token is not read on the initial call.
     */
    public int initSecContext(InputStream in, OutputStream out)
        throws GSSException {
        byte [] inToken = null;
        try {
            if (!this.conn) {
                inToken = new byte[0];
            } else {
                inToken = SSLUtil.readSslMessage(in);
            }
            byte [] outToken = initSecContext(inToken, 0, inToken.length);
            if (outToken != null) {
                out.write(outToken);
                return outToken.length;
            } else {
                return 0;
            }
        } catch (IOException e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }
    }

    /**
     * It works just like {@link #acceptSecContext(byte[], int, int) acceptSecContext}
     * method. It reads one SSL token from input stream, calls 
     * {@link #acceptSecContext(byte[], int, int) acceptSecContext}
     * method and writes the output token to the output stream (if any)
     */
    public void acceptSecContext(InputStream in, OutputStream out)
        throws GSSException {
        try {
            byte [] inToken = SSLUtil.readSslMessage(in);
            byte [] outToken = acceptSecContext(inToken, 0, inToken.length);
            if (outToken != null) {
                out.write(outToken);
            }
        } catch (IOException e) {
            throw new GlobusGSSException(GSSException.FAILURE, e);
        }
    }
    
    public GSSName getSrcName() throws GSSException {
        return this.sourceName;
    }
    
    public GSSName getTargName() throws GSSException {
        return this.targetName;
    }

    public void requestInteg(boolean state) 
        throws GSSException {
        if (!state) {
            throw new GlobusGSSException(GSSException.FAILURE, 
                                         GlobusGSSException.BAD_OPTION, 
                                         "integOn");
        }
    }
    
    public boolean getIntegState() {
        return true; // it is always on with ssl
    }

    public void requestSequenceDet(boolean state) 
        throws GSSException {
        if (!state) {
            throw new GlobusGSSException(GSSException.FAILURE, 
                                         GlobusGSSException.BAD_OPTION,
                                         "seqDet");
        }
    }
    
    public boolean getSequenceDetState() {
        return true; // it is always on with ssl
    }

    public void requestReplayDet(boolean state) 
        throws GSSException {
        if (!state) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION, 
                                         "replayDet");
        }
    }

    public boolean getReplayDetState() {
        return true; // is is always on with ssl
    }

    public void requestAnonymity(boolean state) 
        throws GSSException {
        this.anonymity = state;
    }

    public boolean getAnonymityState() {
        return this.anonymity;
    }

    public void requestMutualAuth(boolean state) 
        throws GSSException {
        if (!state) {
            throw new GlobusGSSException(GSSException.FAILURE, 
                                         GlobusGSSException.BAD_OPTION, 
                                         "mutualAuthOn");
        }
    }
    
    public boolean getMutualAuthState() {
        return true; // always on with gsi i guess
    }

    protected byte[] generateCertRequest(X509Certificate cert) 
        throws GeneralSecurityException {

        int bits = 
            ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength();

        this.keyPair = keyPairCache.getKeyPair(bits);
        
        return this.certFactory.createCertificateRequest(cert, this.keyPair);
    }

    protected void verifyDelegatedCert(X509Certificate certificate)
        throws GeneralSecurityException {
        RSAPublicKey pubKey = (RSAPublicKey)certificate.getPublicKey();
        RSAPrivateKey privKey = (RSAPrivateKey)this.keyPair.getPrivate();
                
        if (!pubKey.getModulus().equals(privKey.getModulus())) {
            throw new GeneralSecurityException(i18n.getMessage("keyMismatch"));
        }
    }

    protected void checkContext() 
        throws GSSException {
        if (!this.conn || !isEstablished()) {
            throw new GSSException(GSSException.NO_CONTEXT);
        }
        
        if (this.checkContextExpiration.booleanValue() && getLifetime() <= 0) {
            throw new GSSException(GSSException.CONTEXT_EXPIRED);
        }
    }

/*DEL
    protected int getDelegationType(X509Certificate issuer) 
        throws GeneralSecurityException, GSSException {

        // GSIConstants.CertificateType certType = BouncyCastleUtil.getCertificateType(issuer, this.tc);
	// TODO: Is this alright without this.tc being passed?
        GSIConstants.CertificateType certType = BouncyCastleUtil.getCertificateType(issuer);
        int dType = this.delegationType.intValue();

        if (logger.isDebugEnabled()) {
            logger.debug("Issuer type: " + certType + " delg. type requested: " + dType);
        }

        if (certType == GSIConstants.CertificateType.EEC) {
            if (dType == GSIConstants.DELEGATION_LIMITED) {
                if (VersionUtil.isGsi2Enabled()) {
                    return GSIConstants.GSI_2_LIMITED_PROXY;
                } else if (VersionUtil.isGsi3Enabled()) {
                    return GSIConstants.GSI_3_LIMITED_PROXY;
                } else {
                    return GSIConstants.GSI_4_LIMITED_PROXY;
                }
            } else if (dType == GSIConstants.DELEGATION_FULL) {
                if (VersionUtil.isGsi2Enabled()) {
                    return GSIConstants.GSI_2_PROXY;
                } else if (VersionUtil.isGsi3Enabled()) {
                    return GSIConstants.GSI_3_IMPERSONATION_PROXY;
                } else {
                    return GSIConstants.GSI_4_IMPERSONATION_PROXY;
                }
            } else if (ProxyCertificateUtil.isProxy(GSIConstants.CertificateType.get(dType))) {
                return dType;
            }
        } else if (ProxyCertificateUtil.isGsi2Proxy(certType)) {
            if (dType == GSIConstants.DELEGATION_LIMITED) {
                return GSIConstants.GSI_2_LIMITED_PROXY;
            } else if (dType == GSIConstants.DELEGATION_FULL) {
                return GSIConstants.GSI_2_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(GSIConstants.CertificateType.get(dType))) {
                return dType;
            }
        } else if (ProxyCertificateUtil.isGsi3Proxy(certType)) {
            if (dType == GSIConstants.DELEGATION_LIMITED) {
                return GSIConstants.GSI_3_LIMITED_PROXY;
            } else if (dType == GSIConstants.DELEGATION_FULL) {
                return GSIConstants.GSI_3_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(GSIConstants.CertificateType.get(dType))) {
                return dType;
            }
        } else if (ProxyCertificateUtil.isGsi4Proxy(certType)) {
            if (dType == GSIConstants.DELEGATION_LIMITED) {
                return GSIConstants.GSI_4_LIMITED_PROXY;
            } else if (dType == GSIConstants.DELEGATION_FULL) {
                return GSIConstants.GSI_4_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi4Proxy(GSIConstants.CertificateType.get(dType))) {
                return dType;
            }
        }
        throw new GSSException(GSSException.FAILURE);
    }
*/


    // -----------------------------------

    protected void setGssMode(Object value) 
        throws GSSException {
        if (!(value instanceof Integer)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object [] {"GSS mode", Integer.class});
        }
        Integer v = (Integer)value;
        if (v == GSIConstants.MODE_GSI || 
            v == GSIConstants.MODE_SSL) {
            this.gssMode = v;
        } else {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION,
                                         "badGssMode");
        }
    }

    protected void setDelegationType(Object value) 
        throws GSSException {
        GSIConstants.DelegationType v;
        if (value instanceof GSIConstants.DelegationType)
            v = (GSIConstants.DelegationType) value;
        else if (value instanceof Integer)
            v = GSIConstants.DelegationType.get(((Integer) value).intValue());
        else {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"delegation type",  GSIConstants.DelegationType.class});
        }
/*DEL
        Integer v = (Integer)value;
*/
        if (v == GSIConstants.DelegationType.FULL ||
            v == GSIConstants.DelegationType.LIMITED) {
            this.delegationType = v;
        } else {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION,
                                         "badDelegType");
        }
    }

    protected void setCheckContextExpired(Object value) 
        throws GSSException {
        if (!(value instanceof Boolean)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"check context expired", Boolean.class});
        }
        this.checkContextExpiration = (Boolean)value;
    }

    protected void setRejectLimitedProxy(Object value) 
        throws GSSException {
        if (!(value instanceof Boolean)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"reject limited proxy", Boolean.class});
        }
        this.rejectLimitedProxy = (Boolean)value;
    }

    protected void setRequireClientAuth(Object value) 
        throws GSSException {
        if (!(value instanceof Boolean)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"require client auth", Boolean.class});
        }
        this.requireClientAuth = (Boolean)value;
    }

    protected void setRequireAuthzWithDelegation(Object value) 
        throws GSSException {
        
        if (!(value instanceof Boolean)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"require authz with delehation", Boolean.class});
        }
        this.requireAuthzWithDelegation = (Boolean)value;
    }

    protected void setAcceptNoClientCerts(Object value)
        throws GSSException {
        if (!(value instanceof Boolean)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"accept no client certs", Boolean.class});
        }
        this.acceptNoClientCerts = (Boolean)value;
    }

    protected void setForceSslV3AndConstrainCipherSuitesForGram(
                             Object value)
        throws GSSException {
        if (!(value instanceof Boolean)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"adjust cipher suites for GRAM", Boolean.class});
        }
        this.forceSSLv3AndConstrainCipherSuitesForGram = (Boolean)value;
    }

/*DEL
    protected void setGrimPolicyHandler(Object value) 
        throws GSSException {
        if (!(value instanceof ProxyPolicyHandler)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"GRIM policy handler", 
                                                       ProxyPolicyHandler.class});
        }
        if (this.proxyPolicyHandlers == null) {
            this.proxyPolicyHandlers = new HashMap();
        }
        this.proxyPolicyHandlers.put("1.3.6.1.4.1.3536.1.1.1.7", value);
    }
*/

    protected void setProxyPolicyHandlers(Object value) 
        throws GSSException {
        if (!(value instanceof Map)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                        new Object[] {"Proxy policy handlers", 
                                                      Map.class});
        }
        this.proxyPolicyHandlers = (Map)value;
    }

/*DEL
    protected void setTrustedCertificates(Object value) 
        throws GSSException {
        if (!(value instanceof TrustedCertificates)) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_OPTION_TYPE,
                                         "badType",
                                         new Object[] {"Trusted certificates", 
                                                       TrustedCertificates.class});
        }
	//TODO: set this in SSLConfigurator before creating SSLContext and engine?
        this.tc = (TrustedCertificates)value;
    }
*/
    
    public void setOption(Oid option, Object value)
        throws GSSException {
        if (option == null) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_ARGUMENT,
                                         "nullOption");
        }
        if (value == null) {
            throw new GlobusGSSException(GSSException.FAILURE,
                                         GlobusGSSException.BAD_ARGUMENT,
                                         "nullOptionValue");
        }
        
        if (option.equals(GSSConstants.GSS_MODE)) {
            setGssMode(value);
        } else if (option.equals(GSSConstants.DELEGATION_TYPE)) {
            setDelegationType(value);
        } else if (option.equals(GSSConstants.CHECK_CONTEXT_EXPIRATION)) {
            setCheckContextExpired(value);
        } else if (option.equals(GSSConstants.REJECT_LIMITED_PROXY)) {
            setRejectLimitedProxy(value);
        } else if (option.equals(GSSConstants.REQUIRE_CLIENT_AUTH)) {
            setRequireClientAuth(value);
/*DEL
        } else if (option.equals(GSSConstants.GRIM_POLICY_HANDLER)) {
            setGrimPolicyHandler(value);
*/
        } else if (option.equals(GSSConstants.TRUSTED_CERTIFICATES)) {
            // setTrustedCertificates(value);
            throw new GSSException(GSSException.UNAVAILABLE);
        } else if (option.equals(GSSConstants.PROXY_POLICY_HANDLERS)) {
            setProxyPolicyHandlers(value);
        } else if (option.equals(GSSConstants.ACCEPT_NO_CLIENT_CERTS)) {
            setAcceptNoClientCerts(value);
        } else if (option.equals(GSSConstants
                                 .AUTHZ_REQUIRED_WITH_DELEGATION)) {
            setRequireAuthzWithDelegation(value);
        } else if (option.equals(GSSConstants
                     .FORCE_SSLV3_AND_CONSTRAIN_CIPHERSUITES_FOR_GRAM)) {
            setForceSslV3AndConstrainCipherSuitesForGram(value);
        } else {
            throw new GlobusGSSException(GSSException.FAILURE, 
                                         GlobusGSSException.UNKNOWN_OPTION,
                                         "unknownOption",
                                         new Object[] {option});
        }
    }
    
    public Object getOption(Oid option) 
        throws GSSException {
        if (option == null) {
            throw new GlobusGSSException(GSSException.FAILURE, 
                                         GlobusGSSException.BAD_ARGUMENT,
                                         "nullOption");
        }
        
        if (option.equals(GSSConstants.GSS_MODE)) {
            return this.gssMode;
        } else if (option.equals(GSSConstants.DELEGATION_TYPE)) {
            return this.delegationType;
        } else if (option.equals(GSSConstants.CHECK_CONTEXT_EXPIRATION)) {
            return this.checkContextExpiration;
        } else if (option.equals(GSSConstants.REJECT_LIMITED_PROXY)) {
            return this.rejectLimitedProxy;
        } else if (option.equals(GSSConstants.REQUIRE_CLIENT_AUTH)) {
            return this.requireClientAuth;
        } else if (option.equals(GSSConstants.TRUSTED_CERTIFICATES)) {
            // return this.tc;
            throw new GSSException(GSSException.UNAVAILABLE);
        } else if (option.equals(GSSConstants.PROXY_POLICY_HANDLERS)) {
            // return this.proxyPolicyHandlers;
            throw new GSSException(GSSException.UNAVAILABLE);
        } else if (option.equals(GSSConstants.ACCEPT_NO_CLIENT_CERTS)) {
            return this.acceptNoClientCerts;
        }
        
        return null;
    }

    /**
     * Initiate the delegation of a credential.
     *
     * This function drives the initiating side of the credential
     * delegation process. It is expected to be called in tandem with the
     * {@link #acceptDelegation(int, byte[], int, int) acceptDelegation}
     * function.
     * <BR>
     * The behavior of this function can be modified by 
     * {@link GSSConstants#DELEGATION_TYPE GSSConstants.DELEGATION_TYPE} 
     * and 
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE} context
     * options. 
     * The {@link GSSConstants#DELEGATION_TYPE GSSConstants.DELEGATION_TYPE}
     * option controls delegation type to be performed. The
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE} 
     * option if set to 
     * {@link GSIConstants#MODE_SSL GSIConstants.MODE_SSL}
     * results in tokens that are not wrapped.
     * 
     * @param credential
     *        The credential to be delegated. May be null
     *        in which case the credential associated with the security
     *        context is used.
     * @param mechanism
     *        The desired security mechanism. May be null.
     * @param lifetime
     *        The requested period of validity (seconds) of the delegated
     *        credential. 
     * @return A token that should be passed to <code>acceptDelegation</code> if 
     *         <code>isDelegationFinished</code> returns false. May be null.
     * @exception GSSException containing the following major error codes: 
     *            <code>GSSException.FAILURE</code>
     */
    public byte[] initDelegation(GSSCredential credential, 
                                 Oid mechanism,
                                 int lifetime,
                                 byte[] buf, int off, int len) 
        throws GSSException {

        logger.debug("Enter initDelegation: " + delegationState);

        if (mechanism != null && !mechanism.equals(getMech())) {
            throw new GSSException(GSSException.BAD_MECH);
        }

        if (this.gssMode != GSIConstants.MODE_SSL && buf != null && len > 0) {
            buf = unwrap(buf, off, len);
            off = 0;
            len = buf.length;
        }
        
        byte [] token = null;

        switch (delegationState) {

        case DELEGATION_START:

            this.delegationFinished = false;
            token = DELEGATION_TOKEN;
            this.delegationState = DELEGATION_SIGN_CERT;
            break;

        case DELEGATION_SIGN_CERT:

            ByteArrayInputStream inData
                = new ByteArrayInputStream(buf, off, len);
            
            if (credential == null) {
                // get default credential
                GSSManager manager = new GlobusGSSManagerImpl();
                credential = manager.createCredential(GSSCredential.INITIATE_AND_ACCEPT);
            }

            if (!(credential instanceof GlobusGSSCredentialImpl)) {
                throw new GSSException(GSSException.DEFECTIVE_CREDENTIAL);
            }

            X509Credential cred = 
                ((GlobusGSSCredentialImpl)credential).getX509Credential();

            X509Certificate [] chain = cred.getCertificateChain();
            
            int time = (lifetime == GSSCredential.DEFAULT_LIFETIME) ? -1 : lifetime;
            
            try {
                X509Certificate cert = 
                    this.certFactory.createCertificate(inData,
                                                       chain[0],
                                                       cred.getPrivateKey(),
                                                       time,
/*DEL
                                                       getDelegationType(chain[0]));
*/
                                                       BouncyCastleCertProcessingFactory.decideProxyType(chain[0], this.delegationType));
                
                ByteArrayOutputStream out 
                    = new ByteArrayOutputStream();

                out.write(cert.getEncoded());
                for (int i=0;i<chain.length;i++) {
                    out.write(chain[i].getEncoded());
                }

                token = out.toByteArray();
            } catch (Exception e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }
            
            this.delegationState = DELEGATION_START;
            this.delegationFinished = true;
            break;

        default:
            throw new GSSException(GSSException.FAILURE);
        }

        logger.debug("Exit initDelegation");
        
        if (this.gssMode != GSIConstants.MODE_SSL && token != null) {
            // XXX: Why wrap() only when not in MODE_SSL?
            return wrap(token, 0, token.length);
        } else {
            return token;
        }
    }

    /**
     * Accept a delegated credential.
     *
     * This function drives the accepting side of the credential
     * delegation process. It is expected to be called in tandem with the
     * {@link #initDelegation(GSSCredential, Oid, int, byte[], int, int) 
     * initDelegation} function.
     * <BR>
     * The behavior of this function can be modified by 
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE} context
     * option. The
     * {@link GSSConstants#GSS_MODE GSSConstants.GSS_MODE} 
     * option if set to 
     * {@link GSIConstants#MODE_SSL GSIConstants.MODE_SSL}
     * results in tokens that are not wrapped.
     *
     * @param lifetime
     *        The requested period of validity (seconds) of the delegated
     *        credential. 
     * @return A token that should be passed to <code>initDelegation</code> if 
     *        <code>isDelegationFinished</code> returns false. May be null.
     * @exception GSSException containing the following major error codes: 
     *            <code>GSSException.FAILURE</code>
     */
    public byte[] acceptDelegation(int lifetime,
                                   byte[] buf, int off, int len)
        throws GSSException {

        logger.debug("Enter acceptDelegation: " + delegationState);
        
        if (this.gssMode != GSIConstants.MODE_SSL && buf != null && len > 0) {
            buf = unwrap(buf, off, len);
            off = 0;
            len = buf.length;
        }

        byte [] token = null;

        switch (delegationState) {

        case DELEGATION_START:

            this.delegationFinished = false;

            if (len != 1 && buf[off] != GSIConstants.DELEGATION_CHAR) {
                throw new GlobusGSSException(GSSException.FAILURE,
                                             GlobusGSSException.DELEGATION_ERROR,
                                             "delegError00",
                                             new Object[] {new Character((char)buf[off])});
            }
            
            try {
/*DEL
                Vector certChain = this.conn.getCertificateChain();
*/
		Certificate[] certChain;
		try {
		    certChain = this.sslEngine.getSession().getPeerCertificates();
		} catch (SSLPeerUnverifiedException e) {
                    certChain = null;
                }
                if (certChain == null || certChain.length == 0) {
                    throw new GlobusGSSException(GSSException.FAILURE, 
                                                 GlobusGSSException.DELEGATION_ERROR,
                                                 "noClientCert");
                }
            
                X509Certificate tmpCert = 
/*DEL
                    PureTLSUtil.convertCert((X509Cert)certChain.lastElement());
*/
                    (X509Certificate) certChain[0];

                token = generateCertRequest(tmpCert);
            } catch (GeneralSecurityException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

            this.delegationState = DELEGATION_COMPLETE_CRED;
            break;
            
        case DELEGATION_COMPLETE_CRED:

            ByteArrayInputStream in = 
                new ByteArrayInputStream(buf, off, len);

            X509Certificate [] chain = null;
            LinkedList certList = new LinkedList();
            X509Certificate cert = null;
            try {
                while(in.available() > 0) {
                    cert = CertificateLoadUtil.loadCertificate(in);
                    certList.add(cert);
                }

                chain = new X509Certificate[certList.size()];
                chain = (X509Certificate[])certList.toArray(chain);

                verifyDelegatedCert(chain[0]);

            } catch (GeneralSecurityException e) {
                throw new GlobusGSSException(GSSException.FAILURE, e);
            }

            X509Credential proxy = 
                new X509Credential(this.keyPair.getPrivate(), chain);

            this.delegatedCred = 
                new GlobusGSSCredentialImpl(proxy, 
                                            GSSCredential.INITIATE_AND_ACCEPT);

            this.delegationState = DELEGATION_START;
            this.delegationFinished = true;
            break;

        default:
            throw new GSSException(GSSException.FAILURE);
        }

        logger.debug("Exit acceptDelegation");

        if (this.gssMode != GSIConstants.MODE_SSL && token != null) {
            // XXX: Why wrap() only when not in MODE_SSL?
            return wrap(token, 0, token.length);
        } else {
            return token;
        }
    }

    public GSSCredential getDelegatedCredential() {
        return this.delegatedCred;
    }
    
    public boolean isDelegationFinished() {
        return this.delegationFinished;
    }

    /**
     * Retrieves arbitrary data about this context.
     * Currently supported oid: <UL>
     * <LI>
     * {@link GSSConstants#X509_CERT_CHAIN GSSConstants.X509_CERT_CHAIN}
     * returns certificate chain of the peer (<code>X509Certificate[]</code>).
     * </LI>
     * </UL>
     *
     * @param oid the oid of the information desired.
     * @return the information desired. Might be null.
     * @exception GSSException containing the following major error codes: 
     *            <code>GSSException.FAILURE</code>
     */
    public Object inquireByOid(Oid oid) 
        throws GSSException {
        if (oid == null) {
            throw new GlobusGSSException(GSSException.FAILURE, 
                                         GlobusGSSException.BAD_ARGUMENT,
                                         "nullOption");
        }
        
        if (oid.equals(GSSConstants.X509_CERT_CHAIN)) {
            if (isEstablished()) {
                // converting certs is slower but keeping coverted certs
                // takes lots of memory.
                try {
/*DEL
                    Vector peerCerts = this.conn.getCertificateChain();
*/
                    Certificate[] peerCerts;
		    try {
			peerCerts = this.sslEngine.getSession().getPeerCertificates();
		    } catch (SSLPeerUnverifiedException e) {
			peerCerts = null;
		    }
                    if (peerCerts != null && peerCerts.length > 0) {
/*DEL
                        return PureTLSUtil.certificateChainToArray(peerCerts);
*/
                        return (X509Certificate[])peerCerts;
                    } else {
                        return null;
                    }
                } catch (Exception e) {
                    throw new GlobusGSSException(
                             GSSException.DEFECTIVE_CREDENTIAL,
                             e
                    );
                }
            }
        } else if (oid.equals(GSSConstants.RECEIVED_LIMITED_PROXY)) {
            return this.peerLimited;
        }
        
        return null;
    }


    // ==================================================================
    // Not implemented below
    // ==================================================================
    
    /**
     * Currently not implemented.
     */
    public int getWrapSizeLimit(int qop, boolean confReq,
                                int maxTokenSize) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public void wrap(InputStream inStream, OutputStream outStream,
                     MessageProp msgProp) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public void unwrap(InputStream inStream, OutputStream outStream,
                       MessageProp msgProp) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public void getMIC(InputStream inStream, OutputStream outStream,
                       MessageProp msgProp) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }
 
    /**
     * Currently not implemented.
     */
    public void verifyMIC(InputStream tokStream, InputStream msgStream,
                          MessageProp msgProp) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public void setChannelBinding(ChannelBinding cb) 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }
 
    /**
     * Currently not implemented.
     */
    public boolean isTransferable() 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public byte [] export() 
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE);
    }
    
}
