/*
 * Copyright 1999-2006 University of Chicago
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
package org.globus.gram;

import java.util.Hashtable;
import java.util.Enumeration;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.MalformedURLException;

import org.globus.util.http.HttpResponse;
import org.globus.util.deactivator.Deactivator;
import org.globus.util.deactivator.DeactivationHandler;
import org.globus.util.GlobusURL;
import org.globus.common.ResourceManagerContact;
import org.globus.gram.internal.GRAMProtocol;
import org.globus.gram.internal.GRAMConstants;
import org.globus.gram.internal.GatekeeperReply;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.gssapi.SSLUtil;
import org.globus.gsi.gssapi.GSSConstants;
import org.globus.gsi.gssapi.net.GssSocket;
import org.globus.gsi.gssapi.net.GssSocketFactory;
import org.globus.gsi.gssapi.net.impl.GSIGssOutputStream;
import org.globus.gsi.gssapi.net.impl.GSIGssInputStream;
import org.globus.gsi.gssapi.auth.GSSAuthorization;
import org.globus.gsi.gssapi.auth.IdentityAuthorization;
import org.globus.gsi.gssapi.auth.HostAuthorization;
import org.globus.gsi.gssapi.auth.SelfAuthorization;
import org.globus.gsi.gssapi.auth.NoAuthorization;

import org.gridforum.jgss.ExtendedGSSManager;
import org.gridforum.jgss.ExtendedGSSContext;

import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/** 
 * This is the main class for using the Globus GRAM API
 * It implements all of the GRAM API functionality such as
 * job submission, canceling, gatekeeper pinging, and job
 * signaling. It also allows for callback registering and
 * unregistering.
 */
public class Gram  {

    private static Log logger =
	LogFactory.getLog(Gram.class.getName());

    private static Socket gatekeeperConnect(GSSCredential cred,
					    ResourceManagerContact rmc,
					    boolean doDel,
					    boolean limitedDelegation)
	throws GSSException, GramException {
	
        GSSAuthorization auth = null;
        String authDN = rmc.getDN();
        if (authDN != null) {
            auth = new IdentityAuthorization(authDN);
        } else {
            auth = HostAuthorization.getInstance();
        }

	GSSManager manager = ExtendedGSSManager.getInstance();
	
	try {
        
		
		GSSName name = auth.getExpectedName(cred, rmc.getHostName());
 
	    ExtendedGSSContext context = 
		(ExtendedGSSContext)manager.createContext(name, 
							  GSSConstants.MECH_OID,
							  cred,
							  GSSContext.DEFAULT_LIFETIME);
	    
	    context.requestCredDeleg(doDel);
	
	    context.setOption(GSSConstants.DELEGATION_TYPE,
			      (limitedDelegation) ? 
			      GSIConstants.DELEGATION_TYPE_LIMITED :
			      GSIConstants.DELEGATION_TYPE_FULL);
	
	    GssSocketFactory factory = GssSocketFactory.getDefault();
	    
	    GssSocket socket = 
		(GssSocket)factory.createSocket(rmc.getHostName(), 
						rmc.getPortNumber(),
						context);
	    
            socket.setAuthorization(NoAuthorization.getInstance());

	    return socket;
	} catch(IOException e) {
	    throw new GramException(GramException.ERROR_CONNECTION_FAILED, e);
	}
    }

    /**    */
    private static void checkProtocolVersion(int protocolVersion) 
	throws GramException {
	if (protocolVersion != GRAMProtocol.GRAM_PROTOCOL_VERSION) {
	    throw new GramException(GramException.VERSION_MISMATCH);
	}
    }

    /**    
     * @exception GramException 
     * @param code 
     */
    private static void checkHttpReply(int code) 
	throws GramException {
	
	if (code == 200) {
	    return;
	} else if (code == 400) {
	    throw new GramException(GramException.PROTOCOL_FAILED);
	} else if (code == 403) {
	    throw new GramException(GramException.ERROR_AUTHORIZATION);
	} else if (code == 404) {
	    throw new GramException(GramException.ERROR_SERVICE_NOT_FOUND);
	} else if (code == 500) {
	    throw new GramException(GramException.GATEKEEPER_MISCONFIGURED);
	} else {
	    // from globus code
	    throw new GramException(GramException.HTTP_UNFRAME_FAILED,
				    new Exception("Unexpected reply: " + 
						  code));
	}
	
    }
  
    /** Returns total number of jobs currently running 
     * for all credentials -- all callback handlers
     *
     * @return number of jobs running
     */
    public static int getActiveJobs() {
	int jobs = 0;
	Enumeration e = callbackHandlers.elements();
	while(e.hasMoreElements()) {
	    CallbackHandler handler = (CallbackHandler)e.nextElement();
	    jobs += handler.getRegisteredJobsSize();
	}
	return jobs;
    }
  
    /** Returns number of jobs currently running
     * for a specified credential (one credential one callback handler)
     * 
     * @return number of jobs running for given credential
     */
    public static int getActiveJobs(GSSCredential cred) {
	if (cred == null) {
	    throw new IllegalArgumentException("cred == null");
	}
	CallbackHandler handler = (CallbackHandler)callbackHandlers.get(cred);
	return (handler == null) ? 0 : handler.getRegisteredJobsSize();
    }
    

    // ----------- GATEKEEPER CALLS ---------------------------
    
    /** 
     * Performs ping operation on the gatekeeper with
     * default user credentials.
     * Verifies if the user is authorized to submit a job
     * to that gatekeeper.
     * 
     * @throws GramException if an error occurs or user in unauthorized
     * @param resourceManagerContact resource manager contact
     */
    public static void ping(String resourceManagerContact) 
	throws GramException, GSSException {
    	ping(null, resourceManagerContact);
    }
  
    /** 
     * Performs ping operation on the gatekeeper with
     * specified user credentials.
     * Verifies if the user is authorized to submit a job
     * to that gatekeeper.
     * 
     * @throws GramException if an error occurs or user in unauthorized
     * @param cred user credentials
     * @param resourceManagerContact resource manager contact
     */
    public static void ping(GSSCredential cred, String resourceManagerContact) 
	throws GramException, GSSException {
	 
	ResourceManagerContact rmc = 
	    new ResourceManagerContact(resourceManagerContact);
	Socket socket = gatekeeperConnect(cred, rmc, false, false);
	
	HttpResponse hd = null;

	try {
	    OutputStream out = socket.getOutputStream();
	    InputStream in   = socket.getInputStream();
	    
	    String msg = GRAMProtocol.PING(rmc.getServiceName(),
					   rmc.getHostName());

	    // send message
	    out.write(msg.getBytes());
	    out.flush();
	    
	    debug("PG SENT:", msg);
	    
	    // receive reply
	    hd = new HttpResponse(in);
	    
	} catch(IOException e) {
	    throw new GramException(GramException.ERROR_PROTOCOL_FAILED, e);
	} finally {
	    try { socket.close(); } catch (Exception e) {}
	}
	
	debug("PG RECEIVED:", hd);
	
	checkHttpReply(hd.httpCode);
    }
    
    /** 
     * Submits a GramJob to specified gatekeeper as an
     * interactive job. Performs limited delegation.
     * 
     * @throws GramException if an error occurs during submisson
     * @param resourceManagerContact resource manager contact
     * @param job gram job
     */
    public static void request(String resourceManagerContact,
			       GramJob job) 
	throws GramException, GSSException {
	request(resourceManagerContact, job, false);	 
    }
    
    /**
     * Submits a GramJob to specified gatekeeper as
     * a interactive or batch job. Performs limited delegation.
     *
     * @throws GramException if an error occurs during submisson
     * @param resourceManagerContact resource manager contact
     * @param job gram job
     * @param batchJob true if batch job, interactive otherwise
     */
    public static void request(String resourceManagerContact,
			       GramJob job,
			       boolean batchJob)
	throws GramException, GSSException {
	request(resourceManagerContact, job, batchJob, true);
    }

    /** 
     * Submits a GramJob to specified gatekeeper as
     * a interactive or batch job.
     * 
     * @throws GramException if an error occurs during submisson
     * @param resourceManagerContact 
     *        resource manager contact
     * @param job 
     *        gram job
     * @param batchJob 
     *        true if batch job, interactive otherwise.
     * @param limitedDelegation
     *        true for limited delegation, false for full delegation.
     *        limited delegation should be the default option.
     */
    public static void request(String resourceManagerContact,
			       GramJob job,
			       boolean batchJob,
			       boolean limitedDelegation) 
	throws GramException, GSSException {
	 
	GSSCredential cred = getJobCredentials(job);

	// at this point proxy cannot be null

	String callbackURL      = null;
	CallbackHandler handler = null;
	
	if (!batchJob) { 
	    handler = initCallbackHandler(cred);
	    callbackURL = handler.getURL();
	    logger.debug("Callback url: " + callbackURL);
	} else {
	    callbackURL = "\"\"";
	}
	 
	ResourceManagerContact rmc = 
	    new ResourceManagerContact(resourceManagerContact);
	 
	Socket socket = gatekeeperConnect(cred, rmc, true, limitedDelegation);

	GatekeeperReply hd = null;

	try {
	    OutputStream out = socket.getOutputStream();
	    InputStream in   = socket.getInputStream();

	    String msg = GRAMProtocol.REQUEST(rmc.getServiceName(),
					      rmc.getHostName(),
					      GRAMConstants.STATUS_ALL,
					      callbackURL,
					      job.getRSL());
	     
	    // send message
	    out.write(msg.getBytes());
	    out.flush();

	    debug("REQ SENT:", msg);

	    // receive reply
	    hd = new GatekeeperReply(in);

	} catch(IOException e) {
	    throw new GramException(GramException.ERROR_PROTOCOL_FAILED, e);
	} finally {
	    try { socket.close(); } catch (Exception e) {}
	}

	debug("REQ RECEIVED:", hd);

	// must be 200
	checkHttpReply(hd.httpCode);
	
	// protocol version must match
	checkProtocolVersion(hd.protocolVersion);
	
	if (hd.status == 0 || hd.status == GramException.WAITING_FOR_COMMIT) {
	    try {
		job.setID( hd.jobManagerUrl );
	    } catch(MalformedURLException ex) {
		throw new GramException(GramException.INVALID_JOB_CONTACT, ex);
	    }
	    if (!batchJob) handler.registerJob(job);	    
	    if (hd.status == GramException.WAITING_FOR_COMMIT) {
                throw new WaitingForCommitException();
            }
	} else {
	    throw new GramException(hd.status);
	}
    }

    // --------------------- JOB MANAGER CALLS --------------------------------
    
    private static GatekeeperReply jmConnect(GSSCredential cred, 
					     GlobusURL jobURL, 
					     String msg) 
	throws GramException, GSSException {

	GSSManager manager = ExtendedGSSManager.getInstance();
	
	GatekeeperReply reply = null;
	GssSocket socket = null;

	try {

	    ExtendedGSSContext context = 
		(ExtendedGSSContext)manager.createContext(null,
							  GSSConstants.MECH_OID,
							  cred,
							  GSSContext.DEFAULT_LIFETIME);

	    context.setOption(GSSConstants.GSS_MODE,
			      GSIConstants.MODE_SSL);
	
	    GssSocketFactory factory = GssSocketFactory.getDefault();
	
	    socket = (GssSocket)factory.createSocket(jobURL.getHost(), 
						     jobURL.getPort(),
						     context);
	    
	    socket.setAuthorization(SelfAuthorization.getInstance());
	    
	    OutputStream out = socket.getOutputStream();
	    InputStream in   = socket.getInputStream();
	    
	    out.write(msg.getBytes());
	    out.flush();
	    
	    debug("JM SENT:", msg);
	    
	    reply = new GatekeeperReply(in);

	} catch(IOException e) {
	    throw new GramException(GramException.ERROR_CONNECTION_FAILED, e);
	} finally {
	    if (socket != null) {
		try { socket.close(); } catch (Exception e) {}
	    }
	}

	debug("JM RECEIVED:", reply);

	// must be 200 otherwise throw exception
	checkHttpReply(reply.httpCode);
	
	// protocol version must match
	checkProtocolVersion(reply.protocolVersion);
	
	return reply;
    }

    /** 
     * Frames and wraps a token according to the GRAM "renew" protocol
     * for use in a GSI delegation handshake.  The input token is framed with
     * a 4 byte big-endian token length header, and the resulting framed token
     * wrapped in SSL mode (GSSContext's GSS_MODE option set to MODE_SSL)
     * 
     * @param c The context used to wrap the token
     * @param token The unaltered output of the context's initDelegation
     * @throws GSSException if an error occurs during token wrapping or if
     * context is insufficient
     * @return a wrapped, framed token to send to globus job manager
     */
    private static byte[] produceRenewToken(ExtendedGSSContext c,
                                            byte[] token)
        throws GSSException {
        if (!GSIConstants.MODE_SSL.equals(c.getOption(GSSConstants.GSS_MODE))) {
            throw new GSSException(GSSException.NO_CONTEXT);
        }
        byte[] framedToken = new byte[token.length + 4];
        SSLUtil.writeInt(token.length, framedToken, 0);
        System.arraycopy(token, 0, framedToken, 4, token.length);
        return c.wrap(framedToken, 0, framedToken.length, null);
    }

    /** 
     * Unwraps and discards frame of a token according to the GRAM "renew"
     * protocol for use in a GSI delegation handshake.  The input token is
     * received from a globus job manager and comes wrapped (SSL mode) and
     * framed with a 4 byte big-endian token length header.
     * 
     * @param c The context to use to unwrap the token
     * @param wrappedToken Token received from job manager during GSI handshake
     * @throws GSSException if an error occurs during token wrapping or if
     * context is insufficient
     * @return a token that can be passed to the context's next initDelegation
     */
    private static byte[] consumeRenewToken(ExtendedGSSContext c,
                                            byte[] wrappedToken)
        throws GSSException {
        if (!GSIConstants.MODE_SSL.equals(c.getOption(GSSConstants.GSS_MODE))) {
            throw new GSSException(GSSException.NO_CONTEXT);
        }
        byte[] framedToken = c.unwrap(wrappedToken, 0,
                                      wrappedToken.length, null);
        byte[] token = new byte[framedToken.length - 4];
        System.arraycopy(framedToken, 4, token, 0, framedToken.length - 4);
        return token;
    }

    /** 
     * Completes a GSI delegation handshake with a globus job manager
     * that has agreed to a (previously sent) GRAM "renew" request.  After
     * the job manager receives the last token in the handshake, it responds
     * with a message following the GRAM protocol indicating delegation success
     * or failure.
     * 
     * @param context Previously established context with job manager
     * @param newCred The credential used to generate a new delegated proxy
     * @param out Stream used to send messages to job manager
     * @param in Stream used to receive messages from job manager
     * @throws GSSException if an error occurs during token wrapping/unwrapping
     * @throws IOException if a communication error occurs
     * @return the GRAM response message indicating delegation status
     */
    private static GatekeeperReply renewDelegationHandshake(
                                                ExtendedGSSContext context,
                                                GSSCredential newCred,
                                                GSIGssOutputStream out,
                                                GSIGssInputStream in)
        throws GSSException, IOException {
        byte [] input = new byte[0];
        byte [] output = null;

        do {
            output = produceRenewToken(context, context.initDelegation(
                                                    newCred, null, 0, input,
                                                    0, input.length));
            out.writeToken(output);
            if (!context.isDelegationFinished()) {
                input = consumeRenewToken(context, in.readHandshakeToken());
            }
        } while (!context.isDelegationFinished());
        GatekeeperReply reply = new GatekeeperReply(in);
        return reply;
    }

    /**
     * Requests that a globus job manager accept newly delegated credentials.
       Uses limited delegation.
     *
     * @param job The job whose credentials are to be renewed/refreshed
     * @param newCred The credentials to use in the delegation process
     * @throws GSSException if a GSSAPI error occurs
     * @throws GramException if a connection/communication error occurs or if
     * delegation failed
     */
    public static void renew(GramJob job, GSSCredential newCred)
        throws GramException, GSSException {
        renew(job, newCred, true);
    }

    /** 
     * Requests that a globus job manager accept newly delegated credentials.
     * This consists of a "renew" message in the GRAM protocol followed by a
     * GSI delegation handshake using wrapped/framed tokens.  Upon successful
     * delegation, the job's credentials are set to the ones used in delegation.
     * 
     * @param job The job whose credentials are to be renewed/refreshed
     * @param newCred The credentials to use in the delegation process
     * @param limitedDelegation Whether to use a full or limited proxy
     * @throws GSSException if a GSSAPI error occurs
     * @throws GramException if a connection/communication error occurs or if
     * delegation failed
     */
    public static void renew(GramJob job, GSSCredential newCred,
                             boolean limitedDelegation)
        throws GramException, GSSException {
        GSSCredential currentCred = getJobCredentials(job);
        GlobusURL jobURL = job.getID();
        if (jobURL == null) {
            throw new GramException(GramException.ERROR_JOB_CONTACT_NOT_SET);
        }

        GSSManager manager = ExtendedGSSManager.getInstance();
        GssSocket socket = null;

        try {
            ExtendedGSSContext context =
                (ExtendedGSSContext)manager.createContext(null,
                                        GSSConstants.MECH_OID, currentCred,
                                        GSSContext.DEFAULT_LIFETIME);
            context.setOption(GSSConstants.GSS_MODE, GSIConstants.MODE_SSL);
            context.setOption(GSSConstants.DELEGATION_TYPE,
                                (limitedDelegation) ?
                                GSIConstants.DELEGATION_TYPE_LIMITED :
                                GSIConstants.DELEGATION_TYPE_FULL);

            GssSocketFactory factory = GssSocketFactory.getDefault();
            socket = (GssSocket)factory.createSocket(jobURL.getHost(),
                                        jobURL.getPort(), context);
            socket.setAuthorization(SelfAuthorization.getInstance());

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // send GRAM protocol "renew"
            String msg = GRAMProtocol.RENEW(jobURL.getURL(), jobURL.getHost());
            out.write(msg.getBytes());
            out.flush();
            debug("RENEW SENT:", msg);
            GatekeeperReply reply = new GatekeeperReply(in);
            debug("RENEW RECEIVED:", reply);
            // proceed w/ delegation only if response looks ok
            checkHttpReply(reply.httpCode);
            if (reply.failureCode == GramException.JOB_CONTACT_NOT_FOUND) {
                throw new GramException(GramException.JOB_CONTACT_NOT_FOUND);
            }

            reply = renewDelegationHandshake(context, newCred,
                                             (GSIGssOutputStream) out,
                                             (GSIGssInputStream) in);

            debug("RENEW RECEIVED: ", reply);
            checkHttpReply(reply.httpCode);
            if (reply.failureCode == GramException.DELEGATION_FAILED) {
                throw new GramException(GramException.DELEGATION_FAILED);
            }
            job.setCredentials(newCred);
        }
        catch (IOException e) {
            throw new GramException(GramException.ERROR_CONNECTION_FAILED, e);
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) {}
            }
        }
    }

    /** 
     * This function cancels an already running job.
     * 
     * @throws GramException if an error occurs during cancel
     * @param job job to be canceled
     */
    public static void cancel(GramJob job)
	throws GramException, GSSException {
      
	GlobusURL jobURL  = job.getID();

	if (jobURL == null) {
	    throw new GramException(GramException.ERROR_JOB_CONTACT_NOT_SET);
	}

	GSSCredential cred = getJobCredentials(job);
	
	String msg = GRAMProtocol.CANCEL_JOB(jobURL.getURL(),
					     jobURL.getHost());
	
	GatekeeperReply reply = jmConnect(cred,
					  jobURL,
					  msg);

	if (reply.failureCode != 0) {
            throw new GramException(reply.failureCode);
        }

	// this might need to be fixed
	// if (handler != null) handler.unregisterJob(jobContact);
    }
  
    /** 
     * This function updates the status of a job (within the job object),
     * and throws an exception if the status is not OK. If the
     * job manager cannot be contacted the job error code is
     * set to GramException.ERROR_CONTACTING_JOB_MANAGER and an 
     * exception with the same error code is thrown.
     * 
     * @throws GramException if an error occurs during status update.
     * @param job the job whose status is to be updated.
     */
    public static void jobStatus(GramJob job) 
	throws GramException, GSSException {
      
	GlobusURL jobURL  = job.getID();
	GSSCredential cred = getJobCredentials(job);
	
	String msg = GRAMProtocol.STATUS_POLL(jobURL.getURL(),
					      jobURL.getHost());
	
	GatekeeperReply hd = null;
      
	try {
	    hd = jmConnect(cred, jobURL, msg);
	} catch(GramException e) {
	    // this is exactly what C does
	    if (e.getErrorCode() == GramException.ERROR_CONNECTION_FAILED) {
		job.setError( GramException.ERROR_CONTACTING_JOB_MANAGER );	
		e.setErrorCode( GramException.ERROR_CONTACTING_JOB_MANAGER );
	    }
	    throw e;
	}
	
	// We didn't seem to care much about setting things 
	// before the status here, presumably because of the
	// assumption that, when polling, listeners are not used
	// on the GramJob. I disagree. There is no good reason
	// why that couldn't happen
	job.setExitCode( hd.exitCode );
	job.setError( hd.failureCode );
	job.setStatus( hd.status );
    }
  
    /** 
     * This function sends a signal to a job.
     * 
     * @throws GramException if an error occurs during cancel
     * @param job the signaled job
     * @param signal type of the signal
     * @param arg argument of the signal
     */
    public static int jobSignal(GramJob job, int signal, String arg)
	throws GramException, GSSException {

	GlobusURL jobURL  = job.getID();
	GSSCredential cred = getJobCredentials(job);
	
	String msg = GRAMProtocol.SIGNAL(jobURL.getURL(),
					 jobURL.getHost(),
					 signal,
					 arg);

	GatekeeperReply hd = null;
	
	hd = jmConnect(cred, jobURL, msg);
	
	switch(signal) {
	case GramJob.SIGNAL_PRIORITY:
	    return hd.failureCode;
	case GramJob.SIGNAL_STDIO_SIZE:
	case GramJob.SIGNAL_STDIO_UPDATE:
	case GramJob.SIGNAL_COMMIT_REQUEST:
	case GramJob.SIGNAL_COMMIT_EXTEND:
	case GramJob.SIGNAL_COMMIT_END:
	case GramJob.SIGNAL_STOP_MANAGER:
	    if (hd.failureCode != 0 && hd.status == GramJob.STATUS_FAILED) {
		throw new GramException(hd.failureCode);
	    } else if (hd.failureCode == 0 && hd.jobFailureCode != 0) {
		job.setError( hd.jobFailureCode );
		job.setStatus(GramJob.STATUS_FAILED);
		return hd.failureCode;
	    } else {
		job.setStatus(hd.status);
		return 0;
	    }
	default:
	    job.setStatus( hd.status );
	    job.setError( hd.failureCode );
	    return 0;
	}
    }

    /** 
     * This function registers the job for status updates.
     * 
     * @throws GramException if an error occurs during registration
     * @param job the job
     */
    public static void registerListener(GramJob job) 
	throws GramException, GSSException {

	CallbackHandler handler;

	GSSCredential cred = getJobCredentials(job);

	handler = initCallbackHandler(cred);
	
	registerListener(job, handler);
    }

    public static void registerListener(GramJob job, CallbackHandler handler) 
	throws GramException, GSSException {
	    
	String callbackURL;
	GlobusURL jobURL;

	GSSCredential cred = getJobCredentials(job);
	callbackURL = handler.getURL();
	jobURL = job.getID();
	 
	String msg = GRAMProtocol.REGISTER_CALLBACK(jobURL.getURL(),
						    jobURL.getHost(),
						    GRAMConstants.STATUS_ALL,
						    callbackURL);
	 
	GatekeeperReply hd = jmConnect(cred, jobURL, msg);
	
	if (hd.failureCode == 0) {
	    handler.registerJob(job);	    
	} else {
	    throw new GramException(hd.failureCode);
	}
    }
    
  
    /** 
     * This function unregisters the job from callback
     * listener. The job status will not be updated.
     * 
     * @throws GramException if an error occurs during unregistering
     * @param job the job
     */
    public static void unregisterListener(GramJob job) 
	throws GramException, GSSException {

        CallbackHandler handler;

        GSSCredential cred = getJobCredentials(job);

        handler = initCallbackHandler(cred);
	
        unregisterListener(job, handler);
    }

    public static void unregisterListener(GramJob job, CallbackHandler handler)
        throws GramException, GSSException {
	
	GlobusURL jobURL;

	GSSCredential cred = getJobCredentials(job);
	jobURL = job.getID();
	
	String msg = GRAMProtocol.UNREGISTER_CALLBACK(jobURL.getURL(),
						      jobURL.getHost(),
						      handler.getURL());
	
	GatekeeperReply reply = jmConnect(cred, jobURL, msg);
	
	handler.unregisterJob(job);
    }
    

    /**
     * Deactivates all callback handlers.
     */
    public static void deactivateAllCallbackHandlers() {
	synchronized(callbackHandlers) {
	    Enumeration e = callbackHandlers.elements();
	    while(e.hasMoreElements()) {
		CallbackHandler handler = (CallbackHandler)e.nextElement();
		handler.shutdown();
	    }
	    callbackHandlers.clear();
	}
    }

    /**
     * Deactivates a callback handler for a given credential.
     *
     * @param cred the credential of the callback handler.
     * @return the callback handler that was deactivated. Null, 
     *         if no callback handler is associated with the credential
     */
    public static CallbackHandler deactivateCallbackHandler(GSSCredential cred) {
	if (cred == null) {
	    return null;
	}
	CallbackHandler handler = 
	    (CallbackHandler)callbackHandlers.remove(cred);
	if (handler == null) {
	    return null;
	}
	handler.shutdown();
	return handler;
    }

    // -------- INTERNAL CALLBACK STUFF -----------------------
  
    /**    */
    protected static Hashtable callbackHandlers = new Hashtable();
    
    static {
	Deactivator.registerDeactivation(new DeactivationHandler() {
		public void deactivate() {
		    Gram.deactivateAllCallbackHandlers();
		}
	    });
    }

    /**    */
    private static synchronized CallbackHandler initCallbackHandler(GSSCredential cred)
	throws GSSException, GramException {
	if (cred == null) {
	    throw new IllegalArgumentException("cred == null");
	}

	CallbackHandler handler = (CallbackHandler)callbackHandlers.get(cred);
	
	if (handler == null) {
	    try {
		handler = new CallbackHandler(cred, 0);	
		// sets socket timeout to max cred lifetime
		handler.setTimeout(cred.getRemainingLifetime());
		callbackHandlers.put(cred, handler);
	    } catch(IOException e) {
		throw new GramException(GramException.INIT_CALLBACK_HANDLER_FAILED, e);
	    }
	}
	
	return handler;
    }

    /**    */
    private static GSSCredential getJobCredentials(GramJob job) 
	throws GSSException {
	GSSCredential cred = job.getCredentials();
	if (cred == null) {
	    GSSManager manager = ExtendedGSSManager.getInstance();
	    cred = manager.createCredential(GSSCredential.INITIATE_AND_ACCEPT);
	    job.setCredentials(cred);
	}
	return cred;
    }

    // --------- DEBUG CONVINIENCE FUNCTIONS ------------
  
    /** 
     * Debug function for displaying the gatekeeper reply.
     */
    private static void debug(String header, GatekeeperReply reply) {
	if (logger.isTraceEnabled()) {
	    logger.trace(header);
	    logger.trace(reply.toString());
	}
    }
    
    /** 
     * Debug function for displaying HTTP responses.
     */
    private static void debug(String header, HttpResponse response) {
	if (logger.isTraceEnabled()) {
	    logger.trace(header);
	    logger.trace(response.toString());
	}
    }
    
    /** A general debug message that prints the header and msg
     * when the debug level is smaler than 3
     * 
     * @param header The header to be printed
     * @param msg The message to be printed
     */
    private static void debug(String header, String msg) {
	if (logger.isTraceEnabled()) {
	    logger.trace(header);
	    logger.trace(msg);
	}
    }
}
