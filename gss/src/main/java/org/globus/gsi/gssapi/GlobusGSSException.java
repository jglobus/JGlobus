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

import java.io.PrintStream;
import java.io.PrintWriter;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.MissingResourceException;

import org.ietf.jgss.GSSException;

import javax.net.ssl.SSLException;

public class GlobusGSSException extends GSSException {

    private static final long serialVersionUID = 1366868883920091438L;

    public static final int
	PROXY_VIOLATION = 5,
	BAD_ARGUMENT = 7,
	BAD_NAME = 25,
	CREDENTIAL_ERROR = 27,
	TOKEN_FAIL = 29,
	DELEGATION_ERROR = 30,
	BAD_MIC = 33,
	UNKNOWN_OPTION = 37;

    public static final int
	BAD_OPTION_TYPE = 100,
	BAD_OPTION = 101,
	UNKNOWN = 102;

    private static ResourceBundle resources;

    static {
	try {
	    resources = ResourceBundle.getBundle("org.globus.gsi.gssapi.errors");
	} catch (MissingResourceException e) {
	    throw new RuntimeException(e.getMessage());
	}
    }

    private final boolean hasCustomMessage;

    public GlobusGSSException(int majorCode,
			      Throwable cause) {
	super(majorCode);
	initCause(cause);
	hasCustomMessage = false;
    }

    public GlobusGSSException(int majorCode,
			      int minorCode,
			      String minorString,
			      Throwable cause) {
	super(majorCode, minorCode, minorString);
	initCause(cause);
	hasCustomMessage = true;
    }

    public GlobusGSSException(int majorCode,
			      int minorCode,
			      String key) {
	this(majorCode, minorCode, key, (Object[])null);
    }

    public GlobusGSSException(int majorCode,
			      int minorCode,
			      String key,
			      Object [] args) {
	super(majorCode);

	String msg = null;
	try {
	    msg = MessageFormat.format(resources.getString(key), args);
	} catch (MissingResourceException e) {
	    //msg = "No msg text defined for '" + key + "'";
	    throw new RuntimeException("bad" + key);
	}

	setMinor(minorCode, msg);
        initCause(null);
	hasCustomMessage = true;
    }


    /**
     * Prints this exception's stack trace to <tt>System.err</tt>.
     * If this exception has a root exception; the stack trace of the
     * root exception is printed to <tt>System.err</tt> instead.
     */
    @Override
    public void printStackTrace() {
        printStackTrace( System.err );
    }

    /**
     * Prints this exception's stack trace to a print stream.
     * If this exception has a root exception; the stack trace of the
     * root exception is printed to the print stream instead.
     * @param ps The non-null print stream to which to print.
     */
    @Override
    public void printStackTrace(PrintStream ps) {
        if ( getCause() != null ) {
            String superString = getLocalMessage();
            synchronized ( ps ) {
                ps.print(superString);
                ps.print((superString.endsWith(".") ?
                          " Caused by " : ". Caused by "));
                getCause().printStackTrace( ps );
            }
        } else {
            super.printStackTrace( ps );
        }
    }

    /**
     * Prints this exception's stack trace to a print writer.
     * If this exception has a root exception; the stack trace of the
     * root exception is printed to the print writer instead.
     * @param pw The non-null print writer to which to print.
     */
    @Override
    public void printStackTrace(PrintWriter pw) {
        if ( getCause() != null ) {
            String superString = getLocalMessage();
            synchronized (pw) {
                pw.print(superString);
                pw.print((superString.endsWith(".") ?
                          " Caused by " : ". Caused by "));
                getCause().printStackTrace( pw );
            }
        } else {
            super.printStackTrace( pw );
        }
    }

    @Override
    public String getMessage() {
        Throwable cause = getCause();

        if (isBoring(this)) {
            return getUsefulMessage(cause);
        } else {
            StringBuilder message = new StringBuilder(super.getMessage());
            if (cause != null) {
                message.append(" [Caused by: ").append(getUsefulMessage(cause)).append("]");
            }
            return message.toString();
        }
    }

    /**
     * Wrapper around getMessage method that tries to provide a meaningful
     * message.  This is needed because many GSSException objects provide no
     * useful information and the actual useful information is in the Throwable
     * that caused the exception.
     */
    private static String getUsefulMessage(Throwable throwable) {
        while(isBoring(throwable)) {
            throwable = throwable.getCause();
        }

        String message = throwable.getMessage();
        if (message == null) {
            message = throwable.getClass().getName();
        }
        return message;
    }

    /**
     * Use heuristics to determine whether the supplied Throwable has any
     * semantic content (i.e., does it provide any additional information).
     *
     * It seems that many GSSException objects are created with no information.
     * Instead, the useful information is contained within the causing
     * Throwable.
     *
     * Also, an SSLException may be thrown by SSLEngine that wraps some more
     * interesting exception but the message has no information.
     *
     * As part of a work-around for this problem, this method tries to guess
     * whether the supplied Throwable contains useful information.
     *
     * @return true if the Throwable contains no useful information, false
     * otherwise.
     */
    private static boolean isBoring(Throwable t) {

        // Last throwable in the causal chain is never boring.
        if (t.getCause() == null) {
            return false;
        }

        // Some GSSExceptions have no semantic content, therefore boring.
        if (t instanceof GSSException) {
            GSSException g = (GlobusGSSException) t;

            if (g.getMajor() == GSSException.FAILURE && g.getMinor() == 0) {
                if (g instanceof GlobusGSSException) {
                    return !((GlobusGSSException)g).hasCustomMessage;
                } else {
                    // Unfortunately, for GSSException, we must compare the
                    // actual message.
                    return g.getMessage().equals("Failure unspecified at GSS-API level");
                }
            }
        }

        // SSLEngine can return a message with no meaning, therefore boring.
        if (t instanceof SSLException &&
                t.getMessage().equals("General SSLEngine problem")) {
            return true;
        }

        return false;
    }

    private String getLocalMessage() {
        String message = super.getMessage();
        return (message == null) ? getClass().getName() : message;
    }
}
