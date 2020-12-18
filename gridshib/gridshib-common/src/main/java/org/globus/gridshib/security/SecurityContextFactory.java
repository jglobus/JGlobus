/*
 * Copyright 2006-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.security;

import java.lang.reflect.Constructor;
import java.util.Iterator;
import java.util.Set;
import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gridshib.config.BootstrapConfigLoader;

/**
 * A factory for creating instances of the
 * <code>SecurityContext</code> interface.
 *
 * @see org.globus.gridshib.security.SecurityContext
 */
public class SecurityContextFactory {

    private static Log logger =
        LogFactory.getLog(SecurityContextFactory.class.getName());

    private static final String DEFAULT_CLASSNAME =
        "org.globus.gridshib.security.SAMLSecurityContext";

    private static Class secCtxImpl;
    private static String secCtxClassName;

    static {
        secCtxImpl = null;
        secCtxClassName = null;

        String className = BootstrapConfigLoader.getSecurityContextImpl();
        if (className == null) {
            className = DEFAULT_CLASSNAME;
        }
        logger.debug("Using default impl: " + className);

        try {
            setSecurityContextImpl(className);
        } catch (ClassNotFoundException e) {
            String msg = "Class not found: " + className;
            throw new RuntimeException(msg, e);
        }
        assert (secCtxImpl != null);
        assert (secCtxClassName != null);
    }

    /**
     * Sets the implementation used by this factory to create
     * instances of the <code>SecurityContext</code> interface.
     * By default, an implementation of type
     * <code>SAMLSecurityContext</code> is used.
     *
     * @param className the fully qualified class name of an
     *        implementation of <code>SecurityContext</code>
     */
    public static void setSecurityContextImpl(String className)
                                       throws ClassNotFoundException {

        if (className == null) {
            String msg = "Class name is null";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        Class impl = Class.forName(className);
        if (impl == null) {
            String msg =
                "Null implementation obtained for class " + className;
            logger.error(msg);
            throw new RuntimeException(msg);
        }

        // this is a test:
        try {
            Class[] paramtypes = {Subject.class};
            Object[] params = {new Subject()};
            Constructor c = impl.getDeclaredConstructor(paramtypes);
            SecurityContext ctx = (SecurityContext)c.newInstance(params);
            logger.debug("Constructed an instance of " + impl.toString());
        } catch (Exception e) {
            String msg =
                "Unable to construct an instance of class " + className;
            logger.error(msg);
            throw new RuntimeException(msg, e);
        }

        secCtxImpl = impl;
        secCtxClassName = className;
        logger.info("SecurityContext implementation permanently " +
                    "set to " + className);
    }

    /**
     * Get the one and only <code>SecurityContext</code> instance
     * associated with the given <code>Subject</code>.  There is
     * exactly one <code>SecurityContext</code> instance for
     * each authenticated user, which is obtained by calling this
     * method.  The result may be the empty
     * <code>SecurityContext</code> instance, but never null.
     * <p>
     * If a security context for the subject does not exist, one
     * is created.  The implementation of <code>SecurityContext</code>
     * used to create the new context is determined by the last
     * successful call to {@link #setSecurityContextImpl(String)}
     * or .
     *
     * @param subject an object representing the authenticated user
     *
     * @return the one and only (non-null) <code>SecurityContext</code>
     *         instance associated with the given <code>Subject</code>
     */
    public static SecurityContext getInstance(Subject subject) {

        if (subject == null) {
            String msg = "Subject is null";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        assert (secCtxClassName != null);
        try {
            return getInstance(subject, secCtxClassName);
        } catch (ClassNotFoundException e) {
            String msg = "Class not found: " + secCtxClassName;
            throw new RuntimeException(msg, e);
        }
    }

    /**
     * Get the one and only <code>SecurityContext</code> instance
     * associated with the given <code>Subject</code>.  There is
     * exactly one <code>SecurityContext</code> instance for
     * each authenticated user, which is obtained by calling this
     * method.  The result may be the empty
     * <code>SecurityContext</code> instance, but never null.
     *
     * @param subject an object representing the authenticated user
     * @param className the fully qualified class name of the
     *        implementation of <code>SecurityContext</code> to use
     *        to create a new instance (if necessary)
     *
     * @return the one and only (non-null) <code>SecurityContext</code>
     *         instance associated with the given <code>Subject</code>
     */
    public static SecurityContext getInstance(Subject subject,
                                              String className)
                                       throws ClassNotFoundException {

        if (subject == null) {
            String msg = "Subject is null";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }

        // check to see if a security context already exists:
        SecurityContext ctx = null;
        Set credSet = subject.getPublicCredentials();
        Iterator creds = credSet.iterator();
        while (creds.hasNext()) {
            Object o = creds.next();
            if (o instanceof SecurityContext) {
                ctx = (SecurityContext)o;
                break;
            }
        }

        // if a security context does not exist, try to create one:
        if (ctx == null) {
            assert (secCtxImpl != null);
            assert (secCtxClassName != null);
            Class impl = secCtxImpl;
            if (!(className == null || className.equals(secCtxClassName))) {
                impl = Class.forName(className);
                String msg =
                    "SecurityContext implementation temporarily set to " +
                    className;
                logger.info(msg);
            }
            logger.debug("Creating new security context of type " +
                         impl.toString());
            try {
                Class[] paramtypes = {Subject.class};
                Object[] params = {subject};
                Constructor c = impl.getDeclaredConstructor(paramtypes);
                ctx = (SecurityContext)c.newInstance(params);
            } catch (Exception e) {
                String msg = "Unable to construct an instance of " +
                             impl.toString();
                throw new RuntimeException(msg, e);
            }
            subject.getPublicCredentials().add(ctx);
            return getInstance(subject, className);  // recurse
        } else {
            logger.debug("Security context found: " + ctx.toString());
            return ctx;
        }
    }
}
