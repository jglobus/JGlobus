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

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.globus.common.CoGProperties;
import org.globus.gsi.util.CertificateUtil;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import javax.security.auth.x500.X500Principal;

import java.io.IOException;
import java.io.Serializable;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * An implementation of <code>GSSName</code>.
 */
public class GlobusGSSName implements GSSName, Serializable {

    static class ReverseDNSCache {
        static class MapEntry {
            final Future<String> hostName;
            Long inserted;

            public MapEntry(Future<String> hostName, Long inserted) {
                this.hostName = hostName;
                this.inserted = inserted;
            }
        }

        // Use TreeMap to avoid clustering in any case
        final protected Map<String, MapEntry> cache = new TreeMap<String, MapEntry>();
        final long duration;
        final ExecutorService threads = Executors.newCachedThreadPool(new ThreadFactory() {
            public Thread newThread(Runnable runnable) {
                Thread t = new Thread(runnable);
                t.setName("Reverse DNS request");
                t.setDaemon(true);
                return t;
            }
        });
        long oldest = System.currentTimeMillis();

        public ReverseDNSCache(long duration) {
            this.duration = duration;
        }

        protected void enforceConstraints() {
            if(oldest + duration < System.currentTimeMillis()) {
                long newOldest = System.currentTimeMillis();
                List<String> toClear = new LinkedList<String>();
                for(Map.Entry<String, MapEntry> e: cache.entrySet()) {
                    if(e.getValue().inserted + duration < System.currentTimeMillis()) toClear.add(e.getKey());
                    else if(e.getValue().inserted < newOldest) newOldest = e.getValue().inserted;
                }
                for(String k: toClear) cache.remove(k);
                oldest = newOldest;
            }
        }

        protected synchronized Future<String> getCached(final String ip) {
            MapEntry inCache = cache.get(ip);
            if(inCache == null) {
                Future<String> name = threads.submit(new Callable<String>() {
                    public String call() throws Exception {
                        return queryHost(ip);
                    }
                });
                inCache = new MapEntry(name, System.currentTimeMillis());
                cache.put(ip, inCache);
            } else {
                inCache.inserted = System.currentTimeMillis();
            }
            enforceConstraints();
            return inCache.hostName;
        }

        public String resolve(String ip) throws UnknownHostException {
            try {
               return getCached(ip).get();
            } catch(InterruptedException e) {
               throw new UnknownHostException(e.getMessage());
            } catch(ExecutionException e) {
               throw new UnknownHostException(e.getMessage());
            }

        }

    }

    static String queryHost(String name) throws UnknownHostException {
        InetAddress i = InetAddress.getByName(name);
        return InetAddress.getByName(i.getHostAddress()).getHostName();
    }

    final static ReverseDNSCache reverseDNSCache = new ReverseDNSCache(CoGProperties.getDefault().getReveseDNSCacheLifetime());

    protected Oid nameType;
    protected X500Principal name;

    // set toString called
    protected String globusID;

    // set when constructing with GSSName.NT_HOSTBASED_SERVICE as name type
    // or in the getter
    protected String hostBasedServiceCN;

    public GlobusGSSName() {
	this.nameType = GSSName.NT_ANONYMOUS;
	this.name = null;
    }

    public GlobusGSSName(X500Principal name) {
	if (name == null) {
	    this.nameType = GSSName.NT_ANONYMOUS;
	}
	this.name = name;
    }

    public GlobusGSSName(byte[] name) {
	if (name == null) {
	    this.nameType = GSSName.NT_ANONYMOUS;
	    this.name = null;
	} else {
	    this.name = new X500Principal(name);
	}
    }

    /**
     * Creates name from Globus DN
     *
     * @param name Globus DN (e.g. /C=US/O=Globus/..) If null
     *        it is considered set as <code>GSSName.ANONYMOUS</code> name type.
     */
    public GlobusGSSName(String name)
	throws GSSException {
	if (name == null) {
	    this.nameType = GSSName.NT_ANONYMOUS;
	    this.name = null;
	} else {
	    try {
		this.name = CertificateUtil.toPrincipal(name);
	    } catch (Exception e) {
		throw new GlobusGSSException(GSSException.BAD_NAME, e);
	    }
	}
    }

    /**
     * Creates name from X509 name of specified type.
     *
     * @param name
     *        Globus DN (e.g. /C=US/O=Globus/..) or service@host name. If null
     *        it is considered set as <code>GSSName.ANONYMOUS</code> name type.
     * @param nameType name type. Only <code>GSSName.NT_ANONYMOUS</code>
     *                 or <code>GSSName.NT_HOSTBASED_SERVICE</code> is supported.
     *                 Maybe be null.
     */
    public GlobusGSSName(String name, Oid nameType)
	throws GSSException {
	if (name == null) {
	    if (nameType != null && !nameType.equals(GSSName.NT_ANONYMOUS)) {
		throw new GSSException(GSSException.BAD_NAMETYPE);
	    }
	    this.name = null;
	    this.nameType = GSSName.NT_ANONYMOUS;
	} else {
	    if (nameType != null) {
		if (nameType.equals(GSSName.NT_HOSTBASED_SERVICE)) {
		    int atPos = name.indexOf('@');
		    if (atPos == -1 || (atPos+1 >= name.length())) {
			throw new GlobusGSSException(GSSException.FAILURE,
						     GlobusGSSException.BAD_NAME,
						     "badName00");
		    }
		    // performs reverse DNS lookup
		    String host = name.substring(atPos+1);
		    try {
                if (CoGProperties.getDefault().getReverseDNSCacheType().equals(CoGProperties.THREADED_CACHE)) {
                    host = reverseDNSCache.resolve(host);
                } else {
                    host = queryHost(host);
                }
            } catch (UnknownHostException e) {
			    throw new GlobusGSSException(GSSException.FAILURE, e);
		    }

            hostBasedServiceCN = name.substring(0, atPos) + "/" + host;
		    this.name = new X500Principal("CN=" + hostBasedServiceCN);
		} else {
		    throw new GSSException(GSSException.BAD_NAMETYPE);
		}
	    } else {
		try {
		    this.name = CertificateUtil.toPrincipal(name);
		} catch (Exception e) {
		    throw new GlobusGSSException(GSSException.BAD_NAME, e);
		}
	    }
	    this.nameType = nameType;
	}
	// both subject & nameType might be null
    }

    public boolean isAnonymous() {
	return (this.name == null);
    }

    public boolean isMN() {
	return true;
    }

    public boolean equals(GSSName another)
	throws GSSException {
	if (another == null) {
	    return false;
	}

	if (isAnonymous()) {
	    return another.isAnonymous();
	}

	if (another.isAnonymous()) {
	    return false;
	}

	if (!(another instanceof GlobusGSSName)) {
	    throw new GSSException(GSSException.FAILURE);
	}

	GlobusGSSName other = (GlobusGSSName)another;

	// both are not anonymous
	// both have non-null subjects
	// nametypes might be different! (null)

	if ((nameType != null && nameType.equals(GSSName.NT_HOSTBASED_SERVICE)) ||
	    (other.nameType != null && other.nameType.equals(GSSName.NT_HOSTBASED_SERVICE))) {
	    // perform host based comparison

	    String hp1 = this.getHostBasedServiceCN(true);
	    String hp2 = other.getHostBasedServiceCN(true);

	    if (hp1 == null || hp2 == null) {
		// something is really wrong
		return false;
	    }

	    String service1 = getService(hp1);
	    String service2 = getService(hp2);

	    // service types do not match
	    if (!service1.equalsIgnoreCase(service2)) {
		return false;
	    }

	    String host1 = getHost(hp1);
	    String host2 = getHost(hp2);

	    int i1=0;
	    int i2=0;
	    int s1 = host1.length();
	    int s2 = host2.length();
	    char h1;
	    char h2;
	    while (i1 < s1 && i2 < s2) {
		h1 = Character.toUpperCase(host1.charAt(i1));
		h2 = Character.toUpperCase(host2.charAt(i2));

		if (h1 == h2) {
		    if (h1 == '.') {
			return host1.equalsIgnoreCase(host2);
		    }
		    i1++;
		    i2++;
		} else if (h1 == '.' && h2 == '-') {
		    return compareHost(host2, i2, host1, i1);
		} else if (h1 == '-' && h2 == '.') {
		    return compareHost(host1, i1, host2, i2);
		} else {
		    return false;
		}
	    }
	    return (i1 == i2);

	} else {
	    // perform regular comparison

	    // cross-check getStringNameType()
	    // that's not implemented right now

	    return toString().equalsIgnoreCase(another.toString());
	}
    }

    /**
     * Returns globus ID string representation of the name.
     * If name represents is an anonymous name string
     * "&lt;anonymous&gt;" is returned.
     */
    public String toString() {
	if (this.name == null) {
	    return "<anonymous>";
	} else {
	    if (this.globusID == null) {
		this.globusID = CertificateUtil.toGlobusID(name);
	    }
	    return this.globusID;
	}
    }

    /**
     * Returns the CN corresponding to the host part of the DN
     * @param last true if the CN is assumed to be the last CN attribute
     * in the RFC 2253 formatted DN, else false to assume it is the first DN
     * attribute
     * @return the CN of the host based service
     */
    protected String getHostBasedServiceCN(boolean last) {
        if (hostBasedServiceCN == null) {
            String dn = name.getName();

            int cnStart;

            if (last) {
                // use the last instance of CN in the DN
                cnStart = dn.lastIndexOf("CN=") + 3;
            } else {
                // use the first instance of CN in the DN
                cnStart = dn.indexOf("CN=") + 3;
            }

            if (cnStart == -1) {
                return null;
            }

            int cnEnd = dn.indexOf(",", cnStart);

            if (cnEnd == -1) {
                int nextAtt = dn.indexOf("=", cnStart);
                if (nextAtt == -1) {
                    // CN is the last attribute in the DN
                    cnEnd = dn.length();
                } else {
                    // unexpected DN format (attributes not comma delimited)
                    return null;
                }
            }

            hostBasedServiceCN = name.getName().substring(cnStart, cnEnd);
        }
        return hostBasedServiceCN;
    }

    private static String getService(String name) {
	int pos = name.indexOf('/');
	return (pos == -1) ? "host" : name.substring(0, pos);
    }

    private static String getHost(String name) {
	int pos = name.indexOf('/');
	return (pos == -1) ? name : name.substring(pos+1);
    }

    private static boolean compareHost(String host1, int i,
				       String host2, int j) {
	if (host1.charAt(i) != '-') {
	    throw new IllegalArgumentException();
	}
	int size = host1.length();
	while (i < size ) {
	    if (host1.charAt(i) == '.') {
		break;
	    } else {
		i++;
	    }
	}
	if (size - i == host2.length() - j) {
	    return host1.regionMatches(i,
				       host2,
				       j,
				       size - i);
	} else {
	    return false;
	}
    }

    // ----------------------------------

    /**
     * Currently not implemented.
     */
    public Oid getStringNameType()
	throws GSSException {
	throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public byte[] export()
	throws GSSException {
	throw new GSSException(GSSException.UNAVAILABLE);
    }

    /**
     * Currently not implemented.
     */
    public GSSName canonicalize(Oid mech)
	throws GSSException {
	throw new GSSException(GSSException.UNAVAILABLE);
    }

    private void writeObject(ObjectOutputStream oos) throws IOException {

        oos.writeObject(this.nameType);
        oos.writeObject(name.getName());
    }

    private void readObject(ObjectInputStream ois)
        throws IOException, ClassNotFoundException {

        this.nameType = (Oid)ois.readObject();
        this.name = new X500Principal((String)ois.readObject());
    }
}
