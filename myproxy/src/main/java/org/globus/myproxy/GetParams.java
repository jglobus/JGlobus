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
package org.globus.myproxy;

import org.ietf.jgss.GSSCredential;
import java.util.List;
import java.util.Iterator;


/**
 * Holds the parameters for the <code>get</code> operation.
 */
public class GetParams
    extends Params {

    private boolean wantTrustroots = false;
    private String credentialName;
    private GSSCredential authzcreds;
    private List voname;
    private List vomses;

    public GetParams() {
	super(MyProxy.GET_PROXY);
    }

    public GetParams(String username, String passphrase) {
	super(MyProxy.GET_PROXY, username, passphrase);
    }

    public void setCredentialName(String credentialName) {
	this.credentialName = credentialName;
    }

    public String getCredentialName() {
	return this.credentialName;
    }

    public void setWantTrustroots(boolean wantTrustroots) {
        this.wantTrustroots = wantTrustroots;
    }

    public boolean getWantTrustroots() {
        return this.wantTrustroots;
    }

    public void setVoname(List voname) {
        this.voname = voname;
    }

    public List getVoname() {
        return this.voname;
    }

    public void setVomses(List vomses) {
        this.vomses = vomses;
    }

    public List getVomses() {
        return this.vomses;
    }

    /**
     * Set credentials for renewal authorization.
     * @param creds
     *        The credentials to renew.
     */
    public void setAuthzCreds(GSSCredential creds) {
        this.authzcreds = creds;
    }

    public GSSCredential getAuthzCreds() {
        return this.authzcreds;
    }

    protected String makeRequest(boolean includePassword) {
	StringBuffer buf = new StringBuffer();
	buf.append(super.makeRequest(includePassword));
	add(buf, CRED_NAME, credentialName);
        add(buf, VONAME, this.voname);
        add(buf, VOMSES, this.vomses);
        if (this.wantTrustroots == true) {
            add(buf, TRUSTROOTS, "1");
        }
	return buf.toString();
    }

    private void add(StringBuffer buf, String prefix, List values) {
        if (values == null) {
            return;
        }
        for (Iterator itr = values.iterator(); itr.hasNext(); ) {
            String value = (String)itr.next();
            add(buf, prefix, value);
        }
    }

}
