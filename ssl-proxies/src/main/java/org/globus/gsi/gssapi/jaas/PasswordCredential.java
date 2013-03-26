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
package org.globus.gsi.gssapi.jaas;

import java.io.Serializable;

public class PasswordCredential implements Serializable {

    private char[] password;
    
    public PasswordCredential(String password) {
	this.password = password.toCharArray();
    }
    
    public String getPassword() {
	return new String(this.password);
    }
    
    public boolean equals(Object another) {
	if (!(another instanceof PasswordCredential)) {
	    return false;
	}
	String pass = ((PasswordCredential)another).getPassword();
	if (this.password == null) {
	    return (pass == null);
	} else {
	    return (new String(this.password)).equals(pass);
	}
    }
    
    public String toString() {
	return getPassword();
    }
}
