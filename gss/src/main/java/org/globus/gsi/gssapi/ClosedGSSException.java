package org.globus.gsi.gssapi;

import org.ietf.jgss.GSSException;

public class ClosedGSSException extends GSSException {
    public ClosedGSSException() {
        super(CONTEXT_EXPIRED);
    }
}
