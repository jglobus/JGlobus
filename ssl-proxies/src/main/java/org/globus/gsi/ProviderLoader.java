package org.globus.gsi;

import org.globus.gsi.provider.GlobusProvider;

import java.security.Security;


public class ProviderLoader {
	private GlobusProvider provider;

	public ProviderLoader(){
		provider = new GlobusProvider();
		Security.addProvider(provider);
	}

	public GlobusProvider getProvider(){
		return provider;
	}
}
