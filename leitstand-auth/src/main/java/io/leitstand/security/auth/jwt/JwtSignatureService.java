/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jwt;

import static io.leitstand.security.mac.MessageAuthenticationCodes.hmacSha256;
import static java.util.Base64.getEncoder;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * A thread-safe service to compute and validate JWT signatures.
 */
@ApplicationScoped
class JwtSignatureService {

	private JsonWebTokenConfig config;
	
	protected JwtSignatureService() {
		// CDI
	}
	
	@Inject
	public JwtSignatureService(JsonWebTokenConfig config) {
		this.config = config;
	}
	
	/**
	 * Computes a JWT HS256 signature
	 * @param header64 - the Base64 encoded JWT header
	 * @param payload64 - the Base64 JWT payload
	 * @return Base64 encoded JWT signature
	 */
	public String sign64(String header64, 
						 String payload64) {
		String message = header64+"."+payload64;
		return getEncoder().encodeToString(hmacSha256(config.getSecret()).sign(message));
	}
	
	/**
	 * Verifies a JWT signature
	 * @param signature64 - the Base64 encoded token signature
	 * @param header64 - the Base64 encoded token header
	 * @param payload64 - the Base64 encoded token payload
	 * @return <code>true</code> if the given token signature is valid, <code>false</code> if not.
	 */
	public boolean isValidSignature(String signature64, 
									String header64, 
									String payload64) {
		return signature64.equals(sign64(header64,payload64));
	}
	
}