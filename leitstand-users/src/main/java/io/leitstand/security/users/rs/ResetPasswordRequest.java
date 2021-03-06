/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.rs;

import javax.json.bind.annotation.JsonbTypeAdapter;
import javax.security.enterprise.credential.Password;
import javax.validation.constraints.NotNull;

import io.leitstand.commons.model.ValueObject;
import io.leitstand.security.users.jsonb.PasswordAdapter;

/**
 * A request to reset the user's current password.
 * <p>
 */
public class ResetPasswordRequest extends ValueObject{
	// Not derived from CompositeValue, because this reques shall not be serializable.
	// Password is not serializable and dumping passwords by object serialization is an potential vulnerability.

	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{new_password.required}")
	private Password newPassword;
	
	@JsonbTypeAdapter(PasswordAdapter.class)
	@NotNull(message="{confirmed_password.required}")
	private Password confirmedPassword;
	
	
	/**
	 * Returns the user's new password.
	 * @return the user's new password.
	 */
	public Password getNewPassword() {
		return newPassword;
	}
	
	/** 
	 * Returns the confirmed password for typo detection.
	 * New password and confirmed password must be equal.
	 * @return the confirmed password.
	 */
	public Password getConfirmedPassword() {
		return confirmedPassword;
	}
	
}