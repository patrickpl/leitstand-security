/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.service;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.ResourceBundle;

import io.leitstand.commons.Reason;

public enum ReasonCode implements Reason{
	
	/** User stored in identity management system*/
	IDM0001I_USER_STORED,
	/** User account password reset by an administrator.*/
	IDM0002I_PASSWORD_RESET,
	/** User account password reset by the user itself.*/
	IDM0003I_PASSWORD_UPDATED,
	/** The requested user does not exist.*/
	IDM0004E_USER_NOT_FOUND,
	/** Password cannot be changed because the given current password was incorrect.*/
	IDM0005E_INCORRECT_PASSWORD, 
	/** The user role does not exist.*/
	IDM0006E_ROLE_NOT_FOUND,
	/** The attempted operation was rejected because athe user has no administrator privileges.*/
	IDM0007E_ADMIN_PRIVILEGES_REQUIRED, 
	/** The password cannot be changed because the new password and the confirmed password mismatch.*/
	IDM0008E_PASSWORD_MISMATCH,
	/** The user has beem removed from the identity management system.*/
	IDM0009I_USER_REMOVED;
		
	
	private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("UserMessages");
	
	/**
	 * {@inheritDoc}
	 */
	public String getMessage(Object... args){
		try{
			String pattern = MESSAGES.getString(name());
			return MessageFormat.format(pattern, args);
		} catch(Exception e){
			return name() + Arrays.asList(args);
		}
	}	

}
