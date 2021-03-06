/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.service;

import java.util.List;

import javax.security.enterprise.credential.Password;

import io.leitstand.security.auth.UserId;

/**
 * Service to maintain users in the leitstand built-in Identity Management.
 */
public interface UserService {

	/**
	 * Adds a new users.
	 * @param user the new user
	 */
	public void addUser(UserSubmission user);
	/**
	 * Returns a list of users matching the given filter string.
	 * @param filter a POSIX regular expression to filter for user ID and surname
	 * @return a list of matching users or an empty list of no matches exist.
	 */
	public List<UserReference> findUsers(String filter);
	
	/**
	 * Returns the settings of the authenticated user.
	 * @return the settings of the authenticated user.
	 */
	public UserSettings getAuthenticatedUser();
	
	/**
	 * Returns the account settings for user account with the given UUID.
	 * Throws an <code>EntityNotFoundException</code> the account does not exist.
	 * @param uuid the account UUID
	 * @return the account settings
	 */
	public UserSettings getUser(String uuid);

	/**
	 * Returns the account settings for user account with the given user ID.
	 * Throws an <code>EntityNotFoundException</code> the account does not exist.
	 * @param userId the user ID
	 * @return the account settings
	 */
	public UserSettings getUser(UserId userId);
	
	/**
	 * Validates user credentials
	 * @param userId the user id
	 * @param password the user's password
	 * @return <code>true</code> if the password is correct, <code>false</code> otherwise.
	 */
	public boolean isValidPassword(UserId userId, 
								   Password password);
	
	/**
	 * Removes the user account with the given UUID.
	 * Returns no error if the account does not exist.
	 * @param uuid the accounts UUID.
	 */
	public void removeUser(String uuid);
	
	/**
	 * Removes the user account with the given user ID.
	 * Returns no error if the account does not exist.
	 * @param userId the accounts user ID.
	 */
	public void removeUser(UserId userId);
	
	/**
	 * Resets the password of an user account.
	 * Resetting the password requires administrator privileges.
	 * @param uuid the account UUID
	 * @param newPassword the new password
	 * @param confirmPassword the confirm password
	 */
	public void resetPassword(String uuid, 
							  Password newPassword,
							  Password confirmPassword);
	
	/**
	 * Resets the password of an user account.
	 * Resetting the password requires administrator privileges.
	 * @param userId the user ID
	 * @param currentPassword the current password
	 * @param newPassword the new password
	 * @param confirmPassword the confirm password
	 */
	public void resetPassword(UserId userId, 
			  				  Password newPassword,
			  				  Password confirmPassword);
	
	/**
	 * Sets the password of a user.
	 * @param uuid the user account UUID
	 * @param currentPassword the current password
	 * @param newPassword the new password
	 * @param confirmPassword the confirm password
	 */
	public void setPassword(String uuid, 
							Password currentPassword, 
							Password newPassword, 
							Password confirmPassword);
	
	/**
	 * Sets the password of a user.
	 * @param userId the user ID
	 * @param currentPassword the current password
	 * @param newPassword the new password
	 * @param confirmPassword the confirm password
	 */
	public void setPassword(UserId userId, 
							Password currentPassword, 
							Password newPassword, 
							Password confirmPassword);
	
	/**
	 * Updates the general settings of a user.
	 * @param settings the user settings.
	 * @see {@link ReasonCode#IDM0004E_USER_NOT_FOUND}
	 */
	public void storeUserSettings(UserSettings settings);
}
