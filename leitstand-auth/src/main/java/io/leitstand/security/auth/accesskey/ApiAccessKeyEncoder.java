/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.accesskey;

public interface ApiAccessKeyEncoder {

	String encode(ApiAccessKey key);
}