/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.UniqueKeyConstraintViolationException.key;
import static io.leitstand.commons.model.StringUtil.isEmptyString;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.newAccessKeyEvent;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.Type.CREATED;
import static io.leitstand.security.accesskeys.event.AccessKeyEvent.Type.REVOKED;
import static io.leitstand.security.accesskeys.model.AccessKey.findByAccessKeyId;
import static io.leitstand.security.accesskeys.model.AccessKey.findByAccessKeyName;
import static io.leitstand.security.accesskeys.model.AccessKey.findByNamePattern;
import static io.leitstand.security.accesskeys.service.AccessKeyData.newAccessKey;
import static io.leitstand.security.accesskeys.service.AccessKeyMetaData.newAccessKeyMetaData;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0001E_ACCESS_KEY_NOT_FOUND;
import static io.leitstand.security.accesskeys.service.ReasonCode.AKY0005E_DUPLICATE_KEY_NAME;
import static io.leitstand.security.auth.accesskey.ApiAccessKey.newApiAccessKey;
import static java.util.stream.Collectors.toList;

import java.util.List;

import javax.enterprise.event.Event;
import javax.inject.Inject;

import io.leitstand.commons.EntityNotFoundException;
import io.leitstand.commons.UniqueKeyConstraintViolationException;
import io.leitstand.commons.model.Repository;
import io.leitstand.commons.model.Service;
import io.leitstand.security.accesskeys.auth.AccessKeys;
import io.leitstand.security.accesskeys.event.AccessKeyEvent;
import io.leitstand.security.accesskeys.service.AccessKeyData;
import io.leitstand.security.accesskeys.service.AccessKeyMetaData;
import io.leitstand.security.accesskeys.service.AccessKeyService;
import io.leitstand.security.auth.UserId;
import io.leitstand.security.auth.accesskey.AccessKeyId;
import io.leitstand.security.auth.accesskey.ApiAccessKey;
import io.leitstand.security.auth.accesskey.ApiAccessKeyEncoder;

@Service
public class DefaultAccessKeyService implements AccessKeyService{

	@Inject
	@AccessKeys 
	private Repository repository;
	
	@Inject
	private ApiAccessKeyEncoder encoder;
	
	@Inject
	private Event<AccessKeyEvent> events;
	
	public DefaultAccessKeyService() {
		// CDI constructor
	}
	
	protected DefaultAccessKeyService(Repository repository,
									  ApiAccessKeyEncoder encoder,
									  Event<AccessKeyEvent> events) {
			this.repository = repository;
			this.encoder = encoder;
			this.events = events;
	}
	
	@Override
	public AccessKeyData getAccessKey(AccessKeyId accessKeyId) {
		AccessKey key = loadAccessKey(accessKeyId);
		
		return newAccessKey()
			   .withAccessKeyId(key.getAccessKeyId())
			   .withAccessKeyName(key.getAccessKeyName())
			   .withDescription(key.getDescription())
			   .withDateCreated(key.getDateCreated())
			   .withMethods(key.getMethods())
			   .withPaths(key.getPaths())
			   .build();
	
	}

	private AccessKey loadAccessKey(AccessKeyId accessKeyId) {
		AccessKey key = repository.execute(findByAccessKeyId(accessKeyId));
		if(key == null) {
			throw new EntityNotFoundException(AKY0001E_ACCESS_KEY_NOT_FOUND,
											  accessKeyId);
		}
		return key;
	}

	@Override
	public String createAccessKey(AccessKeyData accessKey) {
		AccessKeyId accessKeyId = accessKey.getAccessKeyId();
		AccessKey key = repository.execute(findByAccessKeyName(accessKey.getAccessKeyName()));
		if(key != null) {
			throw new UniqueKeyConstraintViolationException(AKY0005E_DUPLICATE_KEY_NAME,
															key("key_name",accessKey.getAccessKeyName()));
		}
		
		key = new AccessKey(accessKeyId,accessKey.getAccessKeyName());
		key.setDescription(accessKey.getDescription());
		for(String method : accessKey.getMethods()) {
			key.addMethod(method);
		}
		for(String path: accessKey.getPaths()) {
			key.addPath(path);
		}
		
		repository.add(key);
		
		ApiAccessKey token = newApiAccessKey()
							 .withId(key.getAccessKeyId())
							 .withUserId(UserId.valueOf(key.getAccessKeyName().getValue()))
							 .withDateCreated(key.getDateCreated())
							 .withMethods(key.getMethods())
							 .withPaths(key.getPaths())
							 .build();
		
		events.fire(newAccessKeyEvent()
					.withAccessKeyId(key.getAccessKeyId())
					.withAccessKeyName(key.getAccessKeyName())
					.withAccessKeyStatus(CREATED)
					.build());
		
		return encoder.encode(token);
		
		
	}

	@Override
	public void updateAccessKey(AccessKeyId accessKeyId, String description) {
		AccessKey key = loadAccessKey(accessKeyId);
		key.setDescription(description);
	}

	@Override
	public void removeAccessKey(AccessKeyId accessKeyId) {
		AccessKey key = repository.execute(findByAccessKeyId(accessKeyId));
		if(key != null) {
			repository.remove(key);
			events.fire(newAccessKeyEvent()
						.withAccessKeyId(accessKeyId)
						.withAccessKeyName(key.getAccessKeyName())
						.withAccessKeyStatus(REVOKED)
						.build());
		}
	}

	@Override
	public List<AccessKeyMetaData> findAccessKeys(String filter) {
		String pattern = filter;
		if(isEmptyString(pattern)) {
			pattern = ".*";
		}
		
		return repository
			   .execute(findByNamePattern(pattern))
			   .stream()
			   .map(key -> newAccessKeyMetaData()
					   	   .withAccessKeyId(key.getAccessKeyId())
					   	   .withAccessKeyName(key.getAccessKeyName())
					   	   .withDescription(key.getDescription())
					   	   .withDateCreated(key.getDateCreated())
					   	   .build())
			   .collect(toList());
	}

}
