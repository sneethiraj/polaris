/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.polaris.extension.auth.ranger.plugin;

import com.google.common.base.Preconditions;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.iceberg.exceptions.ForbiddenException;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.config.FeatureConfiguration;
import org.apache.polaris.core.config.RealmConfig;
import org.apache.polaris.core.entity.PolarisBaseEntity;
import org.apache.polaris.core.entity.PolarisEntityConstants;
import org.apache.polaris.core.entity.PolarisEntityCore;
import org.apache.polaris.core.entity.PolarisPrivilege;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.extension.auth.ranger.RangerPolarisAuthorizerConfig;
import org.apache.polaris.extension.auth.ranger.model.RangerPolarisAccessRequest;
import org.apache.polaris.extension.auth.ranger.model.RangerPolarisResource;
import org.apache.polaris.extension.auth.ranger.utils.RangerUtils;
import org.apache.ranger.authz.api.RangerAuthzException;
import org.apache.ranger.authz.embedded.RangerEmbeddedAuthorizer;
import org.apache.ranger.authz.model.RangerAccessContext;
import org.apache.ranger.authz.model.RangerAuthzResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static org.apache.polaris.core.entity.PolarisEntityConstants.getRootPrincipalName;

public class RangerPolarisPlugin {
    private static final Logger LOG = LoggerFactory.getLogger(RangerPolarisPlugin.class);

    public static final String SERVICE_TYPE = "polaris";
    public static final String SERVICE_NAME_PROPERTY = "ranger.plugin.polaris.service.name";

    private static final String OPERATION_NOT_ALLOWED_FOR_USER_ERROR = "Principal '%s' is not authorized for op %s due to PRINCIPAL_CREDENTIAL_ROTATION_REQUIRED_STATE" ;
    private static final String ROOT_PRINCIPLE_NEEDED_ERROR = "Principal '%s' is not authorized for op %s as Only root principal can perform this operation" ;
    private static final String RANGER_AUTH_FAILED_ERROR  = "Principal '%s' with activated PrincipalRoles '%s' and activated grants via '%s' is not authorized for op '%s'" ;


    private final RangerEmbeddedAuthorizer authorizer ;
    private final boolean enforceCredentialRotationRequiredState;
    public String serviceName ;

    public RangerPolarisPlugin(RangerPolarisAuthorizerConfig config, RealmConfig realmConfig) {
        this.enforceCredentialRotationRequiredState = realmConfig.getConfig(
                        FeatureConfiguration.ENFORCE_PRINCIPAL_CREDENTIAL_ROTATION_REQUIRED_CHECKING);
        Properties rangerConfigProp = RangerUtils.loadProperties(config.configFileName()) ;
        authorizer = new RangerEmbeddedAuthorizer(rangerConfigProp) ;
        serviceName = rangerConfigProp.getProperty(SERVICE_NAME_PROPERTY) ;
    }

    public void init() throws RangerAuthzException {
        authorizer.init();

    }

    public void authorizeOrThrow(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable List<PolarisResolvedPathWrapper> targets,
            @Nullable List<PolarisResolvedPathWrapper> secondaries) {
        try {
            if (!isOperationAllowedForUser(polarisPrincipal, authzOp) ) {
                throw new ForbiddenException(OPERATION_NOT_ALLOWED_FOR_USER_ERROR, polarisPrincipal.getName(), authzOp.name()) ;
                //TODO: enable ranger audit from here to ensure that the request denied captured.
            } else if (authzOp == PolarisAuthorizableOperation.RESET_CREDENTIALS) {
                boolean isRootPrincipal = getRootPrincipalName().equals(polarisPrincipal.getName()) ;
               //TODO: enable ranger audit from here to ensure that the request denied captured.
                if (!isRootPrincipal) {
                    throw new ForbiddenException(ROOT_PRINCIPLE_NEEDED_ERROR, polarisPrincipal.getName(), authzOp.name());
                }
            } else if (!isAccessAuthorized(polarisPrincipal, activatedEntities, authzOp, targets, secondaries)) {
                throw new ForbiddenException(RANGER_AUTH_FAILED_ERROR,
                        polarisPrincipal.getName(),
                        polarisPrincipal.getRoles(),
                        activatedEntities.stream().map(PolarisEntityCore::getName).collect(Collectors.toSet()),
                        authzOp.name());
            }
        }
        catch(IllegalStateException ise) {
            LOG.info("Failed to authorize principal {} for op {}. Throwing exception. {}", polarisPrincipal, authzOp, ise);
            throw ise;
        }
    }

    private boolean isAccessAuthorized(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable List<PolarisResolvedPathWrapper> targets,
            @Nullable List<PolarisResolvedPathWrapper> secondaries) {

        if (LOG.isInfoEnabled()) {

            LOG.info("isAuthorized: users={}, groups={}", polarisPrincipal.getName(), String.join(",", polarisPrincipal.getRoles()));

            LOG.info("isAuthorized: activatedEntities={}",
                activatedEntities.stream()
                    .map(e -> RangerUtils.toResourceType(e.getType()) + ":" + e.getName())
                    .collect(Collectors.joining(","))) ;

            LOG.info("isAuthorized: authzOp={}", authzOp.name()) ;

            LOG.info("isAuthorized: permissions={}",
                authzOp.getPrivilegesOnTarget().stream()
                    .map(RangerUtils::toAccessType)
                    .collect(Collectors.joining(","))) ;

            if (targets != null) {
                LOG.info("isAuthorized: targets={}",
                        targets.stream()
                                .map(RangerPolarisResource::getResourcePath)
                                .collect(Collectors.joining(",")));
            }

            if (secondaries != null) {
                LOG.info("isAuthorized: secondaries={}",
                        secondaries.stream()
                                .map(RangerPolarisResource::getResourcePath)
                                .collect(Collectors.joining(",")));
            }
       }

        return validateTargets(polarisPrincipal, authzOp, targets);

    }

    private boolean validateTargets(@Nonnull PolarisPrincipal polarisPrincipal,
                                    @Nonnull PolarisAuthorizableOperation authzOp,
                                    @Nullable List<PolarisResolvedPathWrapper> targets) {

        boolean accessGranted = false ;

        for (PolarisPrivilege privilegeOnTarget : authzOp.getPrivilegesOnTarget()) {
            // If any privileges are required on target, the target must be non-null.
            Preconditions.checkState(
                    targets != null,
                    "Got null target when authorizing authzOp %s for privilege %s", authzOp, privilegeOnTarget);
        }

        if (targets != null) {
            List<String> errors = new ArrayList<>();
            for (PolarisResolvedPathWrapper target : targets) {
                if (!isTargetAuthorized(polarisPrincipal, authzOp, target)) {
                    errors.add(String.format("Failed to satisfy privilege %s for principalName %s on resolvedPath %s", authzOp.name(), polarisPrincipal.getName(), target));
                }
            }
            if (!errors.isEmpty()) {
                String msg = String.join(",", errors);
                LOG.error(msg);
            }
            else {
                accessGranted = true ;
            }
        }

        return accessGranted ;
    }

    /**
     * Checks whether the resolvedPrincipal in the {@code resolved} resolvedPath has role-expanded
     * permissions matching {@code privilege} on any entity in the resolvedPath of the resolvedPath.
     *
     * <p>The caller is responsible for translating these checks into either behavioral actions (e.g.
     * returning 404 instead of 403, checking other root privileges that supercede the checked
     * privilege, choosing whether to vend credentials) or throwing relevant Unauthorized
     * errors/exceptions.
     */
    public boolean isTargetAuthorized(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull PolarisAuthorizableOperation authzOp,
            PolarisResolvedPathWrapper resolvedPath) {

        RangerPolarisAccessRequest request = new RangerPolarisAccessRequest(polarisPrincipal,resolvedPath, authzOp) ;
        RangerAccessContext context = new RangerAccessContext();
        context.setServiceName(SERVICE_TYPE);
        context.setServiceName(serviceName);
        request.setContext(context) ;

        boolean accessAllowed = false;
        try {
            RangerAuthzResult result = authorizer.authorize(request);
            accessAllowed = RangerAuthzResult.AccessDecision.ALLOW.equals( result.getDecision()) ;
        } catch (RangerAuthzException e) {
            LOG.info("Ranger authorization failed for principal {} on resolvedPath {}. Exception: {}", polarisPrincipal, resolvedPath, e);
        }

        String permissions = authzOp.getPrivilegesOnTarget().stream()
                .map(RangerUtils::toAccessType).collect(Collectors.joining(",")) ;

        LOG.info("RangerPolicyEval: result = {}", accessAllowed);

        return accessAllowed ;

    }

    private boolean isOperationAllowedForUser(PolarisPrincipal polarisPrincipal,PolarisAuthorizableOperation authzOp) {
        return (!(enforceCredentialRotationRequiredState
                   && polarisPrincipal.getProperties().containsKey(PolarisEntityConstants.PRINCIPAL_CREDENTIAL_ROTATION_REQUIRED_STATE)
                   && authzOp != PolarisAuthorizableOperation.ROTATE_CREDENTIALS)) ;
    }


}
